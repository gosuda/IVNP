package sam

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/networking"
)

type loopController struct {
	mu        sync.Mutex
	endpoints map[foundation.Hash]*loopEndpoint
}

func (c *loopController) CreateDestination(_ context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	local, err := spec.Local.Clone()
	if err != nil {
		return nil, err
	}
	endpoint := &loopEndpoint{local: local, controller: c, subscriptions: make(map[destination.DestinationRoute]*loopSubscription)}
	c.mu.Lock()
	c.endpoints[local.Hash()] = endpoint
	c.mu.Unlock()
	return endpoint, nil
}
func (c *loopController) DestroyDestination(_ context.Context, endpoint destination.DestinationEndpoint) error {
	return endpoint.Close()
}

type loopEndpoint struct {
	local         *foundation.LocalDestination
	controller    *loopController
	mu            sync.Mutex
	subscriptions map[destination.DestinationRoute]*loopSubscription
	closed        bool
}

func (e *loopEndpoint) Hash() foundation.Hash { return e.local.Hash() }
func (e *loopEndpoint) B32() string           { return e.local.B32() }
func (e *loopEndpoint) Destination() []byte   { return e.local.Destination() }
func (e *loopEndpoint) DialI2P(context.Context, string) (net.Conn, error) {
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	return left, nil
}
func (e *loopEndpoint) ListenI2P(context.Context, string) (net.Listener, error) {
	return nil, ErrUnsupported
}
func (e *loopEndpoint) SendMessage(_ context.Context, d networking.StreamingTunnelDelivery) error {
	e.controller.mu.Lock()
	target := e.controller.endpoints[d.To]
	e.controller.mu.Unlock()
	if target == nil {
		return ErrProtocol
	}
	target.mu.Lock()
	sub := target.subscriptions[destination.DestinationRoute{Protocol: d.Protocol, ToPort: d.ToPort}]
	if sub == nil {
		sub = target.subscriptions[destination.DestinationRoute{Protocol: d.Protocol}]
	}

	target.mu.Unlock()
	if sub == nil {
		return ErrProtocol
	}
	copyDelivery := d
	copyDelivery.Payload = append([]byte(nil), d.Payload...)
	go func() {
		sub.ch <- &destination.ReceivedMessage{Delivery: copyDelivery}
	}()
	return nil
}
func (e *loopEndpoint) MarshalDatagramV1To(dst, payload []byte) (int, error) {
	identity, err := e.local.Identity()
	if err != nil {
		return 0, err
	}
	return networking.DatagramMarshalV1To(dst, identity, payload, e.local.Sign)
}
func (e *loopEndpoint) MarshalDatagramV2To(dst []byte, target foundation.Hash, payload []byte) (int, error) {
	identity, err := e.local.Identity()
	if err != nil {
		return 0, err
	}
	flags := uint16(2)
	var offline networking.DatagramOfflineSignature
	if meta, ok := e.local.OfflineSignature(); ok {
		flags |= networking.DatagramFlagOffline
		offline = meta
	}
	return networking.DatagramMarshalV2To(dst, target, identity, flags, foundation.Mapping{}, offline, payload, e.local.Sign)
}
func (e *loopEndpoint) MarshalDatagramV3To(dst, payload []byte) (int, error) {
	return networking.DatagramMarshalV3To(dst, e.local.Hash(), 3, foundation.Mapping{}, payload)
}
func (e *loopEndpoint) Subscribe(route destination.DestinationRoute, _ int) (destination.MessageSubscription, error) {
	sub := &loopSubscription{ch: make(chan *destination.ReceivedMessage, 8), done: make(chan struct{})}
	e.mu.Lock()
	e.subscriptions[route] = sub
	e.mu.Unlock()
	return sub, nil
}
func (e *loopEndpoint) Close() error {
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		for _, sub := range e.subscriptions {
			_ = sub.Close()
		}
		e.local.ReleaseSensitive()
	}
	e.mu.Unlock()
	return nil
}

type loopSubscription struct {
	ch   chan *destination.ReceivedMessage
	done chan struct{}
	once sync.Once
}

func (s *loopSubscription) Receive(ctx context.Context) (*destination.ReceivedMessage, error) {
	select {
	case m := <-s.ch:
		return m, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *loopSubscription) Close() error { s.once.Do(func() { close(s.done) }); return nil }

type fixedResolver string

func (r fixedResolver) ResolveDestination(context.Context, string) (string, error) {
	return string(r), nil
}

type blockingResolver struct {
	started  chan struct{}
	canceled chan struct{}
}

func (r *blockingResolver) ResolveDestination(ctx context.Context, _ string) (string, error) {
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	return "", ctx.Err()
}

type cleanupObservation struct {
	initialErr  error
	hasDeadline bool
}

type contextCleanupController struct {
	observed chan cleanupObservation
}

func (c *contextCleanupController) CreateDestination(context.Context, destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	return nil, ErrUnsupported
}

func (c *contextCleanupController) DestroyDestination(ctx context.Context, _ destination.DestinationEndpoint) error {
	_, hasDeadline := ctx.Deadline()
	c.observed <- cleanupObservation{initialErr: ctx.Err(), hasDeadline: hasDeadline}
	<-ctx.Done()
	return ctx.Err()
}

func samDial(t *testing.T, address string) (net.Conn, *bufio.Reader) {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	if _, err = io.WriteString(connection, "HELLO VERSION MIN=3.3 MAX=3.3\n"); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "RESULT=OK VERSION=3.3") {
		t.Fatalf("hello = %q, %v", line, err)
	}
	return connection, reader
}
func readSAMLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func TestEmbeddedServerCancelsNamingLookupOnClose(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	resolver := &blockingResolver{started: make(chan struct{}), canceled: make(chan struct{})}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	connection, _ := samDial(t, server.Addr().String())
	defer connection.Close()
	if _, err = io.WriteString(connection, "NAMING LOOKUP NAME=blocked.i2p\n"); err != nil {
		t.Fatal(err)
	}
	<-resolver.started
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if err = server.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolver.canceled:
	default:
		t.Fatal("server Close did not cancel NAMING LOOKUP")
	}
}

func TestDestroyDestinationUsesBoundedIndependentContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		controller := &contextCleanupController{observed: make(chan cleanupObservation, 1)}
		server := &Server{
			config: ServerConfig{Controller: controller, CleanupTimeout: time.Hour},
			ctx:    parent,
		}
		err := server.destroyDestination(nil)
		observation := <-controller.observed
		if observation.initialErr != nil {
			t.Fatalf("cleanup context started canceled: %v", observation.initialErr)
		}
		if !observation.hasDeadline {
			t.Fatal("cleanup context has no deadline")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("destroyDestination error = %v, want context.DeadlineExceeded", err)
		}
		if !errors.Is(server.Wait(), context.DeadlineExceeded) {
			t.Fatalf("Server.Wait error = %v, want context.DeadlineExceeded", server.Wait())
		}
	})
}
func TestEmbeddedServerKeepsIdleRootSessionAlive(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{
		Address: "127.0.0.1:0", Controller: controller, MaxSessions: 4,
		CommandTimeout: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=STREAM ID=idle-root DESTINATION=TRANSIENT\n")
	if line := readSAMLine(t, reader); !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("session create = %q", line)
	}
	timer := time.NewTimer(3 * 40 * time.Millisecond)
	<-timer.C
	_, _ = io.WriteString(control, "PING root-still-live\n")
	if line := readSAMLine(t, reader); line != "PONG root-still-live" {
		t.Fatalf("idle root ping = %q", line)
	}
}

func TestEmbeddedServerLiveLoopbackStylesAndRecovery(t *testing.T) {
	peer, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.ReleaseSensitive()
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, Resolver: fixedResolver(string(peer.Destination())), MaxSessions: 16})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	address := server.Addr().String()

	streamControl, streamReader := samDial(t, address)
	defer streamControl.Close()
	_, _ = io.WriteString(streamControl, "SESSION CREATE STYLE=STREAM ID=stream DESTINATION=TRANSIENT PORT=80\n")
	if line := readSAMLine(t, streamReader); !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("stream create = %q", line)
	}
	_, _ = io.WriteString(streamControl, "BROKEN \"unterminated\nPING still-alive\n")
	if line := readSAMLine(t, streamReader); !strings.Contains(line, "MALFORMED_COMMAND") {
		t.Fatalf("malformed = %q", line)
	}
	if line := readSAMLine(t, streamReader); line != "PONG still-alive" {
		t.Fatalf("ping = %q", line)
	}

	attachment, attachmentReader := samDial(t, address)
	defer attachment.Close()
	_, _ = io.WriteString(attachment, "STREAM CONNECT ID=stream DESTINATION=peer.i2p TO_PORT=80\n")
	if line := readSAMLine(t, attachmentReader); line != "STREAM STATUS RESULT=OK" {
		t.Fatalf("connect = %q", line)
	}
	_, _ = attachment.Write([]byte("loopback"))
	payload := make([]byte, 8)
	if _, err = io.ReadFull(attachmentReader, payload); err != nil || string(payload) != "loopback" {
		t.Fatalf("relay = %q, %v", payload, err)
	}

	datagramControl, datagramReader := samDial(t, address)
	defer datagramControl.Close()
	_, _ = io.WriteString(datagramControl, "SESSION CREATE STYLE=DATAGRAM ID=dg DESTINATION=TRANSIENT PORT=9\n")
	line := readSAMLine(t, datagramReader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("datagram create = %q", line)
	}
	private := strings.TrimPrefix(strings.Split(line, " DESTINATION=")[1], "")
	local, err := decodePrivateDestination(private)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := local.Identity()
	if err != nil || identity.CryptoKeyType() != foundation.CryptoElGamal {
		t.Fatalf("transient SAM Destination identity = %#v, %v", identity, err)
	}
	if key, keyErr := local.CryptoPublic(foundation.CryptoX25519); keyErr != nil || key == ([32]byte{}) {
		t.Fatalf("transient SAM LS2 key = %x, %v", key, keyErr)
	}
	target := string(local.Destination())
	local.ReleaseSensitive()
	_, _ = io.WriteString(datagramControl, "DATAGRAM SEND ID=dg DESTINATION="+target+" TO_PORT=9 SIZE=4\nDATA")
	// Inbound forwarding runs on a separate goroutine, so DATAGRAM RECEIVED may
	// arrive before the STATUS reply on the shared control connection.
	var datagramStatusOK, datagramReceived bool
	body := make([]byte, 4)
	for !datagramStatusOK || !datagramReceived {
		line = readSAMLine(t, datagramReader)
		switch {
		case line == "DATAGRAM STATUS RESULT=OK":
			datagramStatusOK = true
		case strings.Contains(line, "DATAGRAM RECEIVED") && strings.Contains(line, "SIZE=4"):
			datagramReceived = true
			if _, err = io.ReadFull(datagramReader, body); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("datagram reply = %q", line)
		}
	}
	if string(body) != "DATA" {
		t.Fatalf("datagram body = %q", body)
	}

	rawControl, rawReader := samDial(t, address)
	defer rawControl.Close()
	_, _ = io.WriteString(rawControl, "SESSION CREATE STYLE=RAW ID=raw DESTINATION=TRANSIENT PORT=10 PROTOCOL=18\n")
	line = readSAMLine(t, rawReader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatalf("raw create = %q", line)
	}
	private = strings.Split(line, " DESTINATION=")[1]
	local, err = decodePrivateDestination(private)
	if err != nil {
		t.Fatal(err)
	}
	target = string(local.Destination())
	local.ReleaseSensitive()
	_, _ = io.WriteString(rawControl, "RAW SEND ID=raw DESTINATION="+target+" TO_PORT=10 SIZE=3\nRAW")
	var rawStatusOK, rawReceived bool
	body = make([]byte, 3)
	for !rawStatusOK || !rawReceived {
		line = readSAMLine(t, rawReader)
		switch {
		case line == "RAW STATUS RESULT=OK":
			rawStatusOK = true
		case strings.Contains(line, "RAW RECEIVED") && strings.Contains(line, "SIZE=3"):
			rawReceived = true
			if _, err = io.ReadFull(rawReader, body); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("raw reply = %q", line)
		}
	}
	if string(body) != "RAW" {
		t.Fatalf("raw body = %q", body)
	}

	primary, primaryReader := samDial(t, address)
	defer primary.Close()
	_, _ = io.WriteString(primary, "SESSION CREATE STYLE=PRIMARY ID=primary DESTINATION=TRANSIENT\n")
	if line = readSAMLine(t, primaryReader); !strings.Contains(line, "RESULT=OK") {
		t.Fatal(line)
	}
	_, _ = io.WriteString(primary, "SESSION ADD STYLE=RAW ID=child PORT=11 PROTOCOL=18\n")
	if line = readSAMLine(t, primaryReader); line != "SESSION STATUS RESULT=OK" {
		t.Fatal(line)
	}
	_, _ = io.WriteString(primary, "SESSION REMOVE ID=child\n")
	if line = readSAMLine(t, primaryReader); line != "SESSION STATUS RESULT=OK" {
		t.Fatal(line)
	}

	controller.mu.Lock()
	count := len(controller.endpoints)
	controller.mu.Unlock()
	if count < 4 {
		t.Fatalf("isolated destination count = %d", count)
	}
}
