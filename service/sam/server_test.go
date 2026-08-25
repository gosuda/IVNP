package sam

import (
	"bufio"
	"context"
	clientapi "gosuda.org/ivnp/api/destination"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/protocol/datagram"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type loopController struct {
	mu        sync.Mutex
	endpoints map[ivnp.Hash]*loopEndpoint
}

func (c *loopController) CreateDestination(_ context.Context, spec clientapi.DestinationSpec) (clientapi.DestinationEndpoint, error) {
	local, err := spec.Local.Clone()
	if err != nil {
		return nil, err
	}
	endpoint := &loopEndpoint{local: local, controller: c, subscriptions: make(map[clientapi.DestinationRoute]*loopSubscription)}
	c.mu.Lock()
	c.endpoints[local.Hash()] = endpoint
	c.mu.Unlock()
	return endpoint, nil
}
func (c *loopController) DestroyDestination(_ context.Context, endpoint clientapi.DestinationEndpoint) error {
	return endpoint.Close()
}

type loopEndpoint struct {
	local         *ivnp.LocalDestination
	controller    *loopController
	mu            sync.Mutex
	subscriptions map[clientapi.DestinationRoute]*loopSubscription
	closed        bool
}

func (e *loopEndpoint) Hash() ivnp.Hash     { return e.local.Hash() }
func (e *loopEndpoint) B32() string         { return e.local.B32() }
func (e *loopEndpoint) Destination() []byte { return e.local.Destination() }
func (e *loopEndpoint) DialI2P(context.Context, string) (net.Conn, error) {
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	return left, nil
}
func (e *loopEndpoint) ListenI2P(context.Context, string) (net.Listener, error) {
	return nil, ErrUnsupported
}
func (e *loopEndpoint) SendMessage(_ context.Context, d streamtunnel.Delivery) error {
	e.controller.mu.Lock()
	target := e.controller.endpoints[d.To]
	e.controller.mu.Unlock()
	if target == nil {
		return ErrProtocol
	}
	target.mu.Lock()
	sub := target.subscriptions[clientapi.DestinationRoute{Protocol: d.Protocol, ToPort: d.ToPort}]
	if sub == nil {
		sub = target.subscriptions[clientapi.DestinationRoute{Protocol: d.Protocol}]
	}

	target.mu.Unlock()
	if sub == nil {
		return ErrProtocol
	}
	copyDelivery := d
	copyDelivery.Payload = append([]byte(nil), d.Payload...)
	go func() {
		sub.ch <- &clientapi.ReceivedMessage{Delivery: copyDelivery}
	}()
	return nil
}
func (e *loopEndpoint) MarshalDatagramV1To(dst, payload []byte) (int, error) {
	identity, err := e.local.Identity()
	if err != nil {
		return 0, err
	}
	return datagram.MarshalV1To(dst, identity, payload, e.local.Sign)
}
func (e *loopEndpoint) Subscribe(route clientapi.DestinationRoute, _ int) (clientapi.MessageSubscription, error) {
	sub := &loopSubscription{ch: make(chan *clientapi.ReceivedMessage, 8), done: make(chan struct{})}
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
	ch   chan *clientapi.ReceivedMessage
	done chan struct{}
	once sync.Once
}

func (s *loopSubscription) Receive(ctx context.Context) (*clientapi.ReceivedMessage, error) {
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

func TestEmbeddedServerKeepsIdleRootSessionAlive(t *testing.T) {
	controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
	peer, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.ReleaseSensitive()
	controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
	if err != nil || identity.CryptoKeyType() != ivnp.CryptoElGamal {
		t.Fatalf("transient SAM Destination identity = %#v, %v", identity, err)
	}
	if key, keyErr := local.CryptoPublic(ivnp.CryptoX25519); keyErr != nil || key == ([32]byte{}) {
		t.Fatalf("transient SAM LS2 key = %x, %v", key, keyErr)
	}
	target := string(local.Destination())
	local.ReleaseSensitive()
	_, _ = io.WriteString(datagramControl, "DATAGRAM SEND ID=dg DESTINATION="+target+" TO_PORT=9 SIZE=4\nDATA")
	if line = readSAMLine(t, datagramReader); line != "DATAGRAM STATUS RESULT=OK" {
		t.Fatalf("datagram status = %q", line)
	}
	line = readSAMLine(t, datagramReader)
	if !strings.Contains(line, "DATAGRAM RECEIVED") || !strings.Contains(line, "SIZE=4") {
		t.Fatalf("datagram receive = %q", line)
	}
	body := make([]byte, 4)
	_, _ = io.ReadFull(datagramReader, body)
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
	if line = readSAMLine(t, rawReader); line != "RAW STATUS RESULT=OK" {
		t.Fatalf("raw status = %q", line)
	}
	line = readSAMLine(t, rawReader)
	if !strings.Contains(line, "RAW RECEIVED") || !strings.Contains(line, "SIZE=3") {
		t.Fatalf("raw receive = %q", line)
	}
	body = make([]byte, 3)
	_, _ = io.ReadFull(rawReader, body)
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
