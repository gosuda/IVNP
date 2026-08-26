package sam

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking"
	"gosuda.org/ivnp/observability"
)

func TestEmbeddedServerLiveUDPIngressForwardingAndBinding(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	metrics := observability.NewRegistry()
	server, err := NewServer(ServerConfig{
		Address: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Controller: controller, Metrics: metrics,
		MaxDatagramBytes: 32768, SessionQueue: 4, MaxSessionQueueBytes: 128 << 10, MaxServerQueueBytes: 256 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()

	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = fmt.Fprintf(control, "SESSION CREATE STYLE=DATAGRAM ID=udp DESTINATION=TRANSIENT HOST=127.0.0.1 PORT=%d\n", receiver.LocalAddr().(*net.UDPAddr).Port)
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatal(line)
	}
	private := strings.Split(line, " DESTINATION=")[1]
	local, err := decodePrivateDestination(private)
	if err != nil {
		t.Fatal(err)
	}
	destination := string(local.Destination())
	local.ReleaseSensitive()

	sender, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	wire := []byte("3.3 udp " + destination + " FROM_PORT=4 TO_PORT=0\nhello")
	if _, err = sender.Write(wire); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	forwarded := string(buffer[:n])
	if !strings.Contains(forwarded, "\nFROM_PORT=4\nTO_PORT=0\n\nhello") || !strings.HasPrefix(forwarded, destination[:32]) {
		t.Fatalf("forwarded datagram = %q", forwarded)
	}

	// Key=value IDs, duplicate spacing, and a source IP different from the
	// control socket are rejected without reaching the destination route.
	for _, malformed := range [][]byte{
		[]byte("3.3 ID=udp " + destination + "\nbad"),
		[]byte("3.3  udp " + destination + "\nbad"),
		[]byte("3.3 udp " + destination + "\r\nbad"),
	} {
		_, _ = sender.Write(malformed)
	}
	wrongSource, bindErr := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, server.UDPAddr().(*net.UDPAddr))
	if bindErr == nil {
		_, _ = wrongSource.Write([]byte("3.3 udp " + destination + "\nbad"))
		_ = wrongSource.Close()
	}
	_ = receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err = receiver.ReadFromUDP(buffer); err == nil {
		t.Fatalf("malformed UDP packet forwarded: %q", buffer[:n])
	}
	waitForSAMCondition(t, time.Second, func() bool {
		return metrics.Snapshot().SAM.UDPInvalid >= 3
	}, "SAM UDP invalid accounting")
}

func TestEmbeddedServerPrimaryRawChildUDPHeader(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Controller: controller, SessionQueue: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=PRIMARY ID=owner DESTINATION=TRANSIENT\n")
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatal(line)
	}
	local, err := decodePrivateDestination(strings.Split(line, " DESTINATION=")[1])
	if err != nil {
		t.Fatal(err)
	}
	destination := string(local.Destination())
	local.ReleaseSensitive()
	_, _ = fmt.Fprintf(control, "SESSION ADD STYLE=RAW ID=child HOST=127.0.0.1 PORT=%d PROTOCOL=18 LISTEN_PORT=7 HEADER=true\n", receiver.LocalAddr().(*net.UDPAddr).Port)
	if line = readSAMLine(t, reader); line != "SESSION STATUS RESULT=OK" {
		t.Fatal(line)
	}
	sender, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	_, _ = sender.Write([]byte("3.3 child " + destination + " FROM_PORT=8 TO_PORT=7 PROTOCOL=18\nraw"))
	buffer := make([]byte, 256)
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "FROM_PORT=8\nTO_PORT=7\nPROTOCOL=18\n\nraw" {
		t.Fatalf("raw forwarding = %q", got)
	}

	// Control framing remains intact while the child forwards over UDP.
	_ = control.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err = bufio.NewReader(control).ReadByte(); err == nil {
		t.Fatal("raw UDP forwarding also wrote to PRIMARY control socket")
	}
}

func TestEmbeddedServerUDPQueuedByteBudgetBackpressure(t *testing.T) {
	controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
	server, err := NewServer(ServerConfig{
		Address: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Controller: controller,
		SessionQueue: 2, MaxSessionQueueBytes: 256, MaxServerQueueBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = server.Wait() }()
	control, reader := samDial(t, server.Addr().String())
	defer control.Close()
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=RAW ID=budget DESTINATION=TRANSIENT PROTOCOL=18\n")
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatal(line)
	}
	local, err := decodePrivateDestination(strings.Split(line, " DESTINATION=")[1])
	if err != nil {
		t.Fatal(err)
	}
	destination := string(local.Destination())
	local.ReleaseSensitive()
	sender, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	_, _ = sender.Write([]byte("3.3 budget " + destination + "\nx"))
	_ = control.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if line, err = reader.ReadString('\n'); err == nil {
		t.Fatalf("over-budget UDP ingress reached route: %q", line)
	}
}

func TestTCPDatagramAndRawInvalidSizeReturnStatus(t *testing.T) {
	for _, style := range []string{"DATAGRAM", "RAW"} {
		t.Run(style, func(t *testing.T) {
			controller := &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)}
			server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Controller: controller, MaxDatagramBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			if err = server.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close(); _ = server.Wait() }()
			control, reader := samDial(t, server.Addr().String())
			defer control.Close()
			_, _ = fmt.Fprintf(control, "SESSION CREATE STYLE=%s ID=bad-size DESTINATION=TRANSIENT\n", style)
			line := readSAMLine(t, reader)
			if !strings.Contains(line, "RESULT=OK DESTINATION=") {
				t.Fatal(line)
			}
			_, _ = fmt.Fprintf(control, "%s SEND ID=bad-size DESTINATION=invalid SIZE=1025\n", style)
			if line = readSAMLine(t, reader); line != style+" STATUS RESULT=I2P_ERROR MESSAGE=INVALID_SIZE" {
				t.Fatalf("invalid size status = %q", line)
			}
			_, _ = fmt.Fprintf(control, "%s SEND ID=bad-size DESTINATION=invalid SIZE=nope\n", style)
			if line = readSAMLine(t, reader); line != style+" STATUS RESULT=I2P_ERROR MESSAGE=INVALID_SIZE" {
				t.Fatalf("malformed size status = %q", line)
			}
			_, _ = fmt.Fprintf(control, "%s SEND ID=bad-size DESTINATION=invalid\n", style)
			if line = readSAMLine(t, reader); line != style+" STATUS RESULT=I2P_ERROR MESSAGE=INVALID_SIZE" {
				t.Fatalf("missing size status = %q", line)
			}
		})
	}
}

type blockingUDPController struct {
	loop     *loopController
	entered  chan struct{}
	canceled chan struct{}
}

func (c *blockingUDPController) CreateDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	endpoint, err := c.loop.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &blockingUDPEndpoint{loopEndpoint: endpoint.(*loopEndpoint), entered: c.entered, canceled: c.canceled}, nil
}
func (c *blockingUDPController) DestroyDestination(_ context.Context, endpoint destination.DestinationEndpoint) error {
	return endpoint.Close()
}

type blockingUDPEndpoint struct {
	*loopEndpoint
	entered  chan struct{}
	canceled chan struct{}
}

func (e *blockingUDPEndpoint) SendMessage(ctx context.Context, _ networking.StreamingTunnelDelivery) error {
	select {
	case <-e.entered:
	default:
		close(e.entered)
	}
	<-ctx.Done()
	select {
	case <-e.canceled:
	default:
		close(e.canceled)
	}
	return ctx.Err()
}

func TestUDPBlockingDestinationSendCancelsAndWaitIsBounded(t *testing.T) {
	controller := &blockingUDPController{
		loop:     &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)},
		entered:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	server, err := NewServer(ServerConfig{Address: "127.0.0.1:0", UDPAddress: "127.0.0.1:0", Controller: controller, SessionQueue: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	control, reader := samDial(t, server.Addr().String())
	_, _ = io.WriteString(control, "SESSION CREATE STYLE=RAW ID=blocking DESTINATION=TRANSIENT PROTOCOL=18\n")
	line := readSAMLine(t, reader)
	if !strings.Contains(line, "RESULT=OK DESTINATION=") {
		t.Fatal(line)
	}
	local, err := decodePrivateDestination(strings.Split(line, " DESTINATION=")[1])
	if err != nil {
		t.Fatal(err)
	}
	destination := string(local.Destination())
	local.ReleaseSensitive()
	sender, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sender.Write([]byte("3.3 blocking " + destination + "\nblocked"))
	select {
	case <-controller.entered:
	case <-time.After(time.Second):
		t.Fatal("destination send did not start")
	}
	_ = control.Close()
	_ = sender.Close()
	_ = server.Close()
	waited := make(chan struct{})
	go func() {
		_ = server.Wait()
		close(waited)
	}()
	select {
	case <-controller.canceled:
	case <-time.After(time.Second):
		t.Fatal("destination send context was not canceled")
	}
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("Server.Wait remained blocked after cancellation")
	}
}

func TestDatagramFrameUsesExactPayloadCapacity(t *testing.T) {
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &loopEndpoint{
		local:         local,
		controller:    &loopController{endpoints: make(map[foundation.Hash]*loopEndpoint)},
		subscriptions: make(map[destination.DestinationRoute]*loopSubscription),
	}
	defer endpoint.Close()
	payload := []byte("exact datagram")
	overhead := datagramV1Overhead(endpoint)
	session := &samSession{
		server:           &Server{config: ServerConfig{MaxDatagramBytes: overhead + len(payload)}},
		endpoint:         endpoint,
		datagramOverhead: overhead,
	}
	frame, lease, ok := session.datagramFrame(len(payload))
	if !ok {
		t.Fatal("exact-size datagram frame rejected")
	}
	defer lease.ReleaseSensitive()
	n, err := endpoint.MarshalDatagramV1To(frame, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(frame) || len(frame) != overhead+len(payload) {
		t.Fatalf("framed length = %d, marshal length = %d, want %d", len(frame), n, overhead+len(payload))
	}
	if _, tooLarge, accepted := session.datagramFrame(len(payload) + 1); accepted {
		tooLarge.ReleaseSensitive()
		t.Fatal("oversized datagram frame accepted")
	}
}

func TestSAMHeaderEncoding(t *testing.T) {
	payload := []byte("payload")
	datagramWire, datagramLease, ok := datagramUDPWire("source", 0, 65535, payload)
	if !ok {
		t.Fatal("datagram UDP wire allocation failed")
	}
	if got, want := string(datagramWire), "source\nFROM_PORT=0\nTO_PORT=65535\n\npayload"; got != want {
		t.Fatalf("datagram UDP wire = %q, want %q", got, want)
	}
	datagramLease.ReleaseSensitive()

	rawWire, rawLease, ok := rawUDPWire(65535, 0, 255, payload)
	if !ok {
		t.Fatal("raw UDP wire allocation failed")
	}
	if got, want := string(rawWire), "FROM_PORT=65535\nTO_PORT=0\nPROTOCOL=255\n\npayload"; got != want {
		t.Fatalf("raw UDP wire = %q, want %q", got, want)
	}
	rawLease.ReleaseSensitive()

	datagramHeader, datagramHeaderLease, ok := datagramReceivedHeader("source", 1, 2, len(payload))
	if !ok {
		t.Fatal("datagram header allocation failed")
	}
	if got, want := string(datagramHeader), "DATAGRAM RECEIVED DESTINATION=source FROM_PORT=1 TO_PORT=2 SIZE=7\n"; got != want {
		t.Fatalf("datagram header = %q, want %q", got, want)
	}
	datagramHeaderLease.Release()

	rawHeader, rawHeaderLease, ok := rawReceivedHeader(18, 3, 4, len(payload))
	if !ok {
		t.Fatal("raw header allocation failed")
	}
	if got, want := string(rawHeader), "RAW RECEIVED PROTOCOL=18 FROM_PORT=3 TO_PORT=4 SIZE=7\n"; got != want {
		t.Fatalf("raw header = %q, want %q", got, want)
	}
	rawHeaderLease.Release()
}

func TestUDPPacketReleaseClearsLeasedPayload(t *testing.T) {
	lease, ok := pool.AcquireLease(4)
	if !ok {
		t.Fatal("payload lease allocation failed")
	}
	payload, _ := lease.Bytes(4)
	copy(payload, "data")
	alias := payload
	packet := udpPacket{payload: payload, lease: lease}
	packet.releasePayload()
	if packet.payload != nil || packet.lease != nil {
		t.Fatal("released packet retained payload ownership")
	}
	for i, value := range alias {
		if value != 0 {
			t.Fatalf("released payload byte %d = %d", i, value)
		}
	}
}

func BenchmarkSAMFramingBuffers(b *testing.B) {
	const source = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-~"
	payload := make([]byte, 1024)
	session := &samSession{
		server:           &Server{config: ServerConfig{MaxDatagramBytes: 2048}},
		datagramOverhead: 512,
	}
	b.Run("datagram-frame", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			frame, lease, ok := session.datagramFrame(len(payload))
			if !ok {
				b.Fatal("frame allocation failed")
			}
			frame[0] = 1
			lease.ReleaseSensitive()
		}
	})
	b.Run("datagram-udp-header", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			wire, lease, ok := datagramUDPWire(source, 65535, 65535, payload)
			if !ok {
				b.Fatal("wire allocation failed")
			}
			lease.ReleaseSensitive()
			_ = wire
		}
	})
	b.Run("raw-udp-header", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			wire, lease, ok := rawUDPWire(65535, 65535, 255, payload)
			if !ok {
				b.Fatal("wire allocation failed")
			}
			lease.ReleaseSensitive()
			_ = wire
		}
	})
}
