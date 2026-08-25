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

	ivnp "gosuda.org/ivnp"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/support/observability"
)

func TestEmbeddedServerLiveUDPIngressForwardingAndBinding(t *testing.T) {
	controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
	controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
	controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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
			controller := &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)}
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

func (c *blockingUDPController) CreateDestination(ctx context.Context, spec clientapi.DestinationSpec) (clientapi.DestinationEndpoint, error) {
	endpoint, err := c.loop.CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &blockingUDPEndpoint{loopEndpoint: endpoint.(*loopEndpoint), entered: c.entered, canceled: c.canceled}, nil
}
func (c *blockingUDPController) DestroyDestination(_ context.Context, endpoint clientapi.DestinationEndpoint) error {
	return endpoint.Close()
}

type blockingUDPEndpoint struct {
	*loopEndpoint
	entered  chan struct{}
	canceled chan struct{}
}

func (e *blockingUDPEndpoint) SendMessage(ctx context.Context, _ streamtunnel.Delivery) error {
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
		loop:     &loopController{endpoints: make(map[ivnp.Hash]*loopEndpoint)},
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
