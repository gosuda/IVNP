package streamingtunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/networking/internal/streaming"
)

var (
	_ net.Conn             = (*tunnelConn)(nil)
	_ stream.StreamNetwork = (*TunnelNetwork)(nil)
)

func TestTunnelNetworkRejectsNonInteroperableX25519DestinationIdentity(t *testing.T) {
	destination, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	_, err = NewTunnelNetwork(TunnelNetworkConfig{
		Destination: destination,
		Sender:      &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)},
	})
	if !errors.Is(err, ErrTunnelIdentity) {
		t.Fatalf("X25519 Destination identity error = %v, want %v", err, ErrTunnelIdentity)
	}
}

func TestTunnelNetworkDialListenOrderedBytes(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork), zeroSYNACKPorts: true}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	listener, err := (stream.ListenerConfig{Network: server}).Listen(context.Background(), ":8080")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()

	context, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outbound, err := client.DialI2PFromPort(context, server.B32()+":8080", 4242)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case err = <-acceptErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("listener did not accept synchronized stream")
	}
	t.Cleanup(func() { _ = inbound.Close() })
	if local, ok := outbound.(interface{ LocalI2PPort() uint16 }); !ok || local.LocalI2PPort() != 4242 {
		t.Fatalf("outbound source port = %T/%v", outbound, ok)
	}
	if remote, ok := inbound.(interface{ RemoteI2PPort() uint16 }); !ok || remote.RemoteI2PPort() != 4242 {
		t.Fatalf("inbound source port = %T/%v", inbound, ok)
	}
	fabric.mu.Lock()
	initialACKs := fabric.initialACKs
	fabric.mu.Unlock()
	if initialACKs != 1 {
		t.Fatalf("SYNACK acknowledgements = %d, want 1", initialACKs)
	}

	payload := bytes.Repeat([]byte("tunnel-stream-"), 700)
	if n, err := outbound.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(inbound, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("received payload differs from transmitted bytes")
	}
	fabric.mu.Lock()
	maxDataPayload := fabric.maxDataPayload
	maxDataPacket := fabric.maxDataPacket
	fabric.mu.Unlock()
	if maxDataPayload != localMaxPayloadSize || maxDataPacket != MaxPacketSize {
		t.Fatalf("IVNP advertised MSS produced payload/packet %d/%d, want %d/%d", maxDataPayload, maxDataPacket, localMaxPayloadSize, MaxPacketSize)
	}

	if _, err := inbound.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(outbound, reply); err != nil || string(reply) != "reply" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if n, err := inbound.Read(one); n != 0 || err != io.EOF {
		t.Fatalf("Read after peer Close = %d, %v", n, err)
	}
	if err := inbound.Close(); err != nil {
		t.Fatalf("peer Close after EOF = %v", err)
	}
}

func TestTunnelNetworkHonorsJavaPeerPayloadMSS(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	listener, err := server.ListenI2P(context.Background(), ":8081")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outbound, err := client.DialI2P(ctx, server.B32()+":8081")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	inbound := <-accepted
	t.Cleanup(func() { _ = inbound.Close() })

	connection := outbound.(*tunnelConn)
	connection.setPeerMaxPayloadSize(0)
	if connection.peerMaxPayloadSize != minPeerMaxPayloadSize {
		t.Fatalf("explicit zero MSS = %d, want Java clamp %d", connection.peerMaxPayloadSize, minPeerMaxPayloadSize)
	}
	connection.setPeerMaxPayloadSize(-1)
	if connection.peerMaxPayloadSize != minPeerMaxPayloadSize {
		t.Fatalf("omitted MSS changed negotiated value to %d", connection.peerMaxPayloadSize)
	}
	connection.setPeerMaxPayloadSize(1812)
	payload := bytes.Repeat([]byte("java-streaming-mtu"), 1024)
	if n, writeErr := outbound.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v", n, writeErr)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(inbound, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("received payload differs from transmitted bytes")
	}
	fabric.mu.Lock()
	maxDataPayload := fabric.maxDataPayload
	maxDataPacket := fabric.maxDataPacket
	fabric.mu.Unlock()
	if maxDataPayload != 1812 || maxDataPacket != 1812+HeaderLen {
		t.Fatalf("Java MSS produced payload/packet %d/%d, want %d/%d", maxDataPayload, maxDataPacket, 1812, 1812+HeaderLen)
	}
}

func TestTunnelNetworkRetransmitsLostPacket(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork), dropFirstData: true}
	client, server := newTunnelNetworkPair(t, fabric, 20*time.Millisecond)
	listener, err := server.ListenI2P(context.Background(), ":77")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	context, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outbound, err := client.DialI2P(context, server.B32()+":77")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept stream")
	}
	t.Cleanup(func() { _ = inbound.Close() })

	if _, err := outbound.Write([]byte("retransmit")); err != nil {
		t.Fatal(err)
	}
	if err := inbound.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("retransmit"))
	if _, err := io.ReadFull(inbound, received); err != nil || string(received) != "retransmit" {
		t.Fatalf("retransmitted payload = %q, %v", received, err)
	}
	fabric.mu.Lock()
	dropped := fabric.dropped
	fabric.mu.Unlock()
	if !dropped {
		t.Fatal("test fabric did not drop an initial data packet")
	}
}

func TestTunnelNetworkCloseRetransmitsPendingDataBeforeEOF(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork), dropFirstData: true}
	client, server := newTunnelNetworkPair(t, fabric, 20*time.Millisecond)
	listener, err := server.ListenI2P(context.Background(), ":78")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outbound, err := client.DialI2P(ctx, server.B32()+":78")
	if err != nil {
		t.Fatal(err)
	}
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("listener did not accept stream")
	}
	t.Cleanup(func() { _ = inbound.Close() })

	payload := bytes.Repeat([]byte("close-after-data-"), 100)
	if n, writeErr := outbound.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v", n, writeErr)
	}
	closed := make(chan error, 1)
	go func() { closed <- outbound.Close() }()

	if err = inbound.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(inbound, received); err != nil {
		t.Fatalf("ReadFull() returned before retransmitted data: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("received payload differs after out-of-order CLOSE")
	}
	one := make([]byte, 1)
	if n, readErr := inbound.Read(one); n != 0 || readErr != io.EOF {
		t.Fatalf("Read after ordered CLOSE = %d, %v", n, readErr)
	}
	select {
	case closeErr := <-closed:
		if closeErr != nil {
			t.Fatalf("Close() = %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after CLOSE acknowledgement")
	}
}

func TestTunnelNetworkCloseCancelsBlockedRetransmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		destination, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		sender := &blockingTunnelSender{started: make(chan struct{})}
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: destination, Sender: sender, RetransmitAfter: 10 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 1, 2, true)
		if err := network.register(connection); err != nil {
			_ = network.Close()
			t.Fatal(err)
		}
		connection.mu.Lock()
		connection.pending[1] = pendingPacket{wire: []byte{1}, sent: time.Now().Add(-time.Second)}
		connection.mu.Unlock()
		network.scheduleRetry(connection)
		<-sender.started

		closed := make(chan struct{})
		go func() {
			_ = network.Close()
			close(closed)
		}()
		<-closed
	})
}

func TestTunnelNetworkCloseDrainsPacingQueue(t *testing.T) {
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	sender := &blockingTunnelSender{started: make(chan struct{})}
	network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: destination, Sender: sender})
	if err != nil {
		t.Fatal(err)
	}
	connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 1, 2, true)
	if err := network.register(connection); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() { results <- connection.sendWire(context.Background(), []byte{1}) }()
	select {
	case <-sender.started:
	case <-time.After(time.Second):
		t.Fatal("pacing worker did not start sender")
	}
	go func() { results <- connection.sendWire(context.Background(), []byte{2}) }()
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-results; err == nil {
			t.Fatal("queued send succeeded after network close")
		}
	}
}

func TestSendScheduleDoesNotHeadOfLineBlock(t *testing.T) {
	now := time.Now()
	delayed := &tunnelConn{nextPaced: now.Add(time.Second)}
	ready := &tunnelConn{}
	var schedule sendSchedule
	schedule.push(sendRequest{connection: delayed}, delayed.paceDue(now))
	schedule.push(sendRequest{connection: ready}, ready.paceDue(now))
	request, ok := schedule.peek()
	if !ok || request.request.connection != ready || request.due.After(now) {
		t.Fatalf("send schedule head = %#v; want ready request", request)
	}
}

func TestRetryScheduleUpdatesAndRemovesConnection(t *testing.T) {
	now := time.Now()
	first := &tunnelConn{}
	second := &tunnelConn{}
	schedule := retrySchedule{indices: make(map[*tunnelConn]int)}
	schedule.upsert(first, now.Add(time.Second))
	schedule.upsert(second, now.Add(500*time.Millisecond))
	schedule.upsert(first, now.Add(100*time.Millisecond))

	retry, ok := schedule.peek()
	if !ok || retry.connection != first {
		t.Fatalf("retry schedule head = %#v; want updated first connection", retry)
	}
	schedule.upsert(first, time.Time{})
	retry, ok = schedule.peek()
	if !ok || retry.connection != second {
		t.Fatalf("retry schedule after removal = %#v; want second connection", retry)
	}
}

func TestSendCompletionDrainsAbandonedResult(t *testing.T) {
	network := &TunnelNetwork{}
	completion := network.acquireCompletion()
	completion.release()
	sendRequest{result: completion}.finish(context.Canceled)

	reused := network.acquireCompletion()
	select {
	case err := <-reused.value:
		t.Fatalf("acquired completion retained stale result %v", err)
	default:
	}
	reused.release()
	reused.release()
}

func TestPendingWireLeaseOutlivesPendingOwnerUntilSendFinishes(t *testing.T) {
	wire, lease, ok := acquireWireLease(HeaderLen)
	if !ok {
		t.Fatal("acquireWireLease failed")
	}
	wire[0] = 1
	lease.retain()
	pendingPacket{wire: wire, lease: lease}.release()
	if got := lease.refs.Load(); got != 1 {
		t.Fatalf("wire lease references after pending release = %d, want 1", got)
	}
	sendRequest{wire: wire, lease: lease}.finish(nil)
	if lease.slab != nil {
		t.Fatal("wire lease retained slab after send completion")
	}
}

func TestPendingSendLeaseSurvivesConcurrentNetworkClose(t *testing.T) {
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: destination, Sender: discardTunnelSender{}})
	if err != nil {
		t.Fatal(err)
	}
	connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 1, 2, true)
	if err = network.register(connection); err != nil {
		t.Fatal(err)
	}

	network.outboundMu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := connection.Write([]byte{1})
		writeDone <- writeErr
	}()
	var lease *wireLease
	deadline := time.After(time.Second)
	for lease == nil {
		connection.mu.Lock()
		for _, pending := range connection.pending {
			lease = pending.lease
			break
		}
		connection.mu.Unlock()
		select {
		case <-deadline:
			network.outboundMu.Unlock()
			_ = network.Close()
			t.Fatal("Write did not publish pending wire")
		default:
		}
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- network.Close() }()
	<-connection.done
	closeDeadline := time.After(time.Second)
	for {
		connection.mu.Lock()
		pending := len(connection.pending)
		connection.mu.Unlock()
		if pending == 0 {
			break
		}
		select {
		case <-closeDeadline:
			network.outboundMu.Unlock()
			t.Fatal("concurrent close did not release pending owner")
		default:
		}
	}
	if got := lease.refs.Load(); got != 1 || lease.slab == nil {
		network.outboundMu.Unlock()
		t.Fatalf("wire lease after concurrent close = refs %d slab %p; want retained send owner", got, lease.slab)
	}
	network.outboundMu.Unlock()
	if err = <-writeDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write during close = %v, want net.ErrClosed", err)
	}
	if err = <-closeDone; err != nil {
		t.Fatal(err)
	}
	if lease.slab != nil {
		t.Fatal("wire lease retained slab after send admission failed")
	}
}

func BenchmarkStreamingWireAndCompletionPools(b *testing.B) {
	packet := Packet{SendStreamID: 1, ReceiveStreamID: 2, Sequence: 1, Payload: []byte{1, 2, 3}}
	network := &TunnelNetwork{}
	b.ReportAllocs()
	for b.Loop() {
		_, lease, err := marshalPacketLeased(packet)
		if err != nil {
			b.Fatal(err)
		}
		lease.release()
		completion := network.acquireCompletion()
		completion.release()
		completion.release()
	}
}

func TestStreamingSignatureParsesJavaOptionOrder(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, _ := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	packet := Packet{
		ReceiveStreamID: 1,
		Sequence:        0,
		NACKCount:       8,
		NACKs:           make([]byte, foundation.HashLength),
		Flags:           FlagSynchronize | FlagNoACK | FlagDelayRequested,
		Options:         []byte{0, 5},
	}
	wire, err := client.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := streaming.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, peerMSS, verifyErr := verifyControl(parsed, wire, client.localHash, nil, true); verifyErr != nil {
		t.Fatal(verifyErr)
	} else if peerMSS != localMaxPayloadSize {
		t.Fatalf("advertised payload MSS = %d, want %d", peerMSS, localMaxPayloadSize)
	}
}

func TestTunnelNetworkRejectsTamperedSynchronize(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	packet := Packet{
		ReceiveStreamID: 1,
		Sequence:        0,
		Flags:           FlagSynchronize | FlagNoACK,
	}
	wire, err := client.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] ^= 1
	err = server.HandleDelivery(context.Background(), Delivery{From: client.localHash, To: server.localHash, FromPort: 1, ToPort: 2, Protocol: ProtocolStreaming, Payload: wire})
	if err == nil {
		t.Fatal("tampered synchronized packet was accepted")
	}
}

func TestTunnelNetworkAcceptsJavaSynchronizePayload(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	server.sender = discardTunnelSender{}
	listener, err := server.ListenI2P(context.Background(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	packet := Packet{ReceiveStreamID: 1, Sequence: 0, NACKCount: 8, NACKs: server.localHash[:], Flags: FlagSynchronize | FlagNoACK, Payload: payload}
	wire, err := client.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	err = server.HandleDelivery(context.Background(), Delivery{From: client.localHash, To: server.localHash, FromPort: 1234, ToPort: 80, Protocol: ProtocolStreaming, Payload: wire})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.(*tunnelConn).abort(false) })
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("SYN payload = %q, %v", got, err)
	}
}

func TestTunnelNetworkAcceptsJavaSynchronizeReplyPayload(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	connection := client.newConn(1, 0, server.localHash, foundation.Identity{}, 1234, 80, true)
	if err := client.register(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.abort(false) })
	payload := []byte("HTTP/1.1 200 OK\r\n\r\n")
	packet := Packet{SendStreamID: 1, ReceiveStreamID: 2, Sequence: 0, Flags: FlagSynchronize, Payload: payload}
	wire, err := server.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	err = client.HandleDelivery(context.Background(), Delivery{From: server.localHash, To: client.localHash, FromPort: 80, ToPort: 1234, Protocol: ProtocolStreaming, Payload: wire})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("SYN-ACK payload = %q, %v", got, err)
	}
}

func TestTunnelReliabilityKarnFastRetransmitAndNACKs(t *testing.T) {
	network := &TunnelNetwork{retransmit: time.Second, maxRetries: 4, readCapacity: 1}
	connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 1, 2, true)
	now := time.Now()

	connection.pending[1] = pendingPacket{wire: []byte{1}, sent: now.Add(-100 * time.Millisecond), retransmitted: true}
	connection.acknowledgeLocked(1, nil, now)
	if got, want := connection.rto.RTO(), time.Second; got != want {
		t.Fatalf("Karn changed RTO after retransmitted packet: got %v, want %v", got, want)
	}
	connection.pending[2] = pendingPacket{wire: []byte{2}, sent: now.Add(-200 * time.Millisecond)}
	connection.acknowledgeLocked(2, nil, now)
	if got, want := connection.rto.RTO(), 600*time.Millisecond; got != want {
		t.Fatalf("RTO sample = %v, want %v", got, want)
	}

	connection.pending[3] = pendingPacket{wire: []byte{3}, sent: now}
	nack := []byte{0, 0, 0, 3}
	for range 2 {
		if retransmit := connection.acknowledgeLocked(2, nack, now); len(retransmit) != 0 {
			t.Fatal("fast retransmit fired before three duplicate ACK/NACKs")
		}
	}
	retransmit := connection.acknowledgeLocked(2, nack, now)
	if len(retransmit) != 1 || retransmit[0].wire[0] != 3 {
		t.Fatalf("fast retransmit = %v, want packet 3", retransmit)
	}
	if got := connection.congestion.Window(); got != streaming.MinWindow {
		t.Fatalf("fast retransmit window = %d, want %d", got, streaming.MinWindow)
	}

	connection.expect = 1
	connection.reordered[3] = receivedPacket{payload: []byte("late")}
	if got, want := connection.nacksLocked(), []byte{0, 0, 0, 1, 0, 0, 0, 2}; !bytes.Equal(got, want) {
		t.Fatalf("NACK holes = %v, want %v", got, want)
	}
}

func newTunnelNetworkPair(t *testing.T, fabric *streamFabric, retransmit time.Duration) (*TunnelNetwork, *TunnelNetwork) {
	t.Helper()
	clientDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	serverDestination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: clientDestination, Sender: fabric, RetransmitAfter: retransmit, MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: serverDestination, Sender: fabric, RetransmitAfter: retransmit, MaxRetries: 3})
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	fabric.mu.Lock()
	fabric.networks[clientDestination.Hash()] = client
	fabric.networks[serverDestination.Hash()] = server
	fabric.mu.Unlock()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

type streamFabric struct {
	mu              sync.Mutex
	networks        map[foundation.Hash]*TunnelNetwork
	dropFirstData   bool
	dropped         bool
	maxDataPacket   int
	maxDataPayload  int
	initialACKs     int
	zeroSYNACKPorts bool
}

type discardTunnelSender struct{}

func (discardTunnelSender) SendTunnel(context.Context, Delivery) error { return nil }

type blockingTunnelSender struct{ started chan struct{} }

func (s *blockingTunnelSender) SendTunnel(ctx context.Context, _ Delivery) error {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *streamFabric) SendTunnel(ctx context.Context, delivery Delivery) error {
	packet, err := streaming.Parse(delivery.Payload)
	if err != nil {
		return err
	}
	f.mu.Lock()
	if packet.Sequence != 0 && len(packet.Payload) != 0 {
		if len(packet.Payload) > f.maxDataPayload {
			f.maxDataPayload = len(packet.Payload)
		}
		if len(delivery.Payload) > f.maxDataPacket {
			f.maxDataPacket = len(delivery.Payload)
		}
	}
	if packet.Sequence == 0 && packet.Flags == 0 && packet.SendStreamID != 0 && packet.ReceiveStreamID != 0 && len(packet.Payload) == 0 {
		f.initialACKs++
	}
	if f.zeroSYNACKPorts && packet.Flags&FlagSynchronize != 0 && packet.SendStreamID != 0 {
		delivery.FromPort, delivery.ToPort = 0, 0
	}
	if f.dropFirstData && !f.dropped && packet.Sequence != 0 && len(packet.Payload) != 0 {
		f.dropped = true
		f.mu.Unlock()
		return nil
	}
	target := f.networks[delivery.To]
	f.mu.Unlock()
	if target == nil {
		return ErrTunnelDestination
	}
	return target.HandleDelivery(ctx, delivery)
}
