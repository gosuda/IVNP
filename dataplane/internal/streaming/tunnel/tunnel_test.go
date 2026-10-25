package streamingtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/stream"
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
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork), zeroSYNACKPorts: true, ackCompleted: make(chan struct{}, 1)}
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

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		outbound, err := client.DialI2PFromPort(ctx, server.B32()+":8080", 4242)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = outbound.Close() })
		var inbound net.Conn
		select {
		case inbound = <-accepted:
		case err = <-acceptErr:
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inbound.Close() })
		if local, ok := outbound.(interface{ LocalI2PPort() uint16 }); !ok || local.LocalI2PPort() != 4242 {
			t.Fatalf("outbound source port = %T/%v", outbound, ok)
		}
		if remote, ok := inbound.(interface{ RemoteI2PPort() uint16 }); !ok || remote.RemoteI2PPort() != 4242 {
			t.Fatalf("inbound source port = %T/%v", inbound, ok)
		}
		initialACKs := fabric.waitInitialACKs(t, ctx, 1)
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
	})
}

func TestTunnelNetworkHonorsJavaPeerPayloadMSS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		if connection.peerMaxPayloadSize != minPeerMaxPayloadSize { // +checklocksignore
			t.Fatalf("explicit zero MSS = %d, want Java clamp %d", connection.peerMaxPayloadSize, minPeerMaxPayloadSize) // +checklocksignore
		}
		connection.setPeerMaxPayloadSize(-1)
		if connection.peerMaxPayloadSize != minPeerMaxPayloadSize { // +checklocksignore
			t.Fatalf("omitted MSS changed negotiated value to %d", connection.peerMaxPayloadSize) // +checklocksignore
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
	})
}

func TestTunnelNetworkRetransmitsLostPacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		outbound, err := client.DialI2P(ctx, server.B32()+":77")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = outbound.Close() })
		inbound := <-accepted
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
	})
}

func TestTunnelNetworkCloseRetransmitsPendingDataBeforeEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		inbound := <-accepted
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
		if closeErr := <-closed; closeErr != nil {
			t.Fatalf("Close() = %v", closeErr)
		}
	})
}

func TestTunnelNetworkCloseCancelsBlockedRetransmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retransmitStarted := make(chan struct{})
		var dataAttempts int
		var fabric *streamFabric
		fabric = &streamFabric{
			networks: make(map[foundation.Hash]*TunnelNetwork),
			beforeSend: func(ctx context.Context, delivery Delivery, packet Packet) (bool, error) {
				if packet.Sequence == 0 || len(packet.Payload) == 0 {
					return false, nil
				}
				fabric.mu.Lock()
				dataAttempts++
				attempt := dataAttempts
				fabric.mu.Unlock()
				if attempt == 1 {
					return true, nil
				}
				select {
				case <-retransmitStarted:
				default:
					close(retransmitStarted)
				}
				<-ctx.Done()
				return true, ctx.Err()
			},
		}
		client, server := newTunnelNetworkPair(t, fabric, 10*time.Millisecond)
		listener, err := server.ListenI2P(context.Background(), ":79")
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
		outbound, err := client.DialI2P(context.Background(), server.B32()+":79")
		if err != nil {
			t.Fatal(err)
		}
		inbound := <-accepted
		t.Cleanup(func() { _ = inbound.Close() })

		if _, err := outbound.Write([]byte("retransmit")); err != nil {
			t.Fatal(err)
		}
		<-retransmitStarted
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTunnelNetworkCloseDrainsPacingQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		blockData := false
		var fabric *streamFabric
		fabric = &streamFabric{
			networks: make(map[foundation.Hash]*TunnelNetwork),
			beforeSend: func(ctx context.Context, _ Delivery, packet Packet) (bool, error) {
				fabric.mu.Lock()
				shouldBlock := blockData && packet.Sequence != 0 && len(packet.Payload) != 0
				fabric.mu.Unlock()
				if !shouldBlock {
					return false, nil
				}
				select {
				case <-started:
				default:
					close(started)
				}
				<-ctx.Done()
				return true, ctx.Err()
			},
		}
		client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
		listener, err := server.ListenI2P(context.Background(), ":82")
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
		outbound, err := client.DialI2P(context.Background(), server.B32()+":82")
		if err != nil {
			t.Fatal(err)
		}
		inbound := <-accepted
		t.Cleanup(func() { _ = inbound.Close() })

		fabric.mu.Lock()
		blockData = true
		fabric.mu.Unlock()

		results := make(chan error, 2)
		go func() {
			_, writeErr := outbound.Write([]byte("first"))
			results <- writeErr
		}()
		<-started
		go func() {
			_, writeErr := outbound.Write([]byte("second"))
			results <- writeErr
		}()
		synctest.Wait()

		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := <-results; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("queued Write after network Close = %v, want net.ErrClosed", err)
			}
		}
	})
}

func TestTunnelNetworkMultiStreamFairnessWhenWindowExhausted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dropStalledPort := true
		var fabric *streamFabric
		fabric = &streamFabric{
			networks: make(map[foundation.Hash]*TunnelNetwork),
			beforeSend: func(_ context.Context, delivery Delivery, packet Packet) (bool, error) {
				fabric.mu.Lock()
				drop := dropStalledPort && delivery.FromPort == 4101 && packet.Sequence != 0 && len(packet.Payload) != 0
				fabric.mu.Unlock()
				return drop, nil
			},
		}
		client, server := newTunnelNetworkPair(t, fabric, 20*time.Millisecond)
		listener, err := server.ListenI2P(context.Background(), ":8085")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		accepted := make(chan net.Conn, 2)
		go func() {
			for range 2 {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				accepted <- connection
			}
		}()

		stalledOut, err := client.DialI2PFromPort(context.Background(), server.B32()+":8085", 4101)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stalledOut.Close() })
		stalledIn := <-accepted
		t.Cleanup(func() { _ = stalledIn.Close() })

		activeOut, err := client.DialI2PFromPort(context.Background(), server.B32()+":8085", 4102)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = activeOut.Close() })
		activeIn := <-accepted
		t.Cleanup(func() { _ = activeIn.Close() })

		stalledPayload := bytes.Repeat([]byte("stalled-window-"), 600)
		stalledWriteErr := make(chan error, 1)
		go func() {
			_, writeErr := stalledOut.Write(stalledPayload)
			stalledWriteErr <- writeErr
		}()
		synctest.Wait()
		select {
		case writeErr := <-stalledWriteErr:
			t.Fatalf("stalled stream Write completed while window was exhausted: %v", writeErr)
		default:
		}

		activePayload := bytes.Repeat([]byte("independent-stream-"), 300)
		activeWriteErr := make(chan error, 1)
		go func() {
			_, writeErr := activeOut.Write(activePayload)
			activeWriteErr <- writeErr
		}()
		activeReceived := make([]byte, len(activePayload))
		if _, err := io.ReadFull(activeIn, activeReceived); err != nil {
			t.Fatalf("active stream ReadFull while peer stream stalled: %v", err)
		}
		if !bytes.Equal(activeReceived, activePayload) {
			t.Fatal("active stream payload mismatch")
		}
		if err := <-activeWriteErr; err != nil {
			t.Fatalf("active stream Write: %v", err)
		}

		fabric.mu.Lock()
		dropStalledPort = false
		fabric.mu.Unlock()

		stalledReceived := make([]byte, len(stalledPayload))
		if _, err := io.ReadFull(stalledIn, stalledReceived); err != nil {
			t.Fatalf("stalled stream ReadFull after recovery: %v", err)
		}
		if !bytes.Equal(stalledReceived, stalledPayload) {
			t.Fatal("stalled stream payload mismatch after retransmission")
		}
		if err := <-stalledWriteErr; err != nil {
			t.Fatalf("stalled stream Write after recovery: %v", err)
		}
	})
}

func TestTunnelNetworkRetransmissionAndCleanupOnDropAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		droppedFirst4201 := false
		var fabric *streamFabric
		fabric = &streamFabric{
			networks: make(map[foundation.Hash]*TunnelNetwork),
			beforeSend: func(_ context.Context, delivery Delivery, packet Packet) (bool, error) {
				if packet.Sequence == 0 {
					return false, nil
				}
				fabric.mu.Lock()
				defer fabric.mu.Unlock()
				if delivery.FromPort == 4202 {
					return true, nil
				}
				if delivery.FromPort == 4201 && len(packet.Payload) != 0 && !droppedFirst4201 {
					droppedFirst4201 = true
					return true, nil
				}
				return false, nil
			},
		}
		client, server := newTunnelNetworkPair(t, fabric, 20*time.Millisecond)
		listener, err := server.ListenI2P(context.Background(), ":8086")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })

		accepted := make(chan net.Conn, 2)
		go func() {
			for range 2 {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				accepted <- connection
			}
		}()

		recoveredOut, err := client.DialI2PFromPort(context.Background(), server.B32()+":8086", 4201)
		if err != nil {
			t.Fatal(err)
		}
		recoveredIn := <-accepted

		abandonedOut, err := client.DialI2PFromPort(context.Background(), server.B32()+":8086", 4202)
		if err != nil {
			t.Fatal(err)
		}
		abandonedIn := <-accepted

		if _, err := abandonedOut.Write([]byte("dropped-forever")); err != nil {
			t.Fatal(err)
		}
		if _, err := recoveredOut.Write([]byte("retransmitted")); err != nil {
			t.Fatal(err)
		}
		if err := abandonedOut.SetWriteDeadline(time.Now().Add(15 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if err := abandonedOut.Close(); err == nil {
			t.Fatal("abandoned Close succeeded without peer acknowledgement")
		}
		_ = abandonedIn.Close()

		received := make([]byte, len("retransmitted"))
		if _, err := io.ReadFull(recoveredIn, received); err != nil || string(received) != "retransmitted" {
			t.Fatalf("recovered stream ReadFull = %q, %v", received, err)
		}
		if err := recoveredOut.Close(); err != nil {
			t.Fatalf("recoveredOut Close: %v", err)
		}
		if err := recoveredIn.Close(); err != nil {
			t.Fatalf("recoveredIn Close: %v", err)
		}
		synctest.Wait()
		if stats := client.Stats(); stats.Connections != 0 || stats.PendingPackets != 0 {
			t.Fatalf("client Stats after stream cleanup = %+v, want 0 connections and 0 pending packets", stats)
		}
	})
}

func TestTunnelNetworkCloseDuringBlockedSendPreservesPayloadAndDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		payloadMatch := make(chan bool, 1)
		blockData := false
		var fabric *streamFabric
		fabric = &streamFabric{
			networks: make(map[foundation.Hash]*TunnelNetwork),
			beforeSend: func(_ context.Context, delivery Delivery, packet Packet) (bool, error) {
				fabric.mu.Lock()
				intercept := blockData && packet.Sequence != 0 && len(packet.Payload) != 0
				if intercept {
					blockData = false
				}
				fabric.mu.Unlock()
				if !intercept {
					return false, nil
				}
				snapshot := append([]byte(nil), delivery.Payload...)
				close(entered)
				<-release
				parsedAfterClose, parseErr := dataplanestreaming.Parse(delivery.Payload)
				payloadMatch <- parseErr == nil &&
					bytes.Equal(delivery.Payload, snapshot) &&
					bytes.Equal(parsedAfterClose.Payload, []byte("in-flight-payload"))
				return true, net.ErrClosed
			},
		}
		client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
		listener, err := server.ListenI2P(context.Background(), ":8087")
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
		outbound, err := client.DialI2P(context.Background(), server.B32()+":8087")
		if err != nil {
			t.Fatal(err)
		}
		inbound := <-accepted
		t.Cleanup(func() { _ = inbound.Close() })

		fabric.mu.Lock()
		blockData = true
		fabric.mu.Unlock()

		writeDone := make(chan error, 1)
		go func() {
			_, writeErr := outbound.Write([]byte("in-flight-payload"))
			writeDone <- writeErr
		}()
		<-entered
		synctest.Wait()

		closeDone := make(chan error, 1)
		go func() { closeDone <- client.Close() }()
		synctest.Wait()

		if err := <-writeDone; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write during network Close = %v, want net.ErrClosed", err)
		}
		close(release)
		if !<-payloadMatch {
			t.Fatal("in-flight delivery payload was mutated or corrupted during concurrent network Close")
		}
		if err := <-closeDone; err != nil {
			t.Fatalf("client.Close() = %v", err)
		}
	})
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
	parsed, err := dataplanestreaming.Parse(wire)
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

func TestTunnelNetworkAcknowledgesRetransmittedSynchronizeReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork), ackCompleted: make(chan struct{}, 1)}
		client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
		listener, err := server.ListenI2P(context.Background(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		connection, err := client.DialI2PFromPort(ctx, server.B32()+":80", 1234)
		if err != nil {
			t.Fatal(err)
		}
		clientConn := connection.(*tunnelConn)
		t.Cleanup(func() { clientConn.abort(false) })
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { accepted.(*tunnelConn).abort(false) })
		packet := Packet{SendStreamID: clientConn.localID, ReceiveStreamID: clientConn.remoteID, Flags: FlagSynchronize} // +checklocksignore
		wire, err := server.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
		if err != nil {
			t.Fatal(err)
		}
		err = client.HandleDelivery(ctx, Delivery{From: server.localHash, To: client.localHash, FromPort: 80, ToPort: 1234, Protocol: ProtocolStreaming, Payload: wire})
		if err != nil {
			t.Fatal(err)
		}
		acknowledgments := fabric.waitInitialACKs(t, ctx, 2)
		if acknowledgments != 2 {
			t.Fatalf("SYN reply acknowledgments = %d, want initial and retransmitted reply ACKs", acknowledgments)
		}
	})
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

func TestTunnelNetworkSendsOfflineSignedControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		longTerm, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer longTerm.ReleaseSensitive()
		state := make([]byte, longTerm.PrivateEncodedLen())
		defer clear(state)
		if _, err = longTerm.MarshalPrivateTo(state); err != nil {
			t.Fatal(err)
		}
		publicLength := int(binary.BigEndian.Uint16(state[:2]))
		clear(state[2+publicLength : 2+publicLength+ed25519.PrivateKeySize])
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(private)
		seed := private.Seed()
		defer clear(seed)
		offline := foundation.OfflineSignature{Expires: uint32(time.Now().Add(time.Second).Unix()), Type: foundation.SigningEdDSASHA512Ed25519, PublicKey: public}
		content := make([]byte, offline.SignedContentLen())
		if _, err = offline.MarshalSignedContentTo(content); err != nil {
			t.Fatal(err)
		}
		offline.Signature, err = longTerm.Sign(content)
		if err != nil {
			t.Fatal(err)
		}
		destination, err := foundation.ImportLocalDestinationOffline(state, offline, seed)
		if err != nil {
			t.Fatal(err)
		}
		defer destination.ReleaseSensitive()
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: destination, Sender: discardTunnelSender{}})
		if err != nil {
			t.Fatal(err)
		}
		defer network.Close()
		wire, err := network.signedControl(Packet{ReceiveStreamID: 1, Flags: FlagSynchronize | FlagNoACK}, controlOptions{includeFrom: true, includeMax: true})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := dataplanestreaming.Parse(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = verifyControl(packet, wire, destination.Hash(), nil, true); err != nil {
			t.Fatalf("offline SYN signature: %v", err)
		}
		<-time.After(time.Until(time.Unix(int64(offline.Expires), 0)))
		if _, _, err = verifyControl(packet, wire, destination.Hash(), nil, true); err != nil {
			t.Fatalf("offline SYN at exact expiry: %v", err)
		}
		<-time.After(time.Millisecond)
		if _, _, err = verifyControl(packet, wire, destination.Hash(), nil, true); !errors.Is(err, ErrTunnelSignature) {
			t.Fatalf("expired offline SYN = %v, want signature rejection", err)
		}
	})
}

// +checklocksignore
func TestTunnelNetworkAcceptsJavaOfflineSignedSynchronizeReply(t *testing.T) {
	fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
	client, server := newTunnelNetworkPair(t, fabric, DefaultRetransmitAfter)
	client.sender = discardTunnelSender{}
	connection := client.newConn(1, 0, server.localHash, foundation.Identity{}, 1234, 80, true)
	if err := client.register(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.abort(false) })
	delivery := Delivery{From: server.localHash, To: client.localHash, FromPort: 80, ToPort: 1234, Protocol: ProtocolStreaming}

	earlyACK, err := marshalPacket(Packet{SendStreamID: 1, ReceiveStreamID: 2})
	if err != nil {
		t.Fatal(err)
	}
	delivery.Payload = earlyACK
	if err = client.HandleDelivery(context.Background(), delivery); err != nil {
		t.Fatalf("ACK before SYN reply: %v", err)
	}
	if connection.remoteID != 0 {
		t.Fatalf("early ACK established remote stream %d", connection.remoteID)
	}

	transientPublic, transientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responsePayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	earlyClose := Packet{
		SendStreamID: 1, ReceiveStreamID: 2, Sequence: 1,
		Flags: FlagClose | FlagSignatureIncluded, Payload: responsePayload,
		Options: make([]byte, ed25519.SignatureSize),
	}
	earlyCloseWire, err := marshalPacket(earlyClose)
	if err != nil {
		t.Fatal(err)
	}
	earlyCloseSignatureOffset := 17 + len(earlyClose.NACKs) + 5 + len(earlyClose.Options) - ed25519.SignatureSize
	copy(earlyCloseWire[earlyCloseSignatureOffset:earlyCloseSignatureOffset+ed25519.SignatureSize], ed25519.Sign(transientPrivate, earlyCloseWire))
	delivery.Payload = earlyCloseWire
	if err = client.HandleDelivery(context.Background(), delivery); err != nil {
		t.Fatalf("CLOSE before SYN reply: %v", err)
	}
	offlineBlock := make([]byte, 6+len(transientPublic))
	binary.BigEndian.PutUint32(offlineBlock[:4], uint32(time.Now().Add(time.Hour).Unix()))
	binary.BigEndian.PutUint16(offlineBlock[4:6], uint16(foundation.SigningEdDSASHA512Ed25519))
	copy(offlineBlock[6:], transientPublic)
	offlineSignature, err := server.sign(offlineBlock)
	if err != nil {
		t.Fatal(err)
	}
	packet := Packet{
		SendStreamID: 1, ReceiveStreamID: 2, Flags: FlagSynchronize | FlagSignatureIncluded |
			FlagFromIncluded | FlagMaxPacketSize | FlagOfflineSignature,
	}
	packet.Options = append(packet.Options, server.localRaw...)
	packet.Options = append(packet.Options, byte(localMaxPayloadSize>>8), byte(localMaxPayloadSize&0xff))
	packet.Options = append(packet.Options, offlineBlock...)
	packet.Options = append(packet.Options, offlineSignature...)
	packet.Options = append(packet.Options, make([]byte, ed25519.SignatureSize)...)
	wire, err := marshalPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	signatureOffset := 17 + len(packet.NACKs) + 5 + len(packet.Options) - ed25519.SignatureSize
	copy(wire[signatureOffset:signatureOffset+ed25519.SignatureSize], ed25519.Sign(transientPrivate, wire))
	delivery.Payload = wire
	if err = client.HandleDelivery(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	if connection.remoteID != 2 || connection.peerSigningType != foundation.SigningEdDSASHA512Ed25519 ||
		!bytes.Equal(connection.peerSigningPublic, transientPublic) {
		t.Fatalf("offline SYN reply established remote=%d signing=%d key=%x", connection.remoteID, connection.peerSigningType, connection.peerSigningPublic)
	}
	response := make([]byte, len(responsePayload))
	if _, err = io.ReadFull(connection, response); err != nil || !bytes.Equal(response, responsePayload) {
		t.Fatalf("deferred response = %q, %v", response, err)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("read after deferred CLOSE = %d, %v", n, readErr)
	}
}

// +checklocksignore
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
		if retransmit := connection.acknowledgeLocked(4, nack, now); len(retransmit) != 0 {
			t.Fatal("fast retransmit fired before three explicit NACKs")
		}
	}
	retransmit := connection.acknowledgeLocked(4, nack, now)
	if len(retransmit) != 1 || retransmit[0].wire[0] != 3 {
		t.Fatalf("fast retransmit = %v, want packet 3", retransmit)
	}
	for range 12 {
		if retransmit := connection.acknowledgeLocked(4, nack, now); len(retransmit) != 0 {
			t.Fatal("repeated loss reports retransmitted an already retried packet")
		}
	}
	if got := connection.congestion.Window(); got != dataplanestreaming.MinWindow {
		t.Fatalf("fast retransmit window = %d, want %d", got, dataplanestreaming.MinWindow)
	}
	connection.congestion = dataplanestreaming.NewCongestionWindow(16)
	connection.pending[5] = pendingPacket{wire: []byte{5}, sent: now}
	nack5 := []byte{0, 0, 0, 5}
	for range 3 {
		_ = connection.acknowledgeLocked(6, nack5, now)
	}
	if got, want := connection.congestion.Window(), uint16(8); got != want {
		t.Fatalf("high-window fast retransmit window = %d, want %d", got, want)
	}

	connection.expect = 1
	connection.reordered[3] = receivedPacket{payload: []byte("late")}
	through, nacks := connection.acknowledgmentsLocked()
	if through != 3 {
		t.Fatalf("ACK through = %d, want highest received packet 3", through)
	}
	if got, want := nacks, []byte{0, 0, 0, 1, 0, 0, 0, 2}; !bytes.Equal(got, want) {
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
	mu sync.Mutex
	// +checklocks:mu
	networks map[foundation.Hash]*TunnelNetwork
	// +checklocks:mu
	dropFirstData bool
	// +checklocks:mu
	dropped bool
	// +checklocks:mu
	maxDataPacket int
	// +checklocks:mu
	maxDataPayload int
	// +checklocks:mu
	initialACKs  int
	ackCompleted chan struct{}
	// +checklocks:mu
	zeroSYNACKPorts bool
	beforeSend      func(context.Context, Delivery, Packet) (bool, error)
}

func (f *streamFabric) waitInitialACKs(t testing.TB, ctx context.Context, want int) int {
	t.Helper()
	for {
		f.mu.Lock()
		count := f.initialACKs
		f.mu.Unlock()
		if count >= want {
			return count
		}
		select {
		case <-f.ackCompleted:
		case <-ctx.Done():
			t.Fatalf("delivered SYN-ACK acknowledgements = %d, want %d: %v", count, want, ctx.Err())
			return count
		}
	}
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
	packet, err := dataplanestreaming.Parse(delivery.Payload)
	if err != nil {
		return err
	}
	if f.beforeSend != nil {
		handled, hookErr := f.beforeSend(ctx, delivery, packet)
		if handled || hookErr != nil {
			return hookErr
		}
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
	err = target.HandleDelivery(ctx, delivery)
	initialACK := packet.Sequence == 0 && packet.Flags == 0 && len(packet.Payload) == 0
	connectedStreams := packet.SendStreamID != 0 && packet.ReceiveStreamID != 0
	if err == nil && initialACK && connectedStreams {
		f.mu.Lock()
		f.initialACKs++
		select {
		case f.ackCompleted <- struct{}{}:
		default:
		}
		f.mu.Unlock()
	}
	return err
}
