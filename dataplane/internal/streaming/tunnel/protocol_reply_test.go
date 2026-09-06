package streamingtunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
)

type protocolReplyGate struct {
	started    chan struct{}
	stopped    chan struct{}
	release    chan struct{}
	err        error
	wireIntact bool
}

func (s *protocolReplyGate) SendTunnel(ctx context.Context, delivery Delivery) error {
	original := append([]byte(nil), delivery.Payload...)
	close(s.started)
	select {
	case <-ctx.Done():
		s.err = ctx.Err()
	case <-s.release:
	}
	s.wireIntact = bytes.Equal(delivery.Payload, original)
	close(s.stopped)
	return s.err
}

func TestInboundRepliesDoNotWaitForRoutePreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, time.Hour)
		gate := &protocolReplyGate{started: make(chan struct{}), stopped: make(chan struct{})}
		server.sender = gate
		listener, err := server.ListenI2P(context.Background(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		syn := Packet{ReceiveStreamID: 123, NACKCount: 8, NACKs: server.localHash[:], Flags: FlagSynchronize | FlagNoACK}
		wire, err := client.signedControl(syn, controlOptions{includeFrom: true, includeMax: true})
		if err != nil {
			t.Fatal(err)
		}
		delivery := Delivery{From: client.localHash, To: server.localHash, FromPort: 1234, ToPort: 80, Protocol: ProtocolStreaming, Payload: wire}
		ingress, cancel := context.WithCancel(context.Background())
		defer cancel()
		returned := make(chan error, 1)
		go func() { returned <- server.HandleDelivery(ingress, delivery) }()
		<-gate.started
		synctest.Wait()
		select {
		case err := <-returned:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("SYN handler waited for blocked route preparation")
		}
		cancel()
		synctest.Wait()
		select {
		case <-gate.stopped:
			t.Fatal("protocol reply borrowed the ingress context")
		default:
		}
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		connection := accepted.(*tunnelConn)
		connection.mu.Lock()
		syncLease := connection.synchronizeLease
		connection.mu.Unlock()
		payload := []byte("authenticated data while SYN-ACK waits for NSR")
		data, err := marshalPacket(Packet{SendStreamID: connection.localID, ReceiveStreamID: 123, Sequence: 1, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		delivery.Payload = data
		go func() { returned <- server.HandleDelivery(context.Background(), delivery) }()
		synctest.Wait()
		select {
		case err := <-returned:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("data handler waited for its ACK behind blocked SYN-ACK")
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(accepted, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("inbound data = %q, %v", got, err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-gate.stopped:
		default:
			t.Fatal("shutdown did not join the blocked sender")
		}
		if !gate.wireIntact || !errors.Is(gate.err, context.Canceled) {
			t.Fatalf("blocked send retirement: intact=%t error=%v", gate.wireIntact, gate.err)
		}
		if syncLease == nil || syncLease.slab != nil {
			t.Fatal("shutdown retained the SYN-ACK wire lease")
		}
	})
}

func TestFailedAsynchronousSynchronizeReplyClosesConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, time.Hour)
		sendErr := errors.New("route preparation failed")
		gate := &protocolReplyGate{started: make(chan struct{}), stopped: make(chan struct{}), release: make(chan struct{}), err: sendErr}
		server.sender = gate
		listener, err := server.ListenI2P(context.Background(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		wire, err := client.signedControl(Packet{ReceiveStreamID: 123, Flags: FlagSynchronize | FlagNoACK}, controlOptions{includeFrom: true, includeMax: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := server.HandleDelivery(context.Background(), Delivery{From: client.localHash, To: server.localHash, FromPort: 1234, ToPort: 80, Protocol: ProtocolStreaming, Payload: wire}); err != nil {
			t.Fatal(err)
		}
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		connection := accepted.(*tunnelConn)
		<-gate.started
		close(gate.release)
		<-connection.done
		synctest.Wait()
		if count := server.Stats().Connections; count != 0 {
			t.Fatalf("failed SYN-ACK retained %d connections", count)
		}
		if _, err := connection.Write([]byte("must not send")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after failed SYN-ACK = %v", err)
		}
	})
}

func TestFullProtocolQueueRetiresConnectionAndWire(t *testing.T) {
	network := &TunnelNetwork{
		ctx: context.Background(), done: make(chan struct{}), outbound: make(chan sendRequest, 1),
		byID: make(map[uint32]*tunnelConn), inbound: make(map[inboundKey]*tunnelConn),
		readCapacity: 1, retransmit: time.Second,
	}
	connection := network.newConn(1, 2, foundation.Hash{1}, foundation.Identity{}, 80, 1234, false)
	if err := network.register(connection); err != nil {
		t.Fatal(err)
	}
	network.outbound <- sendRequest{}
	wire, lease, err := marshalPacketLeased(Packet{SendStreamID: 2, ReceiveStreamID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.queueProtocolOwned(wire, lease); !errors.Is(err, ErrTunnelBackpressure) {
		t.Fatalf("full protocol queue = %v", err)
	}
	select {
	case <-connection.done:
	default:
		t.Fatal("queue rejection left the connection active")
	}
	if lease.slab != nil {
		t.Fatal("queue rejection retained the wire lease")
	}
	if count := network.Stats().Connections; count != 0 {
		t.Fatalf("queue rejection retained %d connections", count)
	}
}
