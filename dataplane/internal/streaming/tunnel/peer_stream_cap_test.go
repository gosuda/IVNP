package streamingtunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/foundation"
)

// countingPrepObserver prepares every handshake immediately and counts calls,
// so tests can tell whether an over-cap SYN reached route preparation.
type countingPrepObserver struct {
	TunnelSender
	calls atomic.Int32
}

func (o *countingPrepObserver) PrepareHandshake(context.Context, foundation.Hash) (HandshakeFeedback, error) {
	o.calls.Add(1)
	return &handshakeFeedbackRecorder{TunnelSender: o.TunnelSender}, nil
}

func newPeerCapNetwork(t *testing.T, observer HandshakeObserver) *TunnelNetwork {
	t.Helper()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	network, err := NewTunnelNetwork(TunnelNetworkConfig{
		Destination:       local,
		Sender:            discardTunnelSender{},
		HandshakeObserver: observer,
		AcceptQueue:       4 * maxInboundStreamsPerPeer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	return network
}

func peerCapSYN(t *testing.T, peer, server *TunnelNetwork, streamID uint32) Delivery {
	t.Helper()
	packet := Packet{ReceiveStreamID: streamID, Flags: FlagSynchronize | FlagNoACK}
	wire, err := peer.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	return Delivery{From: peer.localHash, To: server.localHash, FromPort: 1234, ToPort: 80, Protocol: ProtocolStreaming, Payload: wire}
}

func testInboundStreamsCappedPerPeer(t *testing.T, observer *countingPrepObserver) {
	var handshakeObserver HandshakeObserver
	if observer != nil {
		handshakeObserver = observer
	}
	server := newPeerCapNetwork(t, handshakeObserver)
	listener, err := server.ListenI2P(t.Context(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	attacker := newPeerCapNetwork(t, nil)
	honest := newPeerCapNetwork(t, nil)

	for id := uint32(1); id <= maxInboundStreamsPerPeer; id++ {
		if err := server.HandleDelivery(t.Context(), peerCapSYN(t, attacker, server, id)); err != nil {
			t.Fatalf("SYN %d within per-peer stream cap = %v", id, err)
		}
		synctest.Wait()
	}
	if got := server.Stats().Connections; got != maxInboundStreamsPerPeer {
		t.Fatalf("inbound streams from one peer = %d, want %d", got, maxInboundStreamsPerPeer)
	}
	prepared := int32(0)
	if observer != nil {
		prepared = observer.calls.Load()
	}

	overCap := peerCapSYN(t, attacker, server, maxInboundStreamsPerPeer+1)
	if err := server.HandleDelivery(t.Context(), overCap); !errors.Is(err, ErrTunnelBackpressure) {
		t.Fatalf("SYN beyond per-peer stream cap = %v, want ErrTunnelBackpressure", err)
	}
	synctest.Wait()
	if got := server.Stats().Connections; got != maxInboundStreamsPerPeer {
		t.Fatalf("inbound streams after over-cap SYN = %d, want %d", got, maxInboundStreamsPerPeer)
	}
	if observer != nil && observer.calls.Load() != prepared {
		t.Fatal("over-cap SYN reached handshake route preparation")
	}

	// A retransmitted SYN for an existing stream is not a new stream.
	if err := server.HandleDelivery(t.Context(), peerCapSYN(t, attacker, server, 1)); err != nil {
		t.Fatalf("retransmitted SYN for an admitted stream = %v", err)
	}
	// The cap is per peer: another destination still opens streams.
	if err := server.HandleDelivery(t.Context(), peerCapSYN(t, honest, server, 1)); err != nil {
		t.Fatalf("SYN from another peer = %v", err)
	}
	synctest.Wait()

	// Closing one of the attacker's streams frees one slot for that peer.
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if accepted.(*tunnelConn).peer != attacker.localHash {
		t.Fatal("first accepted stream is not from the capped peer")
	}
	accepted.(*tunnelConn).abort(false)
	if err := server.HandleDelivery(t.Context(), overCap); err != nil {
		t.Fatalf("SYN after one stream closed = %v", err)
	}
	synctest.Wait()
	next := peerCapSYN(t, attacker, server, maxInboundStreamsPerPeer+2)
	if err := server.HandleDelivery(t.Context(), next); !errors.Is(err, ErrTunnelBackpressure) {
		t.Fatalf("SYN beyond per-peer stream cap after reuse = %v, want ErrTunnelBackpressure", err)
	}
}

func TestInboundStreamsAreCappedPerPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testInboundStreamsCappedPerPeer(t, nil)
	})
}

func TestInboundStreamsAreCappedPerPeerBeforeRoutePreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		testInboundStreamsCappedPerPeer(t, &countingPrepObserver{TunnelSender: discardTunnelSender{}})
	})
}
