package streamingtunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/foundation"
)

// stallingPrepObserver models route preparation for peers whose LeaseSet
// lookup never completes. Preparation for a stalled peer blocks until its
// context ends (or until release closes when ignoreCancel is set); every other
// peer prepares immediately.
type stallingPrepObserver struct {
	TunnelSender
	ignoreCancel bool
	release      chan struct{}

	mu sync.Mutex
	// +checklocks:mu
	stalled map[foundation.Hash]bool
	// +checklocks:mu
	calls map[foundation.Hash]int
	// +checklocks:mu
	canceled []foundation.Hash
}

func newStallingPrepObserver(sender TunnelSender) *stallingPrepObserver {
	return &stallingPrepObserver{
		TunnelSender: sender,
		stalled:      make(map[foundation.Hash]bool),
		release:      make(chan struct{}),
		calls:        make(map[foundation.Hash]int),
	}
}

func (o *stallingPrepObserver) PrepareHandshake(ctx context.Context, remote foundation.Hash) (HandshakeFeedback, error) {
	o.mu.Lock()
	o.calls[remote]++
	stalled := o.stalled[remote]
	o.mu.Unlock()
	if !stalled {
		return &handshakeFeedbackRecorder{TunnelSender: o.TunnelSender}, nil
	}
	if o.ignoreCancel {
		<-o.release
		return nil, context.Canceled
	}
	<-ctx.Done()
	o.mu.Lock()
	o.canceled = append(o.canceled, remote)
	o.mu.Unlock()
	return nil, ctx.Err()
}

func (o *stallingPrepObserver) stall(remote foundation.Hash) {
	o.mu.Lock()
	o.stalled[remote] = true
	o.mu.Unlock()
}

func (o *stallingPrepObserver) snapshot() (map[foundation.Hash]int, []foundation.Hash) {
	o.mu.Lock()
	defer o.mu.Unlock()
	calls := make(map[foundation.Hash]int, len(o.calls))
	for remote, count := range o.calls {
		calls[remote] = count
	}
	return calls, append([]foundation.Hash(nil), o.canceled...)
}

func newSYNAdmissionServer(t *testing.T, observer *stallingPrepObserver) (*TunnelNetwork, *tunnelListener) {
	t.Helper()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: discardTunnelSender{}, HandshakeObserver: observer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	listener, err := server.ListenI2P(t.Context(), ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return server, listener.(*tunnelListener)
}

func newSYNPeer(t *testing.T) *TunnelNetwork {
	t.Helper()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: discardTunnelSender{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}

func synFrom(t *testing.T, peer, server *TunnelNetwork, streamID uint32) Delivery {
	t.Helper()
	packet := Packet{ReceiveStreamID: streamID, Flags: FlagSynchronize | FlagNoACK}
	wire, err := peer.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	if err != nil {
		t.Fatal(err)
	}
	return Delivery{From: peer.localHash, To: server.localHash, FromPort: 1234, ToPort: 80, Protocol: ProtocolStreaming, Payload: wire}
}

func acceptFrom(t *testing.T, listener *tunnelListener, want foundation.Hash) {
	t.Helper()
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.(*tunnelConn).abort(false)
	if got := connection.(*tunnelConn).peer; got != want {
		t.Fatalf("accepted stream from %x, want %x", got[:4], want[:4])
	}
}

func TestInboundSYNPreparationIsBoundedPerPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		observer := newStallingPrepObserver(discardTunnelSender{})
		server, listener := newSYNAdmissionServer(t, observer)
		attacker := newSYNPeer(t)
		observer.stall(attacker.localHash)
		for id := uint32(1); id <= maxInboundSYNPrep; id++ {
			err := server.HandleDelivery(t.Context(), synFrom(t, attacker, server, id))
			if id <= maxInboundSYNPrepPerPeer && err != nil {
				t.Fatalf("SYN %d within per-peer budget = %v", id, err)
			}
			if id > maxInboundSYNPrepPerPeer && !errors.Is(err, ErrTunnelBackpressure) {
				t.Fatalf("SYN %d beyond per-peer budget = %v, want ErrTunnelBackpressure", id, err)
			}
		}
		synctest.Wait()
		if calls, _ := observer.snapshot(); calls[attacker.localHash] != maxInboundSYNPrepPerPeer {
			t.Fatalf("stalled preparations for one peer = %d, want %d", calls[attacker.localHash], maxInboundSYNPrepPerPeer)
		}
		honest := newSYNPeer(t)
		if err := server.HandleDelivery(t.Context(), synFrom(t, honest, server, 1)); err != nil {
			t.Fatalf("honest SYN behind one stalled peer = %v", err)
		}
		acceptFrom(t, listener, honest.localHash)
	})
}

func TestInboundSYNPreparationEvictsOldestStalledPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		observer := newStallingPrepObserver(discardTunnelSender{})
		server, listener := newSYNAdmissionServer(t, observer)
		attackers := make([]*TunnelNetwork, maxInboundSYNPrep)
		for index := range attackers {
			attackers[index] = newSYNPeer(t)
			observer.stall(attackers[index].localHash)
		}
		for _, attacker := range attackers {
			if err := server.HandleDelivery(t.Context(), synFrom(t, attacker, server, 1)); err != nil {
				t.Fatalf("stalled SYN admission = %v", err)
			}
			synctest.Wait()
		}
		honest := newSYNPeer(t)
		if err := server.HandleDelivery(t.Context(), synFrom(t, honest, server, 1)); err != nil {
			t.Fatalf("honest SYN behind %d stalled peers = %v", maxInboundSYNPrep, err)
		}
		acceptFrom(t, listener, honest.localHash)
		synctest.Wait()
		if _, canceled := observer.snapshot(); len(canceled) != 1 || canceled[0] != attackers[0].localHash {
			t.Fatalf("canceled preparations = %d, want only the oldest stalled peer", len(canceled))
		}
	})
}

func TestInboundSYNPreparationBoundsDrainingWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		observer := newStallingPrepObserver(discardTunnelSender{})
		observer.ignoreCancel = true
		server, _ := newSYNAdmissionServer(t, observer)
		defer close(observer.release)
		for admitted := 0; admitted < maxInboundSYNPrepRunning; admitted++ {
			attacker := newSYNPeer(t)
			observer.stall(attacker.localHash)
			if err := server.HandleDelivery(t.Context(), synFrom(t, attacker, server, 1)); err != nil {
				t.Fatalf("SYN %d within running budget = %v", admitted, err)
			}
			synctest.Wait()
		}
		extra := newSYNPeer(t)
		observer.stall(extra.localHash)
		if err := server.HandleDelivery(t.Context(), synFrom(t, extra, server, 1)); !errors.Is(err, ErrTunnelBackpressure) {
			t.Fatalf("SYN beyond running budget = %v, want ErrTunnelBackpressure", err)
		}
	})
}
