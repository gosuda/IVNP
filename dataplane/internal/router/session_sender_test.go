package router

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	dataplanentcp2 "gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	"gosuda.org/ivnp/foundation"
)

type blockedTransportPeers struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockedTransportPeers) RouterInfo(foundation.Hash) (foundation.NetworkDatabaseRouterInfo, bool) {
	p.calls.Add(1)
	if p.entered != nil {
		p.once.Do(func() { close(p.entered) })
		<-p.release
	}
	return foundation.NetworkDatabaseRouterInfo{}, false
}

func (p *blockedTransportPeers) DialRouterInfo(peer foundation.Hash, _ uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	info, ok := p.RouterInfo(peer)
	if !ok {
		return foundation.NetworkDatabaseRouterInfo{}, ErrSessionUnavailable
	}
	return info, nil
}

func (*blockedTransportPeers) AdmitRouterInfo(foundation.NetworkDatabaseRouterInfo, uint64) error {
	return nil
}
func (*blockedTransportPeers) PeerAtEndpoint(netip.AddrPort) (foundation.Hash, bool) {
	return foundation.Hash{}, false
}

func TestNativeSendRejectsMissingSessionWithoutSetup(t *testing.T) {
	peers := new(blockedTransportPeers)
	ntcp := &NTCP2Manager{networkID: 2,
		started: true, ctx: t.Context(), peers: peers,
		sessions: make(map[foundation.Hash]*dataplanentcp2.Session),
		dialing:  make(map[foundation.Hash]*ntcp2DialAttempt),
		pending:  make(chan struct{}, 1), bindings: TransportBindings{Clock: WallClock{}},
	}
	ssu := &SSU2Manager{networkID: 2,
		started: true, ctx: t.Context(), peers: peers,
		bindings: TransportBindings{Clock: WallClock{}},
	}
	for name, sender := range map[string]interface {
		Send(context.Context, foundation.Hash, foundation.I2NPMessage) error
	}{"NTCP2": ntcp, "SSU2": ssu, "directory": NewEstablishedSender(ntcp, ssu)} {
		t.Run(name, func(t *testing.T) {
			if err := sender.Send(t.Context(), foundation.Hash{9}, foundation.I2NPMessage{}); !errors.Is(err, ErrSessionUnavailable) {
				t.Fatalf("missing session send = %v, want %v", err, ErrSessionUnavailable)
			}
		})
	}
	if calls := peers.calls.Load(); calls != 0 {
		t.Fatalf("established-only sends initiated %d peer resolutions", calls)
	}
}

func TestSSU2EstablishedSendContinuesWhilePeerSetupBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		sender, err := manager.PreparedSession(session.peer)
		if err != nil {
			t.Fatal(err)
		}
		peers := &blockedTransportPeers{entered: make(chan struct{}), release: make(chan struct{})}
		manager.peers = peers
		setupDone := make(chan error, 1)
		go func() {
			_, err := manager.establish(t.Context(), foundation.Hash{2})
			setupDone <- err
		}()
		<-peers.entered
		ctx, cancel := context.WithCancel(t.Context())
		delivered := make(chan error, 1)
		finished := false
		defer func() {
			close(peers.release)
			cancel()
			if !finished {
				<-delivered
			}
			if err := <-setupDone; !errors.Is(err, ErrSSU2Peer) {
				t.Errorf("unavailable setup result = %v, want %v", err, ErrSSU2Peer)
			}
		}()
		go func() { delivered <- sender.Send(ctx, managerHotPathMessage()) }()
		synctest.Wait()
		select {
		case slot := <-manager.egressQueue:
			slot.done <- nil
		default:
			t.Fatal("blocked peer setup prevented established packet submission")
		}
		synctest.Wait()
		select {
		case err := <-delivered:
			finished = true
			if err != nil {
				t.Fatalf("established delivery during setup: %v", err)
			}
		default:
			t.Fatal("established delivery waited for unrelated peer setup")
		}
	})
}

func TestPreparedSSU2SenderCannotUseRetiredSession(t *testing.T) {
	manager, session := newSSU2SendTestHarness(t)
	sender, err := manager.PreparedSession(session.peer)
	if err != nil {
		t.Fatal(err)
	}
	manager.removeSession(session)
	if err = sender.Send(t.Context(), managerHotPathMessage()); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("retired handle send = %v, want %v", err, ErrSessionUnavailable)
	}
	if _, err = manager.PreparedSession(session.peer); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("retired session reacquired: %v", err)
	}
}
