package router

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
)

type blockedTransportPeers struct {
	delegate *transportTestPeers
	blocked  foundation.Hash
	calls    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (p *blockedTransportPeers) RouterInfo(peer foundation.Hash) (foundation.NetworkDatabaseRouterInfo, bool) {
	if p.delegate != nil && peer != p.blocked {
		return p.delegate.RouterInfo(peer)
	}
	p.calls.Add(1)
	if p.entered != nil {
		p.once.Do(func() { close(p.entered) })
		<-p.release
	}
	return foundation.NetworkDatabaseRouterInfo{}, false
}

func (p *blockedTransportPeers) DialRouterInfo(peer foundation.Hash, now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	if p.delegate != nil && peer != p.blocked {
		return p.delegate.DialRouterInfo(peer, now)
	}
	info, ok := p.RouterInfo(peer)
	if !ok {
		return foundation.NetworkDatabaseRouterInfo{}, ErrSessionUnavailable
	}
	return info, nil
}

func (p *blockedTransportPeers) AdmitRouterInfo(info foundation.NetworkDatabaseRouterInfo, now uint64) error {
	if p.delegate != nil {
		return p.delegate.AdmitRouterInfo(info, now)
	}
	return nil
}

func (p *blockedTransportPeers) PeerAtEndpoint(endpoint netip.AddrPort) (foundation.Hash, bool) {
	if p.delegate != nil {
		return p.delegate.PeerAtEndpoint(endpoint)
	}
	return foundation.Hash{}, false
}

func TestNativeSendRejectsMissingSessionWithoutSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		conn := newSSU2SimConn(t, net_, "alice")
		local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
		peers := new(blockedTransportPeers)
		ntcp := newConfiguredNTCP2Manager(t, peers)
		ntcp.started = true
		ntcp.ctx = t.Context()
		ntcp.bindings = TransportBindings{Clock: WallClock{}}

		ssu, err := NewSSU2Manager(SSU2ManagerConfig{
			NetworkID:     2,
			Peers:         peers,
			StaticPrivate: static,
			IntroKey:      intro,
		})
		if err != nil {
			t.Fatal(err)
		}
		startSSU2SimManager(t, t.Context(), ssu, conn, local, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, ssu)
		})

		for name, sender := range map[string]interface {
			Send(context.Context, foundation.Hash, foundation.I2NPMessage) error
		}{"NTCP2": ntcp, "SSU2": ssu, "directory": NewEstablishedSender(ntcp, ssu)} {
			if err := sender.Send(t.Context(), foundation.Hash{9}, foundation.I2NPMessage{}); !errors.Is(err, ErrSessionUnavailable) {
				t.Fatalf("%s missing session send = %v, want %v", name, err, ErrSessionUnavailable)
			}
		}
		if calls := peers.calls.Load(); calls != 0 {
			t.Fatalf("established-only sends initiated %d peer resolutions", calls)
		}
	})
}

func TestSSU2EstablishedSendContinuesWhilePeerSetupBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		blockedPeer := foundation.Hash{2}
		peers := &blockedTransportPeers{
			delegate: aliceDB,
			blocked:  blockedPeer,
			entered:  make(chan struct{}),
			release:  make(chan struct{}),
		}
		aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{
			NetworkID:        2,
			Peers:            peers,
			StaticPrivate:    aliceStatic,
			IntroKey:         aliceIntro,
			HandshakeTimeout: time.Second,
			IdleTimeout:      time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)
		received := make(chan foundation.I2NPMessage, 1)
		startSSU2SimManager(t, t.Context(), aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, func(msg foundation.I2NPMessage, _ uint64, _ bool) error {
			received <- msg
			return nil
		})
		t.Cleanup(func() {
			select {
			case <-peers.release:
			default:
				close(peers.release)
			}
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(t.Context(), bob.Hash()); err != nil {
			t.Fatal(err)
		}
		sender, err := aliceManager.PreparedSession(bob.Hash())
		if err != nil {
			t.Fatal(err)
		}

		setupDone := make(chan error, 1)
		go func() {
			setupDone <- aliceManager.EnsureSession(t.Context(), blockedPeer)
		}()
		<-peers.entered

		if err := sender.Send(t.Context(), managerHotPathMessage()); err != nil {
			t.Fatalf("established delivery during blocked peer setup: %v", err)
		}
		if got := <-received; got.Header.ID != managerHotPathMessage().Header.ID {
			t.Fatalf("delivered message ID = %d, want %d", got.Header.ID, managerHotPathMessage().Header.ID)
		}

		close(peers.release)
		if err := <-setupDone; !errors.Is(err, ErrSSU2Peer) {
			t.Fatalf("unavailable setup result = %v, want %v", err, ErrSSU2Peer)
		}
	})
}

func TestPreparedSSU2SenderCannotUseRetiredSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), now); err != nil {
			t.Fatal(err)
		}
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, time.Minute)
		startSSU2SimManager(t, t.Context(), aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(t.Context(), bob.Hash()); err != nil {
			t.Fatal(err)
		}
		sender, err := aliceManager.PreparedSession(bob.Hash())
		if err != nil {
			t.Fatal(err)
		}
		if !aliceManager.DropSession(bob.Hash()) {
			t.Fatal("DropSession returned false for active session")
		}
		if err = sender.Send(t.Context(), managerHotPathMessage()); !errors.Is(err, ErrSessionUnavailable) {
			t.Fatalf("retired handle send = %v, want %v", err, ErrSessionUnavailable)
		}
		if _, err = aliceManager.PreparedSession(bob.Hash()); !errors.Is(err, ErrSessionUnavailable) {
			t.Fatalf("retired session reacquired: %v", err)
		}
	})
}
