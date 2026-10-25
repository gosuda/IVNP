package router

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

var errTestTransientPublicationFailure = errors.New("transient publication failure")

func newSSU2ConfiguredManager(t *testing.T, peers TransportPeerSource) (*SSU2Manager, *transportTestLocal) {
	t.Helper()
	local, static, intro := newSSU2TestLocal(t, "192.0.2.1:23456")
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		NetworkID:        2,
		Peers:            peers,
		StaticPrivate:    static,
		IntroKey:         intro,
		HandshakeTimeout: time.Second,
		IdleTimeout:      time.Minute,
		TokenLifetime:    time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, local
}

func TestSSU2PeerTestOutcomeTable(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.7:42000")
	observed := netip.MustParseAddrPort("198.51.100.7:43000")
	manager, _ := newSSU2ConfiguredManager(t, nil)
	resultFor := func(withFive bool, received netip.AddrPort) PeerTestResult {
		t.Helper()
		state := &ssu2PeerTestState{
			nonce:    1,
			message4: &dataplanessu2.PeerTestBlock{Message: 4, Address: endpoint},
			message7: &dataplanessu2.PeerTestBlock{Message: 7, Address: received},
		}
		if withFive {
			state.message5 = &dataplanessu2.PeerTestBlock{Message: 5, Address: endpoint}
		}
		manager.mu.Lock()
		result, done := manager.peerTestResultLocked(state, false)
		manager.mu.Unlock()
		if !done {
			t.Fatal("complete peer-test evidence did not produce an outcome")
		}
		return result
	}
	if result := resultFor(false, endpoint); result.Outcome != PeerTestFirewalled {
		t.Fatalf("4/7 exact without 5 outcome = %v, want FIREWALLED", result.Outcome)
	}
	if result := resultFor(false, observed); result.Outcome != PeerTestFirewalled {
		t.Fatalf("first same-IP port mismatch outcome = %v, want confirmation-pending FIREWALLED", result.Outcome)
	}
	if result := resultFor(false, observed); result.Outcome != PeerTestSymmetricNAT {
		t.Fatalf("confirmed same-IP port mismatch outcome = %v, want SYMNAT", result.Outcome)
	}
	if result := resultFor(true, netip.MustParseAddrPort("203.0.113.10:44000")); result.Outcome != PeerTestOK || result.Diagnostic == "" {
		t.Fatalf("4/5/7 mismatch result = %#v, want OK with diagnostic", result)
	}
}

func TestSSU2RelayTagPublicationAndExpiry(t *testing.T) {
	manager, local := newSSU2ConfiguredManager(t, nil)
	now := time.Now()
	var peer foundation.Hash
	peer[0] = 9
	manager.bindings = TransportBindings{LocalInfo: local, Clock: WallClock{}}
	manager.advertisedRelays[peer] = ssu2RelayTagLease{peer: peer, tag: 77, expires: now.Add(time.Minute)}
	if _, err := manager.publishRelaySnapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidates := selectSSU2Introducers(local.Snapshot(), uint64(now.Unix()))
	if len(candidates) != 1 || candidates[0].peer != peer || candidates[0].relayTag != 77 {
		t.Fatalf("published introducers = %#v, want relay tag 77 for peer", candidates)
	}
	manager.advertisedRelays[peer] = ssu2RelayTagLease{peer: peer, tag: 77, expires: now.Add(-time.Second)}
	manager.expireExtensions(now)
	if _, err := manager.publishRelaySnapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if candidates = selectSSU2Introducers(local.Snapshot(), uint64(now.Unix())); len(candidates) != 0 {
		t.Fatalf("expired relay tag remained published: %#v", candidates)
	}
}

func TestSSU2NewTokenCacheExpiryAndPathTimeout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	peer := foundation.Hash{1}
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 34567}
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.bindings = TransportBindings{Clock: transportTestClock{now: now}}
	manager.newTokens[newTokenCacheKey(peer, remote, 2)] = ssu2NewTokenLease{
		peer: peer, endpoint: remote.String(), destination: 2, token: 3, expires: now.Add(time.Second),
	}
	manager.mu.Lock()
	if token := manager.cachedNewTokenLocked(peer, remote, 2); token != 3 {
		manager.mu.Unlock()
		t.Fatalf("cached 1-RTT token = %d, want 3", token)
	}
	if token := manager.cachedNewTokenLocked(peer, remote, 3); token != 0 {
		manager.mu.Unlock()
		t.Fatalf("destination-isolated 1-RTT token = %d, want 0", token)
	}
	manager.newTokens[newTokenCacheKey(peer, remote, 2)] = ssu2NewTokenLease{destination: 2, expires: now.Add(-time.Second)}
	if token := manager.cachedNewTokenLocked(peer, remote, 2); token != 0 {
		manager.mu.Unlock()
		t.Fatalf("expired cached token = %d, want fallback token request", token)
	}
	manager.mu.Unlock()
}

func TestSSU2ManagerLiveEgressShutdownAndIOStats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		conn := newSSU2SimConn(t, net_, "alice")
		receiver := newSSU2SimConn(t, net_, "bob")
		local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
		manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: static, IntroKey: intro})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(func() {
			cancel()
			_ = manager.Close()
			_ = manager.Wait()
		})
		if err = manager.Start(ctx, TransportBindings{
			SSU2: conn, LocalInfo: local, Clock: WallClock{},
			HandleI2NPContext: func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error { return nil },
		}); err != nil {
			t.Fatal(err)
		}
		payload := []byte{1, 2, 3, 4}
		if err = manager.writeTo(payload, receiver.LocalAddr()); err != nil {
			t.Fatalf("live egress write: %v", err)
		}
		buffer := make([]byte, len(payload))
		if n, _, readErr := receiver.ReadFromUDP(buffer); readErr != nil || n != len(payload) {
			t.Fatalf("live egress receive = n %d err %v, want %d bytes", n, readErr, len(payload))
		}
		stats := manager.IOStats()
		if stats.DatagramsSent != 1 || stats.BytesSent != uint64(len(payload)) {
			t.Fatalf("egress IOStats = %#v, want one %d-byte datagram", stats, len(payload))
		}
		if err = manager.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close manager: %v", err)
		}
		if err = manager.writeTo(payload, receiver.LocalAddr()); !errors.Is(err, ErrSSU2Session) {
			t.Fatalf("egress after deterministic close = %v, want ErrSSU2Session", err)
		}
	})
}

func TestSSU2ManagerLivePeerTestOrchestration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		charlieConn := newSSU2SimConn(t, net_, "charlie")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		charlie, charlieStatic, charlieIntro := newSSU2TestLocal(t, charlieConn.LocalAddr().String())
		aliceDB, bobDB, charlieDB := newTransportTestPeers(), newTransportTestPeers(), newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admission := range []struct {
			database *transportTestPeers
			info     foundation.NetworkDatabaseRouterInfo
		}{
			{aliceDB, bob.Snapshot()}, {aliceDB, charlie.Snapshot()},
			{bobDB, charlie.Snapshot()}, {charlieDB, alice.Snapshot()},
		} {
			if err := admission.database.AdmitRouterInfo(admission.info, now); err != nil {
				t.Fatal(err)
			}
		}
		results := make(chan PeerTestResult, 1)
		aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro,
			OnPeerTestResult: func(result PeerTestResult) { results <- result }})
		if err != nil {
			t.Fatal(err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		charlieManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: charlieDB, StaticPrivate: charlieStatic, IntroKey: charlieIntro})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(func() {
			cancel()
			for _, manager := range []*SSU2Manager{aliceManager, bobManager, charlieManager} {
				closeSSU2LiveManager(t, manager)
			}
		})
		for _, start := range []struct {
			manager *SSU2Manager
			conn    *simnet.UDPConn
			local   *transportTestLocal
		}{
			{aliceManager, aliceConn, alice}, {bobManager, bobConn, bob}, {charlieManager, charlieConn, charlie},
		} {
			startSSU2SimManager(t, ctx, start.manager, start.conn, start.local, nil)
		}
		message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 1, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())}, Payload: make([]byte, 12)}
		if err := bobManager.EnsureSession(ctx, charlie.Hash()); err != nil {
			t.Fatalf("authenticate Bob/Charlie session: %v", err)
		}
		if err := bobManager.Send(ctx, charlie.Hash(), message); err != nil {
			t.Fatalf("establish Bob/Charlie session: %v", err)
		}
		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatalf("authenticate Alice/Bob session: %v", err)
		}
		if err := aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatalf("establish Alice/Bob session: %v", err)
		}
		result := <-results
		if result.Outcome != PeerTestOK {
			t.Fatalf("live PeerTest result = %#v, want OK", result)
		}
	})
}

func TestSSU2DispatchShutdownCancelsContextAwareCallback(t *testing.T) {
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
		ctx, cancel := context.WithCancel(t.Context())
		entered := make(chan struct{})
		callbackErr := make(chan error, 1)
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		if err := bobManager.Start(ctx, TransportBindings{
			SSU2: bobConn, LocalInfo: bob, Clock: WallClock{},
			HandleI2NPContext: func(cbCtx context.Context, _ foundation.Hash, _ foundation.I2NPMessage, _ uint64, _ bool) error {
				close(entered)
				<-cbCtx.Done()
				err := cbCtx.Err()
				callbackErr <- err
				return err
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		if err := aliceManager.Send(ctx, bob.Hash(), ssu2LiveMessage(1)); err != nil {
			t.Fatal(err)
		}
		<-entered
		if err := bobManager.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if err := <-callbackErr; !errors.Is(err, context.Canceled) {
			t.Fatalf("dispatch error = %v, want context cancellation", err)
		}
		if err := bobManager.Wait(); err != nil {
			t.Fatalf("Wait after callback cancellation: %v", err)
		}
	})
}

func TestSSU2LiveRelayTagLeasePublishesRenewsAndWithdraws(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admission := range []struct {
			database *transportTestPeers
			info     foundation.NetworkDatabaseRouterInfo
		}{
			{aliceDB, bob.Snapshot()},
			{bobDB, alice.Snapshot()},
		} {
			if err := admission.database.AdmitRouterInfo(admission.info, now); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, 3*time.Second, 10*time.Second)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, 3*time.Second, 10*time.Second)
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.RequestRelayTag(ctx, bob.Hash()); err != nil {
			t.Fatalf("request live relay tag: %v", err)
		}
		net_.Advance(100 * time.Millisecond)

		snapshot := alice.Snapshot()
		candidates := selectSSU2Introducers(snapshot, uint64(time.Now().Unix()))
		if len(candidates) != 1 || candidates[0].peer != bob.Hash() || candidates[0].relayTag == 0 {
			t.Fatalf("RelayTag grant publication candidates = %#v, want 1 introducer for Bob", candidates)
		}
		initialPublished := snapshot.Published
		if valid, err := snapshot.Verify(); err != nil || !valid {
			t.Fatalf("RelayTag publication is not a signed RouterInfo: valid=%v err=%v", valid, err)
		}

		net_.Advance(3 * time.Second)
		snapshot = alice.Snapshot()
		candidates = selectSSU2Introducers(snapshot, uint64(time.Now().Unix()))
		if len(candidates) < 1 || snapshot.Published <= initialPublished {
			t.Fatalf("RelayTag lease was not renewed: candidates=%#v published=%d initial=%d", candidates, snapshot.Published, initialPublished)
		}

		closeSSU2LiveManager(t, bobManager)
		net_.Advance(4 * time.Second)
		if hasSSU2IntroducerOptions(alice.Snapshot()) {
			t.Fatal("expired RelayTag remained advertised after Bob closed")
		}
		if valid, err := alice.Snapshot().Verify(); err != nil || !valid {
			t.Fatalf("withdrawn RelayTag snapshot is not signed: valid=%v err=%v", valid, err)
		}
	})
}

func TestSSU2LiveNewTokenCacheSkipsRetryAndExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobRawConn := newSSU2SimConn(t, net_, "bob")
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobRawConn.LocalAddr().String())
		bobConn := &ssu2TokenCountingConn{UDPSocket: bobRawConn, intro: append([]byte(nil), bobIntro...)}
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admission := range []struct {
			database *transportTestPeers
			info     foundation.NetworkDatabaseRouterInfo
		}{
			{aliceDB, bob.Snapshot()},
			{bobDB, alice.Snapshot()},
		} {
			if err := admission.database.AdmitRouterInfo(admission.info, now); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, 10*time.Second, 2*time.Second)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, 10*time.Second, 2*time.Second)
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		send := func(id uint32) {
			t.Helper()
			if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
				t.Fatalf("authenticate token-cache session: %v", err)
			}
			if err := aliceManager.Send(ctx, bob.Hash(), ssu2LiveMessage(id)); err != nil {
				t.Fatalf("live token-cache send %d: %v", id, err)
			}
		}
		send(1)
		net_.Advance(50 * time.Millisecond)

		firstRequests, firstRetries := bobConn.Counts()
		if firstRequests == 0 || firstRetries == 0 {
			t.Fatalf("first establishment did not traverse TokenRequest/Retry: requests=%d retries=%d", firstRequests, firstRetries)
		}

		net_.Advance(3500 * time.Millisecond)
		if aliceManager.HasSession(bob.Hash()) || bobManager.HasSession(alice.Hash()) {
			t.Fatal("first session was not evicted after idle timeout")
		}

		send(2)
		net_.Advance(50 * time.Millisecond)
		if !aliceManager.HasSession(bob.Hash()) {
			t.Fatal("second session was not established with cached token")
		}
		if requests, retries := bobConn.Counts(); requests != firstRequests || retries != firstRetries {
			t.Fatalf("cached token sent TokenRequest/Retry: got requests=%d retries=%d, want %d/%d", requests, retries, firstRequests, firstRetries)
		}

		net_.Advance(11 * time.Second)
		if aliceManager.HasSession(bob.Hash()) || bobManager.HasSession(alice.Hash()) {
			t.Fatal("second session was not evicted after idle timeout")
		}

		send(3)
		net_.Advance(50 * time.Millisecond)
		if requests, retries := bobConn.Counts(); requests <= firstRequests || retries <= firstRetries {
			t.Fatalf("expired token did not fall back to TokenRequest/Retry: got requests=%d retries=%d, initial=%d/%d", requests, retries, firstRequests, firstRetries)
		}
	})
}

func TestSSU2LivePathMigration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		proxy := newSSU2MigrationProxy(t, net_, aliceConn.LocalAddr().(*net.UDPAddr), bobConn.LocalAddr().(*net.UDPAddr))
		t.Cleanup(proxy.Close)
		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, proxy.primary.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admission := range []struct {
			database *transportTestPeers
			info     foundation.NetworkDatabaseRouterInfo
		}{
			{aliceDB, bob.Snapshot()},
			{bobDB, alice.Snapshot()},
		} {
			if err := admission.database.AdmitRouterInfo(admission.info, now); err != nil {
				t.Fatal(err)
			}
		}
		received := make(chan foundation.I2NPMessage, 1)
		bobReceived := make(chan foundation.I2NPMessage, 2)
		ctx, cancel := context.WithCancel(t.Context())
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Second, 10*time.Second)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Second, 10*time.Second)
		proxy.Start()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, func(message foundation.I2NPMessage, _ uint64, _ bool) error {
			received <- message
			return nil
		})
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, func(message foundation.I2NPMessage, _ uint64, _ bool) error {
			bobReceived <- message
			return nil
		})
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		send := func(manager *SSU2Manager, peer foundation.Hash, id uint32, action string) {
			t.Helper()
			if err := manager.EnsureSession(ctx, peer); err != nil {
				t.Fatalf("authenticate %s: %v", action, err)
			}
			if err := manager.Send(ctx, peer, ssu2LiveMessage(id)); err != nil {
				t.Fatalf("%s: %v", action, err)
			}
		}
		send(aliceManager, bob.Hash(), 1, "establish initial path")
		if message := <-bobReceived; message.Header.ID != 1 {
			t.Fatalf("initial path delivered message %d, want 1", message.Header.ID)
		}

		proxy.Migrate()
		send(aliceManager, bob.Hash(), 2, "send authenticated traffic over candidate path")
		net_.Advance(50 * time.Millisecond)

		send(bobManager, alice.Hash(), 3, "send over migrated endpoint")
		if message := <-received; message.Header.ID != 3 {
			t.Fatalf("migrated endpoint delivered message %d, want 3", message.Header.ID)
		}
		if proxy.secondaryFromBob.Load() == 0 {
			t.Fatal("Bob did not send traffic to migrated secondary endpoint")
		}
	})
}

func newSSU2LiveManager(t *testing.T, database *transportTestPeers, static, intro []byte, tokenLifetime, idleTimeout time.Duration) *SSU2Manager {
	t.Helper()
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: database, StaticPrivate: static, IntroKey: intro, TokenLifetime: tokenLifetime,
		HandshakeTimeout: time.Second, IdleTimeout: idleTimeout})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func closeSSU2LiveManager(t *testing.T, manager *SSU2Manager) {
	t.Helper()
	if err := manager.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close live SSU2 manager: %v", err)
	}
	if err := manager.Wait(); err != nil {
		t.Errorf("wait live SSU2 manager: %v", err)
	}
}

func ssu2LiveMessage(id uint32) foundation.I2NPMessage {
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: id, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: []byte("live SSU2 extension test"),
	}
}

func hasSSU2IntroducerOptions(info foundation.NetworkDatabaseRouterInfo) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		options := address.Options.Iterator()
		for {
			key, _, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			if string(key) == "itag0" {
				return true
			}
		}
	}
}

type ssu2TokenCountingConn struct {
	UDPSocket
	intro    []byte
	requests atomic.Int64
	retries  atomic.Int64
}

func (c *ssu2TokenCountingConn) ReadMsgUDPAddrPort(b, oob []byte) (int, int, int, netip.AddrPort, error) {
	n, oobn, flags, addr, err := c.UDPSocket.ReadMsgUDPAddrPort(b, oob)
	if err == nil && n > 0 {
		wire := append([]byte(nil), b[:n]...)
		if header, _, parseErr := dataplanessu2.ParseOutOfSession(wire, c.intro, 2); parseErr == nil && header.Type == dataplanessu2.TokenRequest {
			c.requests.Add(1)
		}
	}
	return n, oobn, flags, addr, err
}

func (c *ssu2TokenCountingConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.UDPSocket.ReadFromUDPAddrPort(b)
	if err == nil && n > 0 {
		wire := append([]byte(nil), b[:n]...)
		if header, _, parseErr := dataplanessu2.ParseOutOfSession(wire, c.intro, 2); parseErr == nil && header.Type == dataplanessu2.TokenRequest {
			c.requests.Add(1)
		}
	}
	return n, addr, err
}

func (c *ssu2TokenCountingConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if len(b) > 0 {
		wire := append([]byte(nil), b...)
		if header, _, parseErr := dataplanessu2.ParseOutOfSession(wire, c.intro, 2); parseErr == nil && header.Type == dataplanessu2.Retry {
			c.retries.Add(1)
		}
	}
	return c.UDPSocket.WriteToUDPAddrPort(b, addr)
}

func (c *ssu2TokenCountingConn) Counts() (requests, retries int) {
	return int(c.requests.Load()), int(c.retries.Load())
}

type ssu2MigrationProxy struct {
	primary, secondary *simnet.UDPConn
	alice, bob         *net.UDPAddr
	wg                 sync.WaitGroup
	migrated           atomic.Bool
	secondaryFromBob   atomic.Int64
}

func newSSU2MigrationProxy(t *testing.T, net_ *simnet.Network, alice, bob *net.UDPAddr) *ssu2MigrationProxy {
	t.Helper()
	return &ssu2MigrationProxy{
		primary:   newSSU2SimConn(t, net_, "proxy-primary"),
		secondary: newSSU2SimConn(t, net_, "proxy-secondary"),
		alice:     cloneUDPAddress(alice).(*net.UDPAddr),
		bob:       cloneUDPAddress(bob).(*net.UDPAddr),
	}
}

func (p *ssu2MigrationProxy) Start() {
	for _, conn := range []*simnet.UDPConn{p.primary, p.secondary} {
		p.wg.Add(1)
		go p.forward(conn)
	}
}

func (p *ssu2MigrationProxy) forward(conn *simnet.UDPConn) {
	defer p.wg.Done()
	packet := make([]byte, dataplanessu2.MaxIPv4PacketLen)
	for {
		n, remote, err := conn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		wire := append([]byte(nil), packet[:n]...)
		switch {
		case conn == p.primary && sameUDPAddress(remote, p.alice):
			outbound := p.primary
			if p.migrated.Load() {
				outbound = p.secondary
			}
			_, _ = outbound.WriteToUDP(wire, p.bob)
		case sameUDPAddress(remote, p.bob):
			if conn == p.secondary {
				p.secondaryFromBob.Add(1)
			}
			_, _ = p.primary.WriteToUDP(wire, p.alice)
		}
	}
}

func (p *ssu2MigrationProxy) Migrate() {
	p.migrated.Store(true)
}

func (p *ssu2MigrationProxy) Close() {
	_ = p.primary.Close()
	_ = p.secondary.Close()
	p.wg.Wait()
}

type flakyIntroducerLocal struct {
	*transportTestLocal
	mu        sync.Mutex
	failures  int
	calls     int
	firstCall chan struct{}
}

func (f *flakyIntroducerLocal) UpdateSSU2Introducers(ctx context.Context, introducers []SSU2Introducer) error {
	f.mu.Lock()
	f.calls++
	call := f.calls
	if call == 1 && f.firstCall != nil {
		close(f.firstCall)
	}
	if f.failures > 0 {
		f.failures--
		f.mu.Unlock()
		return errTestTransientPublicationFailure
	}
	f.mu.Unlock()
	return f.transportTestLocal.UpdateSSU2Introducers(ctx, introducers)
}

func (f *flakyIntroducerLocal) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestSSU2PeerTestOutOfSessionRolesRequireApprovedExactEndpoints(t *testing.T) {
	now := time.Now()
	alice, _, _ := newSSU2TestLocal(t, "127.0.0.1:31001")
	charlie, _, _ := newSSU2TestLocal(t, "127.0.0.1:31002")
	database := newTransportTestPeers()
	if err := database.AdmitRouterInfo(charlie.Snapshot(), uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	state := &ssu2PeerTestState{
		nonce: 41, alice: alice.Hash(), bob: foundation.Hash{9}, expires: now.Add(time.Minute),
	}
	callbacks := 0
	manager, _ := newSSU2ConfiguredManager(t, database)
	manager.bindings = TransportBindings{LocalInfo: alice, Clock: transportTestClock{now: now}}
	manager.peerTests[state.nonce] = state
	manager.onPeerTest = func(dataplanessu2.PeerTestBlock, net.Addr) { callbacks++ }
	phase5 := dataplanessu2.PeerTestBlock{
		Message: 5, Nonce: state.nonce, Timestamp: uint32(now.Unix()),
		Address: netip.MustParseAddrPort("127.0.0.1:31001"),
	}
	phase5Payload, err := dataplanessu2.MarshalPeerTestBlock(nil, phase5)
	if err != nil {
		t.Fatal(err)
	}
	destinationID, sourceID := dataplanessu2.PeerTestConnectionIDs(state.nonce)
	phase5Header := dataplanessu2.LongHeader{DestinationID: destinationID, SourceID: sourceID}
	manager.handlePeerTest(phase5Header, phase5Payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31003")))
	if state.message5 != nil || callbacks != 0 {
		t.Fatal("phase 5 from unknown RouterInfo endpoint escaped source validation")
	}
	manager.handleOutOfSessionPeerTest(phase5, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.2:31002")))
	if state.message5 != nil {
		t.Fatal("phase 5 from wrong source IP was retained")
	}
	manager.handlePeerTest(phase5Header, phase5Payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31002")))
	if state.message5 == nil || state.message5Peer != charlie.Hash() || callbacks != 1 {
		t.Fatal("phase 5 from Charlie's exact approved endpoint was not bound before callback")
	}

	state.charlie = charlie.Hash()
	phase7 := dataplanessu2.PeerTestBlock{Message: 7, Nonce: state.nonce}
	manager.handleOutOfSessionPeerTest(phase7, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31003")))
	if state.message7 != nil {
		t.Fatal("phase 7 from Charlie's wrong source port was retained")
	}
	manager.handleOutOfSessionPeerTest(phase7, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31002")))
	if state.message7 == nil {
		t.Fatal("phase 7 from Charlie's exact approved endpoint was rejected")
	}

	remoteAlice, _, _ := newSSU2TestLocal(t, "127.0.0.1:31004")
	charlieDB := newTransportTestPeers()
	if err := charlieDB.AdmitRouterInfo(remoteAlice.Snapshot(), uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	charlieState := &ssu2PeerTestState{
		nonce: 42, alice: remoteAlice.Hash(), bob: foundation.Hash{8}, charlie: charlie.Hash(), expires: now.Add(time.Minute),
	}
	charlieManager, _ := newSSU2ConfiguredManager(t, charlieDB)
	charlieManager.bindings = TransportBindings{LocalInfo: charlie, Clock: transportTestClock{now: now}}
	charlieManager.peerTests[charlieState.nonce] = charlieState
	phase6 := dataplanessu2.PeerTestBlock{Message: 6, Nonce: charlieState.nonce}
	charlieManager.handleOutOfSessionPeerTest(phase6, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31005")))
	if charlieState.message6Received {
		t.Fatal("forged phase 6 from an unapproved endpoint was accepted")
	}
	charlieManager.handleOutOfSessionPeerTest(phase6, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31004")))
	if !charlieState.message6Received {
		t.Fatal("phase 6 from Alice's exact approved endpoint was rejected")
	}
}

func TestSSU2RelayTagDirectionsRenewPerPeerAndCapDistinctAdvertisements(t *testing.T) {
	now := time.Now()
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = context.Background()
	manager.bindings = TransportBindings{Clock: transportTestClock{now: now}}
	grantPeer := foundation.Hash{1}
	manager.relayGrants[grantPeer] = ssu2RelayTagLease{peer: grantPeer, tag: 11, expires: now.Add(time.Second)}
	manager.introducers[11] = grantPeer
	manager.handleRelayTagRequest(&ssu2TransportSession{peer: grantPeer})
	if len(manager.relayGrants) != 1 || manager.relayGrants[grantPeer].tag != 11 {
		t.Fatalf("grant renewal did not atomically retain the per-peer lease: %+v", manager.relayGrants)
	}
	if len(manager.advertisedRelays) != 0 {
		t.Fatal("server-side RelayTag grant leaked into advertised introducers")
	}

	for index := range ssu2RelayTarget {
		peer := foundation.Hash{byte(index + 2)}
		manager.relayTagPending[peer] = now.Add(time.Second)
		manager.handleRelayTag(&ssu2TransportSession{peer: peer}, dataplanessu2.RelayTag{Tag: uint32(20 + index), Expiration: uint32(now.Add(30 * time.Second).Unix())})
	}
	if len(manager.advertisedRelays) != ssu2RelayTarget {
		t.Fatalf("advertised introducers = %d, want exactly %d distinct peers", len(manager.advertisedRelays), ssu2RelayTarget)
	}
	renewPeer := foundation.Hash{2}
	manager.relayTagPending[renewPeer] = now.Add(time.Second)
	manager.handleRelayTag(&ssu2TransportSession{peer: renewPeer}, dataplanessu2.RelayTag{Tag: 99, Expiration: uint32(now.Add(40 * time.Second).Unix())})
	if len(manager.advertisedRelays) != ssu2RelayTarget || manager.advertisedRelays[renewPeer].tag != 99 {
		t.Fatalf("advertised renewal did not replace the peer atomically: %+v", manager.advertisedRelays)
	}
	manager.handleRelayTag(&ssu2TransportSession{peer: renewPeer}, dataplanessu2.RelayTag{Tag: 101, Expiration: uint32(now.Add(45 * time.Second).Unix())})
	if manager.advertisedRelays[renewPeer].tag != 99 {
		t.Fatal("unsolicited RelayTag replaced a directionally requested lease")
	}
	extra := foundation.Hash{9}
	manager.relayTagPending[extra] = now.Add(time.Second)
	manager.handleRelayTag(&ssu2TransportSession{peer: extra}, dataplanessu2.RelayTag{Tag: 100, Expiration: uint32(now.Add(40 * time.Second).Unix())})
	if _, accepted := manager.advertisedRelays[extra]; accepted || len(manager.advertisedRelays) != ssu2RelayTarget {
		t.Fatal("fourth advertised introducer bypassed the exact-three distinct-peer cap")
	}
}

func TestSSU2RelayPublicationWorkerRetriesToExactSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		conn := newSSU2SimConn(t, net_, "alice")
		local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
		flaky := &flakyIntroducerLocal{transportTestLocal: local, failures: 2, firstCall: make(chan struct{})}
		manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: static, IntroKey: intro, HandshakeTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(func() {
			cancel()
			closeSSU2LiveManager(t, manager)
		})
		if err = manager.Start(ctx, TransportBindings{
			SSU2: conn, LocalInfo: flaky, Clock: WallClock{},
			HandleI2NPContext: func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error { return nil },
		}); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		manager.mu.Lock()
		for index := range ssu2RelayTarget {
			peer := foundation.Hash{byte(index + 1)}
			manager.advertisedRelays[peer] = ssu2RelayTagLease{peer: peer, tag: uint32(70 + index), expires: now.Add(time.Minute)}
		}
		manager.relayRevision++
		revision := manager.relayRevision
		manager.mu.Unlock()
		manager.syncRelayTagPublication()
		<-flaky.firstCall
		manager.mu.RLock()
		publishedAfterFailure := manager.publishedRevision
		manager.mu.RUnlock()
		if publishedAfterFailure == revision {
			t.Fatal("failed publication was marked published")
		}
		net_.Advance(500 * time.Millisecond)
		manager.mu.RLock()
		published := manager.publishedRevision == revision
		manager.mu.RUnlock()
		if !published || flaky.callCount() < 3 || len(selectSSU2Introducers(flaky.Snapshot(), uint64(time.Now().Unix()))) != ssu2RelayTarget {
			t.Fatalf("bounded RelayTag publication reconciliation incomplete: published=%v calls=%d introducers=%d", published, flaky.callCount(), len(selectSSU2Introducers(flaky.Snapshot(), uint64(time.Now().Unix()))))
		}
	})
}

func TestSSU2NewTokenCacheIsBoundedReplacesAndClears(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = context.Background()
	manager.tokenLifetime = time.Hour
	manager.bindings = TransportBindings{Clock: transportTestClock{now: now}}
	expiration := uint32(now.Add(30 * time.Minute).Unix())
	for index := range ssu2MaxNewTokens + 32 {
		peer := foundation.Hash{byte(index), byte(index >> 8)}
		remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+index)))
		session := &ssu2TransportSession{peer: peer, remote: remote, sendID: uint64(index + 1)}
		manager.storeNewToken(session, dataplanessu2.NewToken{Token: uint64(index + 10), Expiration: expiration})
	}
	if len(manager.newTokens) != ssu2MaxNewTokens {
		t.Fatalf("NewToken cache size = %d, want %d", len(manager.newTokens), ssu2MaxNewTokens)
	}
	peer := foundation.Hash{7}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:25000"))
	first := &ssu2TransportSession{peer: peer, remote: remote, sendID: 9001}
	second := &ssu2TransportSession{peer: peer, remote: remote, sendID: 9002}
	manager.storeNewToken(first, dataplanessu2.NewToken{Token: 1, Expiration: expiration})
	manager.storeNewToken(second, dataplanessu2.NewToken{Token: 2, Expiration: expiration})
	manager.mu.Lock()
	evictedFirst := manager.cachedNewTokenLocked(peer, remote, first.sendID)
	retainedSecond := manager.cachedNewTokenLocked(peer, remote, second.sendID)
	tokenCount := len(manager.newTokens)
	manager.mu.Unlock()
	if evictedFirst != 0 ||
		retainedSecond != 2 ||
		tokenCount != ssu2MaxNewTokens {
		t.Fatal("NewToken per-peer endpoint replacement or bounded eviction failed")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if len(manager.newTokens) != 0 {
		t.Fatal("NewToken cache survived manager Close")
	}
}

func TestSSU2RelayPermutationRandomizesOnlyIndependentFlows(t *testing.T) {
	var owned [5]ssu2EgressSlot
	flows := [...]uint64{1, 2, 1, 3, 2}
	var original [5]*ssu2EgressSlot
	for index := range owned {
		owned[index].flow = flows[index]
		owned[index].relay = true
		owned[index].data[0] = byte(index)
		original[index] = &owned[index]
	}
	changed := false
	for range 16 {
		slots := original
		shuffleIndependentRelayRun(slots[:])
		last := map[uint64]byte{}
		for _, slot := range slots {
			if previous, exists := last[slot.flow]; exists && slot.data[0] < previous {
				t.Fatalf("flow %d order was reversed by relay permutation", slot.flow)
			}
			last[slot.flow] = slot.data[0]
		}
		for index := range slots {
			if slots[index] != original[index] {
				changed = true
			}
		}
	}
	if !changed {
		t.Fatal("CSPRNG relay permutation remained deterministic FIFO across all trials")
	}
}

func TestSSU2PeerTestControlUsesBoundedRelayMixingClass(t *testing.T) {
	peer, _, _ := newSSU2TestLocal(t, "127.0.0.1:31020")
	database := newTransportTestPeers()
	now := time.Now()
	if err := database.AdmitRouterInfo(peer.Snapshot(), uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	free := make(chan *ssu2EgressSlot, 1)
	queue := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager, _ := newSSU2ConfiguredManager(t, database)
	manager.started = true
	manager.ctx = context.Background()
	manager.bindings = TransportBindings{Clock: transportTestClock{now: now}}
	manager.egressFree = free
	manager.egressQueue = queue
	test := dataplanessu2.PeerTestBlock{
		Message: 5, Nonce: 73, Timestamp: uint32(now.Unix()),
		Address: netip.MustParseAddrPort("127.0.0.1:31021"),
	}
	result := make(chan error, 1)
	go func() { result <- manager.SendPeerTest(context.Background(), peer.Hash(), test) }()
	slot := <-queue
	if !slot.relay || slot.flow != uint64(test.Nonce) {
		t.Fatalf("PeerTest egress class = relay %v flow %d, want relay flow %d", slot.relay, slot.flow, test.Nonce)
	}
	slot.done <- nil
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestSSU2StartRejectsBlockingLegacyDispatchBinding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		conn := newSSU2SimConn(t, net_, "alice")
		local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
		manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: static, IntroKey: intro})
		if err != nil {
			t.Fatal(err)
		}
		err = manager.Start(t.Context(), TransportBindings{
			SSU2: conn, LocalInfo: local, Clock: WallClock{},
			HandleI2NP: func(foundation.I2NPMessage, uint64, bool) error { select {} },
		})
		if !errors.Is(err, ErrSSU2ManagerConfig) {
			t.Fatalf("legacy blocking dispatch Start error = %v, want configuration rejection", err)
		}
	})
}
