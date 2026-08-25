package router

import (
	"context"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/network_database"
	"gosuda.org/ivnp/networking/internal/transport/ssu2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestSSU2PeerTestOutcomeTable(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.7:42000")
	observed := netip.MustParseAddrPort("198.51.100.7:43000")
	manager := &SSU2Manager{symmetricEvidence: make(map[string]ssu2PeerTestEvidence)}
	resultFor := func(withFive bool, received netip.AddrPort) PeerTestResult {
		t.Helper()
		state := &ssu2PeerTestState{
			nonce:    1,
			message4: &ssu2.PeerTestBlock{Message: 4, Address: endpoint},
			message7: &ssu2.PeerTestBlock{Message: 7, Address: received},
		}
		if withFive {
			state.message5 = &ssu2.PeerTestBlock{Message: 5, Address: endpoint}
		}
		result, done := manager.peerTestResultLocked(state, false)
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
	local, _, _ := newSSU2TestLocal(t, "127.0.0.1:23456")
	now := time.Now()
	var peer foundation.Hash
	peer[0] = 9
	manager := &SSU2Manager{
		bindings:         TransportBindings{LocalInfo: local, Clock: WallClock{}},
		advertisedRelays: map[foundation.Hash]ssu2RelayTagLease{peer: {peer: peer, tag: 77, expires: now.Add(time.Minute)}},
	}
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
	manager := &SSU2Manager{
		bindings:      TransportBindings{Clock: fixedClock{now: now}},
		tokenLifetime: time.Minute,
		newTokens: map[string]ssu2NewTokenLease{
			newTokenCacheKey(peer, remote, 2): {peer: peer, endpoint: remote.String(), destination: 2, token: 3, expires: now.Add(time.Second)},
		},
	}
	if token := manager.cachedNewTokenLocked(peer, remote, 2); token != 3 {
		t.Fatalf("cached 1-RTT token = %d, want 3", token)
	}
	if token := manager.cachedNewTokenLocked(peer, remote, 3); token != 0 {
		t.Fatalf("destination-isolated 1-RTT token = %d, want 0", token)
	}
	manager.newTokens[newTokenCacheKey(peer, remote, 2)] = ssu2NewTokenLease{destination: 2, expires: now.Add(-time.Second)}
	if token := manager.cachedNewTokenLocked(peer, remote, 2); token != 0 {
		t.Fatalf("expired cached token = %d, want fallback token request", token)
	}
	session := &ssu2TransportSession{candidate: &ssu2PathCandidate{remote: remote, expires: now.Add(time.Second)}}
	session.expirePath(now.Add(time.Second))
	if session.candidate != nil {
		t.Fatal("timed out candidate path was retained")
	}
}

func TestSSU2ManagerLiveEgressShutdownAndIOStats(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
	manager, err := NewSSU2Manager(SSU2ManagerConfig{StaticPrivate: static, IntroKey: intro})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = manager.Close()
		_ = manager.Wait()
		_ = receiver.Close()
	})
	if err = manager.Start(ctx, TransportBindings{
		SSU2: conn, LocalInfo: local, Clock: WallClock{},
		HandleI2NPContext: func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	payload := []byte{1, 2, 3, 4}
	if err = manager.writeTo(payload, receiver.LocalAddr()); err != nil {
		t.Fatalf("live egress write: %v", err)
	}
	buffer := make([]byte, len(payload))
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
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
}

func TestSSU2ManagerLivePeerTestOrchestration(t *testing.T) {
	bind := func() *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	aliceConn, bobConn, charlieConn := bind(), bind(), bind()
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	charlie, charlieStatic, charlieIntro := newSSU2TestLocal(t, charlieConn.LocalAddr().String())
	aliceDB, bobDB, charlieDB := networkdatabase.NewDatabase(alice.Hash(), 16), networkdatabase.NewDatabase(bob.Hash(), 16), networkdatabase.NewDatabase(charlie.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	for _, admission := range []struct {
		database *networkdatabase.Database
		info     networkdatabase.RouterInfo
	}{
		{aliceDB, bob.Snapshot()}, {aliceDB, charlie.Snapshot()},
		{bobDB, charlie.Snapshot()}, {charlieDB, alice.Snapshot()},
	} {
		if err := admission.database.AdmitRouterInfo(admission.info, false, now); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan PeerTestResult, 1)
	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro,
		OnPeerTestResult: func(result PeerTestResult) { results <- result },
	})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{Database: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
	if err != nil {
		t.Fatal(err)
	}
	charlieManager, err := NewSSU2Manager(SSU2ManagerConfig{Database: charlieDB, StaticPrivate: charlieStatic, IntroKey: charlieIntro})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		for _, manager := range []*SSU2Manager{aliceManager, bobManager, charlieManager} {
			_ = manager.Close()
			_ = manager.Wait()
		}
	})
	for _, start := range []struct {
		manager *SSU2Manager
		conn    *net.UDPConn
		local   *LocalRouterInfo
	}{
		{aliceManager, aliceConn, alice}, {bobManager, bobConn, bob}, {charlieManager, charlieConn, charlie},
	} {
		if err := start.manager.Start(ctx, TransportBindings{
			SSU2: start.conn, LocalInfo: start.local, Clock: WallClock{},
			HandleI2NPContext: func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error { return nil },
		}); err != nil {
			t.Fatal(err)
		}
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())}, Payload: make([]byte, 12)}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err := bobManager.Send(sendCtx, charlie.Hash(), message); err != nil {
		t.Fatalf("establish Bob/Charlie session: %v", err)
	}
	if err := aliceManager.Send(sendCtx, bob.Hash(), message); err != nil {
		t.Fatalf("establish Alice/Bob session: %v", err)
	}
	select {
	case result := <-results:
		if result.Outcome != PeerTestOK {
			t.Fatalf("live PeerTest result = %#v, want OK", result)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("live PeerTest did not complete")
	}
}

func TestSSU2DispatchShutdownCancelsContextAwareCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	queue := make(chan *ssu2DispatchBatch, 1)
	manager := &SSU2Manager{
		ctx:            ctx,
		dispatchQueues: []chan *ssu2DispatchBatch{queue},
		bindings: TransportBindings{
			Clock: fixedClock{now: time.Unix(1, 0)},
			HandleI2NPContext: func(ctx context.Context, _ foundation.Hash, _ i2np.Message, _ uint64, _ bool) error {
				close(entered)
				<-ctx.Done()
				return ctx.Err()
			},
		},
	}
	batch := &ssu2DispatchBatch{count: 1, done: make(chan error, 1)}
	manager.wg.Add(1)
	go manager.dispatchLoop(queue)
	queue <- batch
	<-entered
	cancel()
	select {
	case err := <-batch.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dispatch error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch callback did not return after cancellation")
	}
	waited := make(chan struct{})
	go func() { manager.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("dispatch loop did not stop after callback cancellation")
	}
}

func TestSSU2LiveRelayTagLeasePublishesRenewsAndWithdraws(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	aliceDB := networkdatabase.NewDatabase(alice.Hash(), 16)
	bobDB := networkdatabase.NewDatabase(bob.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	for _, admission := range []struct {
		database *networkdatabase.Database
		info     networkdatabase.RouterInfo
	}{
		{aliceDB, bob.Snapshot()},
		{bobDB, alice.Snapshot()},
	} {
		if err := admission.database.AdmitRouterInfo(admission.info, false, now); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, 3*time.Second, 10*time.Second)
	bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, 3*time.Second, 10*time.Second)
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, nil)
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, aliceManager)
		closeSSU2LiveManager(t, bobManager)
	})

	requestCtx, requestCancel := context.WithTimeout(ctx, 5*time.Second)
	defer requestCancel()
	if err := aliceManager.RequestRelayTag(requestCtx, bob.Hash()); err != nil {
		t.Fatalf("request live relay tag: %v", err)
	}
	var initialPublished uint64
	waitForSSU2Live(t, 5*time.Second, func() bool {
		snapshot := alice.Snapshot()
		candidates := selectSSU2Introducers(snapshot, uint64(time.Now().Unix()))
		if len(candidates) != 1 || candidates[0].peer != bob.Hash() || candidates[0].relayTag == 0 {
			return false
		}
		initialPublished = snapshot.Published
		return true
	}, "RelayTag grant publication")
	if valid, err := alice.Snapshot().Verify(); err != nil || !valid {
		t.Fatalf("RelayTag publication is not a signed RouterInfo: valid=%v err=%v", valid, err)
	}

	waitForSSU2Live(t, 5*time.Second, func() bool {
		snapshot := alice.Snapshot()
		candidates := selectSSU2Introducers(snapshot, uint64(time.Now().Unix()))
		return len(candidates) >= 1 && snapshot.Published > initialPublished
	}, "RelayTag lease renewal")

	closeSSU2LiveManager(t, bobManager)
	waitForSSU2Live(t, 6*time.Second, func() bool {
		return !hasSSU2IntroducerOptions(alice.Snapshot())
	}, "expired RelayTag withdrawal")
	if valid, err := alice.Snapshot().Verify(); err != nil || !valid {
		t.Fatalf("withdrawn RelayTag snapshot is not signed: valid=%v err=%v", valid, err)
	}
}

func TestSSU2LiveNewTokenCacheSkipsRetryAndExpires(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
	proxy := newSSU2TokenProxy(t, aliceConn.LocalAddr().(*net.UDPAddr), bobConn.LocalAddr().(*net.UDPAddr))
	t.Cleanup(proxy.Close)
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, proxy.conn.LocalAddr().String())
	aliceDB := networkdatabase.NewDatabase(alice.Hash(), 16)
	bobDB := networkdatabase.NewDatabase(bob.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	for _, admission := range []struct {
		database *networkdatabase.Database
		info     networkdatabase.RouterInfo
	}{
		{aliceDB, bob.Snapshot()},
		{bobDB, alice.Snapshot()},
	} {
		if err := admission.database.AdmitRouterInfo(admission.info, false, now); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, 2*time.Second, 200*time.Millisecond)
	bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, 2*time.Second, 200*time.Millisecond)
	proxy.Start(bobIntro)
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, nil)
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, nil)
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, aliceManager)
		closeSSU2LiveManager(t, bobManager)
	})

	send := func(id uint32) {
		sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
		defer sendCancel()
		if err := aliceManager.Send(sendCtx, bob.Hash(), ssu2LiveMessage(id)); err != nil {
			t.Fatalf("live token-cache send %d: %v", id, err)
		}
	}
	send(1)
	waitForSSU2Live(t, 3*time.Second, func() bool {
		return liveNewTokenPresent(aliceManager, bob.Hash())
	}, "NewToken storage after first establishment")
	waitForSSU2Live(t, 3*time.Second, func() bool {
		return liveSessionAbsent(aliceManager, bob.Hash()) && liveSessionAbsent(bobManager, alice.Hash())
	}, "first session idle eviction")
	firstRequests, firstRetries := proxy.Counts()
	if firstRequests == 0 || firstRetries == 0 {
		t.Fatalf("first establishment did not traverse TokenRequest/Retry: requests=%d retries=%d", firstRequests, firstRetries)
	}

	send(2)
	waitForSSU2Live(t, 3*time.Second, func() bool {
		return !liveSessionAbsent(aliceManager, bob.Hash())
	}, "cached-token second establishment")
	if requests, retries := proxy.Counts(); requests != firstRequests || retries != firstRetries {
		t.Fatalf("cached token sent TokenRequest/Retry: got requests=%d retries=%d, want %d/%d", requests, retries, firstRequests, firstRetries)
	}
	waitForSSU2Live(t, 3*time.Second, func() bool {
		return liveSessionAbsent(aliceManager, bob.Hash()) && liveSessionAbsent(bobManager, alice.Hash())
	}, "second session idle eviction")
	waitForSSU2Live(t, 5*time.Second, func() bool {
		return !liveNewTokenPresent(aliceManager, bob.Hash())
	}, "NewToken expiry")

	send(3)
	waitForSSU2Live(t, 3*time.Second, func() bool {
		requests, retries := proxy.Counts()
		return requests > firstRequests && retries > firstRetries
	}, "expired-token TokenRequest/Retry fallback")
}

func TestSSU2LivePathMigrationRejectsWrongSourceReplayAndTimeout(t *testing.T) {
	aliceConn := newSSU2LoopbackConn(t)
	bobConn := newSSU2LoopbackConn(t)
	proxy := newSSU2MigrationProxy(t, aliceConn.LocalAddr().(*net.UDPAddr), bobConn.LocalAddr().(*net.UDPAddr))
	t.Cleanup(proxy.Close)
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, proxy.primary.LocalAddr().String())
	aliceDB := networkdatabase.NewDatabase(alice.Hash(), 16)
	bobDB := networkdatabase.NewDatabase(bob.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	for _, admission := range []struct {
		database *networkdatabase.Database
		info     networkdatabase.RouterInfo
	}{
		{aliceDB, bob.Snapshot()},
		{bobDB, alice.Snapshot()},
	} {
		if err := admission.database.AdmitRouterInfo(admission.info, false, now); err != nil {
			t.Fatal(err)
		}
	}
	received := make(chan i2np.Message, 1)
	ctx, cancel := context.WithCancel(context.Background())
	aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Second, 10*time.Second)
	bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Second, 10*time.Second)
	proxy.Start()
	startSSU2LiveManager(t, ctx, aliceManager, aliceConn, alice, func(message i2np.Message, _ uint64, _ bool) error {
		received <- message
		return nil
	})
	startSSU2LiveManager(t, ctx, bobManager, bobConn, bob, nil)
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, aliceManager)
		closeSSU2LiveManager(t, bobManager)
	})

	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err := aliceManager.Send(sendCtx, bob.Hash(), ssu2LiveMessage(1)); err != nil {
		t.Fatalf("establish initial path: %v", err)
	}
	proxy.Migrate()
	if err := aliceManager.Send(sendCtx, bob.Hash(), ssu2LiveMessage(2)); err != nil {
		t.Fatalf("send authenticated traffic over candidate path: %v", err)
	}
	secondary := proxy.secondary.LocalAddr().(*net.UDPAddr)
	waitForSSU2Live(t, 4*time.Second, func() bool {
		return liveSessionRemoteIs(bobManager, alice.Hash(), secondary)
	}, "authenticated PathChallenge/PathResponse migration")
	if err := bobManager.Send(sendCtx, alice.Hash(), ssu2LiveMessage(3)); err != nil {
		t.Fatalf("send over migrated endpoint: %v", err)
	}
	select {
	case message := <-received:
		if message.Header.ID != 3 {
			t.Fatalf("migrated endpoint delivered message %d, want 3", message.Header.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("migrated endpoint did not deliver Bob traffic")
	}

	replay := proxy.FirstMigratedAlicePacket()
	if len(replay) == 0 {
		t.Fatal("migration proxy did not capture an authenticated packet to replay")
	}
	attacker := newSSU2LoopbackConn(t)
	t.Cleanup(func() { _ = attacker.Close() })
	if _, err := attacker.WriteToUDP(replay, bobConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("replay authenticated packet from wrong source: %v", err)
	}
	waitForSSU2Live(t, time.Second, func() bool {
		return livePathCandidatePresent(bobManager, alice.Hash())
	}, "wrong-source replay candidate")
	if !liveSessionRemoteIs(bobManager, alice.Hash(), secondary) {
		t.Fatal("wrong-source replay changed the authenticated endpoint")
	}
	waitForSSU2Live(t, 3*time.Second, func() bool {
		return !livePathCandidatePresent(bobManager, alice.Hash()) && liveSessionRemoteIs(bobManager, alice.Hash(), secondary)
	}, "wrong-source replay path timeout rejection")
}

func newSSU2LoopbackConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newSSU2LiveManager(t *testing.T, database *networkdatabase.Database, static, intro []byte, tokenLifetime, idleTimeout time.Duration) *SSU2Manager {
	t.Helper()
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database: database, StaticPrivate: static, IntroKey: intro, TokenLifetime: tokenLifetime,
		HandshakeTimeout: time.Second, IdleTimeout: idleTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func startSSU2LiveManager(t *testing.T, ctx context.Context, manager *SSU2Manager, conn *net.UDPConn, local *LocalRouterInfo, handle func(i2np.Message, uint64, bool) error) {
	t.Helper()
	if handle ==
		nil {
		handle = func(i2np.Message, uint64, bool) error { return nil }
	}

	if err := manager.Start(ctx, TransportBindings{
		SSU2: conn, LocalInfo: local, Clock: WallClock{},
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message i2np.Message, now uint64, floodfill bool) error {
			return handle(message, now, floodfill)
		},
	}); err != nil {
		t.Fatal(err)
	}
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

func waitForSSU2Live(t *testing.T, timeout time.Duration, condition func() bool, name string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", name)
		case <-tick.C:
		}
	}
}

func ssu2LiveMessage(id uint32) i2np.Message {
	return i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: id, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: []byte("live SSU2 extension test"),
	}
}

func hasSSU2IntroducerOptions(info networkdatabase.RouterInfo) bool {
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

func liveSessionAbsent(manager *SSU2Manager, peer foundation.Hash) bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.sessionsByPeer[peer] == nil
}

func liveSessionRemoteIs(manager *SSU2Manager, peer foundation.Hash, remote *net.UDPAddr) bool {
	manager.mu.RLock()
	session := manager.sessionsByPeer[peer]
	manager.mu.RUnlock()
	return session != nil && sameUDPAddress(session.remoteAddr(), remote)
}

func livePathCandidatePresent(manager *SSU2Manager, peer foundation.Hash) bool {
	manager.mu.RLock()
	session := manager.sessionsByPeer[peer]
	manager.mu.RUnlock()
	if session == nil {
		return false
	}
	session.pathMu.Lock()
	defer session.pathMu.Unlock()
	return session.candidate != nil
}

func liveNewTokenPresent(manager *SSU2Manager, peer foundation.Hash) bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for _, lease := range manager.newTokens {
		if lease.peer == peer && lease.expires.After(time.Now()) {
			return true
		}
	}
	return false
}

type ssu2TokenProxy struct {
	conn       *net.UDPConn
	alice, bob *net.UDPAddr
	intro      []byte
	done       chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	requests   int
	retries    int
}

func newSSU2TokenProxy(t *testing.T, alice, bob *net.UDPAddr) *ssu2TokenProxy {
	t.Helper()
	conn := newSSU2LoopbackConn(t)
	return &ssu2TokenProxy{conn: conn, alice: cloneUDPAddress(alice).(*net.UDPAddr), bob: cloneUDPAddress(bob).(*net.UDPAddr), done: make(chan struct{})}
}

func (p *ssu2TokenProxy) Start(intro []byte) {
	p.intro = append([]byte(nil), intro...)
	p.wg.Go(func() {
		packet := make([]byte, ssu2.MaxIPv4PacketLen)
		for {
			_ = p.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, remote, err := p.conn.ReadFromUDP(packet)
			if err != nil {
				select {
				case <-p.done:
					return
				default:
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
			}
			wire := append([]byte(nil), packet[:n]...)
			if sameUDPAddress(remote, p.alice) {
				if header, _, parseErr := ssu2.ParseOutOfSession(append([]byte(nil), wire...), p.intro); parseErr == nil {
					p.mu.Lock()
					if header.Type == ssu2.TokenRequest {
						p.requests++
					}
					p.mu.Unlock()
				}
				_, _ = p.conn.WriteToUDP(wire, p.bob)
			} else if sameUDPAddress(remote, p.bob) {
				if header, _, parseErr := ssu2.ParseOutOfSession(append([]byte(nil), wire...), p.intro); parseErr == nil && header.Type == ssu2.Retry {
					p.mu.Lock()
					p.retries++
					p.mu.Unlock()
				}
				_, _ = p.conn.WriteToUDP(wire, p.alice)
			}
		}
	})
}

func (p *ssu2TokenProxy) Counts() (requests, retries int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests, p.retries
}

func (p *ssu2TokenProxy) Close() {
	close(p.done)
	p.wg.Wait()
}

type ssu2MigrationProxy struct {
	primary, secondary *net.UDPConn
	alice, bob         *net.UDPAddr
	done               chan struct{}
	wg                 sync.WaitGroup
	mu                 sync.Mutex
	migrated           bool
	firstMigrated      []byte
}

func newSSU2MigrationProxy(t *testing.T, alice, bob *net.UDPAddr) *ssu2MigrationProxy {
	t.Helper()
	return &ssu2MigrationProxy{
		primary: newSSU2LoopbackConn(t), secondary: newSSU2LoopbackConn(t),
		alice: cloneUDPAddress(alice).(*net.UDPAddr), bob: cloneUDPAddress(bob).(*net.UDPAddr),
		done: make(chan struct{}),
	}
}

func (p *ssu2MigrationProxy) Start() {
	for _, conn := range []*net.UDPConn{p.primary, p.secondary} {
		p.wg.Add(1)
		go p.forward(conn)
	}
}

func (p *ssu2MigrationProxy) forward(conn *net.UDPConn) {
	defer p.wg.Done()
	packet := make([]byte, ssu2.MaxIPv4PacketLen)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(packet)
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}
		wire := append([]byte(nil), packet[:n]...)
		switch {
		case conn == p.primary && sameUDPAddress(remote, p.alice):
			p.mu.Lock()
			migrated := p.migrated
			if migrated && len(p.firstMigrated) == 0 {
				p.firstMigrated = append([]byte(nil), wire...)
			}
			p.mu.Unlock()
			outbound := p.primary
			if migrated {
				outbound = p.secondary
			}
			_, _ = outbound.WriteToUDP(wire, p.bob)
		case sameUDPAddress(remote, p.bob):
			_, _ = p.primary.WriteToUDP(wire, p.alice)
		}
	}
}

func (p *ssu2MigrationProxy) Migrate() {
	p.mu.Lock()
	p.migrated = true
	p.mu.Unlock()
}

func (p *ssu2MigrationProxy) FirstMigratedAlicePacket() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.firstMigrated...)
}

func (p *ssu2MigrationProxy) Close() {
	close(p.done)
	p.wg.Wait()
}

type flakyIntroducerLocal struct {
	*LocalRouterInfo
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
		return errors.New("transient publication failure")
	}
	f.mu.Unlock()
	return f.LocalRouterInfo.UpdateSSU2Introducers(ctx, introducers)
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
	database := networkdatabase.NewDatabase(alice.Hash(), 16)
	if err := database.AdmitRouterInfo(charlie.Snapshot(), false, uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	state := &ssu2PeerTestState{
		nonce: 41, alice: alice.Hash(), bob: foundation.Hash{9}, expires: now.Add(time.Minute),
	}
	callbacks := 0
	manager := &SSU2Manager{
		database:     database,
		maxClockSkew: time.Minute,
		bindings:     TransportBindings{LocalInfo: alice, Clock: fixedClock{now: now}},
		peerTests:    map[uint32]*ssu2PeerTestState{state.nonce: state},
		onPeerTest:   func(ssu2.PeerTestBlock, net.Addr) { callbacks++ },
	}
	phase5 := ssu2.PeerTestBlock{
		Message: 5, Nonce: state.nonce, Timestamp: uint32(now.Unix()),
		Address: netip.MustParseAddrPort("127.0.0.1:31001"),
	}
	phase5Payload, err := ssu2.MarshalPeerTestBlock(nil, phase5)
	if err != nil {
		t.Fatal(err)
	}
	destinationID, sourceID := ssu2.PeerTestConnectionIDs(state.nonce)
	phase5Header := ssu2.LongHeader{DestinationID: destinationID, SourceID: sourceID}
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
	phase7 := ssu2.PeerTestBlock{Message: 7, Nonce: state.nonce}
	manager.handleOutOfSessionPeerTest(phase7, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31003")))
	if state.message7 != nil {
		t.Fatal("phase 7 from Charlie's wrong source port was retained")
	}
	manager.handleOutOfSessionPeerTest(phase7, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:31002")))
	if state.message7 == nil {
		t.Fatal("phase 7 from Charlie's exact approved endpoint was rejected")
	}

	remoteAlice, _, _ := newSSU2TestLocal(t, "127.0.0.1:31004")
	charlieDB := networkdatabase.NewDatabase(charlie.Hash(), 16)
	if err := charlieDB.AdmitRouterInfo(remoteAlice.Snapshot(), false, uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	charlieState := &ssu2PeerTestState{
		nonce: 42, alice: remoteAlice.Hash(), bob: foundation.Hash{8}, charlie: charlie.Hash(), expires: now.Add(time.Minute),
	}
	charlieManager := &SSU2Manager{
		database:  charlieDB,
		bindings:  TransportBindings{LocalInfo: charlie, Clock: fixedClock{now: now}},
		peerTests: map[uint32]*ssu2PeerTestState{charlieState.nonce: charlieState},
	}
	phase6 := ssu2.PeerTestBlock{Message: 6, Nonce: charlieState.nonce}
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
	manager := &SSU2Manager{
		started:          true,
		ctx:              context.Background(),
		maxPending:       16,
		timeout:          time.Second,
		tokenLifetime:    time.Minute,
		bindings:         TransportBindings{Clock: fixedClock{now: now}},
		introducers:      make(map[uint32]foundation.Hash),
		relayGrants:      make(map[foundation.Hash]ssu2RelayTagLease),
		advertisedRelays: make(map[foundation.Hash]ssu2RelayTagLease),
		relayTagPending:  make(map[foundation.Hash]time.Time),
		sessionsByPeer:   make(map[foundation.Hash]*ssu2TransportSession),
		sessionsByID:     make(map[uint64]*ssu2TransportSession),
	}
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
		manager.handleRelayTag(&ssu2TransportSession{peer: peer}, ssu2.RelayTag{Tag: uint32(20 + index), Expiration: uint32(now.Add(30 * time.Second).Unix())})
	}
	if len(manager.advertisedRelays) != ssu2RelayTarget {
		t.Fatalf("advertised introducers = %d, want exactly %d distinct peers", len(manager.advertisedRelays), ssu2RelayTarget)
	}
	renewPeer := foundation.Hash{2}
	manager.relayTagPending[renewPeer] = now.Add(time.Second)
	manager.handleRelayTag(&ssu2TransportSession{peer: renewPeer}, ssu2.RelayTag{Tag: 99, Expiration: uint32(now.Add(40 * time.Second).Unix())})
	if len(manager.advertisedRelays) != ssu2RelayTarget || manager.advertisedRelays[renewPeer].tag != 99 {
		t.Fatalf("advertised renewal did not replace the peer atomically: %+v", manager.advertisedRelays)
	}
	manager.handleRelayTag(&ssu2TransportSession{peer: renewPeer}, ssu2.RelayTag{Tag: 101, Expiration: uint32(now.Add(45 * time.Second).Unix())})
	if manager.advertisedRelays[renewPeer].tag != 99 {
		t.Fatal("unsolicited RelayTag replaced a directionally requested lease")
	}
	extra := foundation.Hash{9}
	manager.relayTagPending[extra] = now.Add(time.Second)
	manager.handleRelayTag(&ssu2TransportSession{peer: extra}, ssu2.RelayTag{Tag: 100, Expiration: uint32(now.Add(40 * time.Second).Unix())})
	if _, accepted := manager.advertisedRelays[extra]; accepted || len(manager.advertisedRelays) != ssu2RelayTarget {
		t.Fatal("fourth advertised introducer bypassed the exact-three distinct-peer cap")
	}
}

func TestSSU2RelayPublicationWorkerRetriesToExactSnapshot(t *testing.T) {
	conn := newSSU2LoopbackConn(t)
	local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
	flaky := &flakyIntroducerLocal{LocalRouterInfo: local, failures: 2, firstCall: make(chan struct{})}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{StaticPrivate: static, IntroKey: intro, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		closeSSU2LiveManager(t, manager)
	})
	if err = manager.Start(ctx, TransportBindings{
		SSU2: conn, LocalInfo: flaky, Clock: WallClock{},
		HandleI2NPContext: func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error { return nil },
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
	select {
	case <-flaky.firstCall:
	case <-time.After(time.Second):
		t.Fatal("publication worker did not attempt reconciliation")
	}
	manager.mu.RLock()
	publishedAfterFailure := manager.publishedRevision
	manager.mu.RUnlock()
	if publishedAfterFailure == revision {
		t.Fatal("failed publication was marked published")
	}
	waitForSSU2Live(t, 3*time.Second, func() bool {
		manager.mu.RLock()
		published := manager.publishedRevision == revision
		manager.mu.RUnlock()
		return published && flaky.callCount() >= 3 && len(selectSSU2Introducers(flaky.Snapshot(), uint64(time.Now().Unix()))) == ssu2RelayTarget
	}, "bounded RelayTag publication reconciliation")
}

func TestSSU2NewTokenCacheIsBoundedReplacesAndClears(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := &SSU2Manager{
		started:        true,
		ctx:            context.Background(),
		tokenLifetime:  time.Hour,
		bindings:       TransportBindings{Clock: fixedClock{now: now}},
		newTokens:      make(map[string]ssu2NewTokenLease),
		peerTests:      make(map[uint32]*ssu2PeerTestState),
		sessionsByID:   make(map[uint64]*ssu2TransportSession),
		sessionsByPeer: make(map[foundation.Hash]*ssu2TransportSession),
	}
	expiration := uint32(now.Add(30 * time.Minute).Unix())
	for index := range ssu2MaxNewTokens + 32 {
		peer := foundation.Hash{byte(index), byte(index >> 8)}
		remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+index)))
		session := &ssu2TransportSession{peer: peer, remote: remote, sendID: uint64(index + 1)}
		manager.storeNewToken(session, ssu2.NewToken{Token: uint64(index + 10), Expiration: expiration})
	}
	if len(manager.newTokens) != ssu2MaxNewTokens {
		t.Fatalf("NewToken cache size = %d, want %d", len(manager.newTokens), ssu2MaxNewTokens)
	}
	peer := foundation.Hash{7}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:25000"))
	first := &ssu2TransportSession{peer: peer, remote: remote, sendID: 9001}
	second := &ssu2TransportSession{peer: peer, remote: remote, sendID: 9002}
	manager.storeNewToken(first, ssu2.NewToken{Token: 1, Expiration: expiration})
	manager.storeNewToken(second, ssu2.NewToken{Token: 2, Expiration: expiration})
	if manager.cachedNewTokenLocked(peer, remote, first.sendID) != 0 ||
		manager.cachedNewTokenLocked(peer, remote, second.sendID) != 2 ||
		len(manager.newTokens) != ssu2MaxNewTokens {
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
	database := networkdatabase.NewDatabase(foundation.Hash{1}, 4)
	now := time.Now()
	if err := database.AdmitRouterInfo(peer.Snapshot(), false, uint64(now.UnixMilli())); err != nil {
		t.Fatal(err)
	}
	free := make(chan *ssu2EgressSlot, 1)
	queue := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager := &SSU2Manager{
		database: database, started: true, ctx: context.Background(),
		bindings:   TransportBindings{Clock: fixedClock{now: now}},
		egressFree: free, egressQueue: queue,
	}
	test := ssu2.PeerTestBlock{
		Message: 5, Nonce: 73, Timestamp: uint32(now.Unix()),
		Address: netip.MustParseAddrPort("127.0.0.1:31021"),
	}
	result := make(chan error, 1)
	go func() { result <- manager.SendPeerTest(context.Background(), peer.Hash(), test) }()
	var slot *ssu2EgressSlot
	select {
	case slot = <-queue:
	case <-time.After(time.Second):
		t.Fatal("PeerTest packet did not enter egress")
	}
	if !slot.relay || slot.flow != uint64(test.Nonce) {
		t.Fatalf("PeerTest egress class = relay %v flow %d, want relay flow %d", slot.relay, slot.flow, test.Nonce)
	}
	slot.done <- nil
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("PeerTest egress did not complete")
	}
}

func TestSSU2StartRejectsBlockingLegacyDispatchBinding(t *testing.T) {
	conn := newSSU2LoopbackConn(t)
	local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
	manager, err := NewSSU2Manager(SSU2ManagerConfig{StaticPrivate: static, IntroKey: intro})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Start(context.Background(), TransportBindings{
		SSU2: conn, LocalInfo: local, Clock: WallClock{},
		HandleI2NP: func(i2np.Message, uint64, bool) error { select {} },
	})
	if !errors.Is(err, ErrSSU2ManagerConfig) {
		t.Fatalf("legacy blocking dispatch Start error = %v, want configuration rejection", err)
	}
}
