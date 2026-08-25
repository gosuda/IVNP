package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/network/transport/ssu2"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
)

func TestSSU2RouterInfoStoreUsesDeterministicGzipAndServiceAdmission(t *testing.T) {
	local, _, _ := newSSU2TestLocal(t, "127.0.0.1:23456")
	now := time.UnixMilli(int64(local.Snapshot().Published))
	first, err := ssu2RouterInfoStore(local.Snapshot(), now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ssu2RouterInfoStore(local.Snapshot(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatal("RouterInfo gzip payload is not deterministic")
	}
	store, err := i2np.ParseDatabaseStore(first.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Data) < 2 || store.Data[0] != 0x1f || store.Data[1] != 0x8b {
		t.Fatalf("RouterInfo store is not gzip: %x", store.Data[:min(2, len(store.Data))])
	}
	database := netdb.NewDatabase(ivnp.Hash{}, 16)
	service := NewService(database)
	if err = service.HandleI2NP(first, uint64(now.UnixMilli()), false); err != nil {
		t.Fatalf("Service rejected SSU2 RouterInfo store: %v", err)
	}
	if _, found := database.Routers().Get(local.Hash()); !found {
		t.Fatal("Service did not admit SSU2 RouterInfo store")
	}
}

func TestSSU2RelayRouterInfoStoreCacheReusesAndRefreshesLocalSnapshot(t *testing.T) {
	local, static, intro := newSSU2TestLocal(t, "127.0.0.1:23456")
	now := time.UnixMilli(1_700_000_000_000)
	manager := &SSU2Manager{routerInfoStores: make(map[ivnp.Hash]ssu2RouterInfoStoreSnapshot)}

	info := local.Snapshot()
	if _, err := manager.cachedSSU2RouterInfoStore(info, now); err != nil {
		t.Fatalf("prepare initial RouterInfo store: %v", err)
	}
	sentinel := []byte{0xde, 0xad, 0xbe, 0xef}
	manager.routerInfoStores[local.Hash()] = ssu2RouterInfoStoreSnapshot{
		raw:        append([]byte(nil), info.Bytes()...),
		compressed: sentinel,
		hash:       local.Hash(),
	}
	reused, err := manager.cachedSSU2RouterInfoStore(info, now)
	if err != nil {
		t.Fatalf("reuse prepared RouterInfo store: %v", err)
	}
	reusedStore, err := i2np.ParseDatabaseStore(reused.Payload)
	if err != nil || !bytes.Equal(reusedStore.Data, sentinel) {
		t.Fatalf("relay store recompressed cached RouterInfo: %x, %v", reusedStore.Data, err)
	}

	private, err := ecdh.X25519().NewPrivateKey(static)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "host", Value: "127.0.0.1"},
			{Key: "i", Value: ivnp.EncodeI2PBase64(intro)},
			{Key: "port", Value: "23457"},
			{Key: "s", Value: ivnp.EncodeI2PBase64(private.PublicKey().Bytes())},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatalf("replace local RouterInfo: %v", err)
	}
	if err = local.Publish(context.Background()); err != nil {
		t.Fatalf("publish changed local RouterInfo: %v", err)
	}
	refreshed, err := manager.cachedSSU2RouterInfoStore(local.Snapshot(), now)
	if err != nil {
		t.Fatalf("refresh RouterInfo store: %v", err)
	}
	refreshedStore, err := i2np.ParseDatabaseStore(refreshed.Payload)
	if err != nil || len(refreshedStore.Data) < 2 || refreshedStore.Data[0] != 0x1f || refreshedStore.Data[1] != 0x8b {
		t.Fatalf("refreshed RouterInfo store = %x, %v", refreshedStore.Data, err)
	}
	if bytes.Equal(manager.routerInfoStores[local.Hash()].raw, info.Bytes()) {
		t.Fatal("RouterInfo cache was not refreshed after local publication")
	}
}

func TestSSU2DispatchI2NPUsesClockAndRejectsExpired(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	var deliveredAt uint64
	manager := &SSU2Manager{ctx: context.Background(), bindings: TransportBindings{
		Clock: fixedClock{now: now},
		HandleI2NPContext: func(_ context.Context, _ ivnp.Hash, _ i2np.Message, nowMillis uint64, _ bool) error {
			deliveredAt = nowMillis
			return nil
		},
	}}
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: uint64(now.Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 12),
	}
	if err := manager.dispatchI2NP(ivnp.Hash{1}, message); err != nil {
		t.Fatalf("dispatch current I2NP: %v", err)
	}
	if deliveredAt != uint64(now.UnixMilli()) {
		t.Fatalf("dispatch now = %d, want %d", deliveredAt, now.UnixMilli())
	}

	service := NewService(netdb.NewDatabase(ivnp.Hash{}, 16))
	manager = &SSU2Manager{ctx: context.Background(), bindings: TransportBindings{
		Clock: fixedClock{now: now},
		HandleI2NPContext: func(_ context.Context, _ ivnp.Hash, message i2np.Message, nowMillis uint64, floodfill bool) error {
			return service.HandleI2NP(message, nowMillis, floodfill)
		},
	}}
	message.Header.ID++
	message.Header.Expiration = uint64(now.Add(-time.Duration(i2npMessageClockSkewMillis+1) * time.Millisecond).UnixMilli())
	if err := manager.dispatchI2NP(ivnp.Hash{1}, message); err != ErrExpired {
		t.Fatalf("expired SSU2 I2NP error = %v, want %v", err, ErrExpired)
	}
}

func TestSSU2ManagerAuthenticatesAndRoutesI2NP(t *testing.T) {
	aliceConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	bobConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = aliceConn.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	aliceDB := netdb.NewDatabase(alice.Hash(), 16)
	bobDB := netdb.NewDatabase(bob.Hash(), 16)
	if err = aliceDB.AdmitRouterInfo(bob.Snapshot(), false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit Bob RouterInfo: %v", err)
	}

	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{Database: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{Database: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan i2np.Message, 1)
	var deliveredAt atomic.Uint64
	if err = bobManager.Start(ctx, TransportBindings{
		SSU2:      bobConn,
		LocalInfo: bob,
		Clock:     WallClock{},
		HandleI2NPContext: func(_ context.Context, _ ivnp.Hash, message i2np.Message, nowMillis uint64, _ bool) error {
			deliveredAt.Store(nowMillis)
			received <- message
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err = aliceManager.Start(ctx, TransportBindings{
		SSU2:      aliceConn,
		LocalInfo: alice,
		Clock:     WallClock{},
		HandleI2NPContext: func(context.Context, ivnp.Hash, i2np.Message, uint64, bool) error {
			return nil
		},
	}); err != nil {
		_ = bobManager.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = aliceManager.Close()
		_ = bobManager.Close()
		if err := aliceManager.Wait(); err != nil {
			t.Errorf("Alice manager wait: %v", err)
		}
		if err := bobManager.Wait(); err != nil {
			t.Errorf("Bob manager wait: %v", err)
		}
	})

	expires := uint64(time.Now().Add(time.Minute).UnixMilli())
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 9, Expiration: expires},
		Payload: make([]byte, 12),
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err = aliceManager.Send(sendCtx, bob.Hash(), message); err != nil {
		t.Fatalf("Send over native SSU2: %v", err)
	}
	select {
	case got := <-received:
		if got.Header.Type != message.Header.Type || got.Header.ID != message.Header.ID || got.Header.Expiration != message.Header.Expiration/1000*1000 {
			t.Fatalf("received I2NP header = %#v, want %#v", got.Header, message.Header)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native SSU2 peer did not receive I2NP")
	}
	if deliveredAt.Load() == 0 {
		t.Fatal("SSU2 delivery used a zero current time")
	}
	if bobDB.Routers().Len() != 1 {
		t.Fatalf("authenticated Alice RouterInfo was not admitted: len = %d", bobDB.Routers().Len())
	}
	if !waitForSSU2SentPackets(aliceManager, bob.Hash(), 5*time.Second) {
		t.Fatal("SSU2 ACK did not release the reliable data packet")
	}
	largePayload := make([]byte, 4096)
	for index := range largePayload {
		largePayload[index] = byte(index)
	}
	large := i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: 10, Expiration: expires},
		Payload: largePayload,
	}
	if err = aliceManager.Send(sendCtx, bob.Hash(), large); err != nil {
		t.Fatalf("Send fragmented native SSU2 message: %v", err)
	}
	select {
	case got := <-received:
		if got.Header.Type != large.Header.Type || got.Header.ID != large.Header.ID || !bytes.Equal(got.Payload, large.Payload) {
			t.Fatalf("received fragmented I2NP = %#v, payload length %d", got.Header, len(got.Payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native SSU2 peer did not receive fragmented I2NP")
	}
	if !waitForSSU2SentPackets(aliceManager, bob.Hash(), 5*time.Second) {
		t.Fatal("SSU2 ACK did not release fragmented data packets")
	}
	retransmitted := i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: 11, Expiration: expires},
		Payload: []byte("reliable SSU2 retransmission"),
	}
	if err = aliceManager.Send(sendCtx, bob.Hash(), retransmitted); err != nil {
		t.Fatalf("Send retransmitted native SSU2 message: %v", err)
	}
	select {
	case got := <-received:
		if got.Header.ID != retransmitted.Header.ID || !bytes.Equal(got.Payload, retransmitted.Payload) {
			t.Fatalf("received retransmitted I2NP = %#v, %x", got.Header, got.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native SSU2 retransmission did not arrive")
	}
	if !waitForSSU2SentPackets(aliceManager, bob.Hash(), 5*time.Second) {
		t.Fatal("SSU2 retransmission was not acknowledged")
	}
	if !aliceManager.Status().Running || !bobManager.Status().Running {
		t.Fatal("native SSU2 managers stopped during a live session")
	}
}

func TestSSU2ManagerRelaysIntroductionAndHolePunch(t *testing.T) {
	aliceConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	bobConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = aliceConn.Close()
		t.Fatal(err)
	}
	charlieConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = aliceConn.Close()
		_ = bobConn.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
	bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
	charlie, charlieStatic, charlieIntro := newSSU2TestLocal(t, charlieConn.LocalAddr().String())
	charlieEndpoint, err := netip.ParseAddrPort(charlieConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	aliceEndpoint, err := netip.ParseAddrPort(aliceConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	aliceDB := netdb.NewDatabase(alice.Hash(), 16)
	bobDB := netdb.NewDatabase(bob.Hash(), 16)
	charlieDB := netdb.NewDatabase(charlie.Hash(), 16)
	now := uint64(time.Now().UnixMilli())
	for _, admission := range []struct {
		database *netdb.Database
		info     netdb.RouterInfo
	}{
		{aliceDB, bob.Snapshot()},
		{aliceDB, charlie.Snapshot()},
		{bobDB, alice.Snapshot()},
		{bobDB, charlie.Snapshot()},
		{charlieDB, bob.Snapshot()},
	} {
		if err = admission.database.AdmitRouterInfo(admission.info, false, now); err != nil {
			t.Fatalf("admit relay RouterInfo: %v", err)
		}
	}
	received := make(chan i2np.Message, 4)
	charlieService := NewWithSinks(charlieDB, Sinks{
		DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil },
	})
	aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database:      aliceDB,
		StaticPrivate: aliceStatic,
		IntroKey:      aliceIntro,
		SignControl: func(message []byte) ([]byte, error) {
			return alice.Sign(message), nil
		},
		IntroductionEndpoint: func() (netip.AddrPort, error) {
			return aliceEndpoint, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewSSU2Manager(SSU2ManagerConfig{Database: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
	if err != nil {
		t.Fatal(err)
	}
	charlieManager, err := NewSSU2Manager(SSU2ManagerConfig{
		Database:      charlieDB,
		StaticPrivate: charlieStatic,
		IntroKey:      charlieIntro,
		SignControl: func(message []byte) ([]byte, error) {
			return charlie.Sign(message), nil
		},
		IntroductionEndpoint: func() (netip.AddrPort, error) {
			return charlieEndpoint, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []struct {
		manager *SSU2Manager
		conn    *net.UDPConn
		local   *LocalRouterInfo
		handler func(i2np.Message, uint64, bool) error
	}{
		{aliceManager, aliceConn, alice, func(i2np.Message, uint64, bool) error { return nil }},
		{bobManager, bobConn, bob, func(i2np.Message, uint64, bool) error { return nil }},
		{charlieManager, charlieConn, charlie, func(message i2np.Message, nowMillis uint64, fromFloodfill bool) error {
			if message.Header.Type == i2np.Data {
				received <- message
				return nil
			}
			return charlieService.HandleI2NP(message, nowMillis, fromFloodfill)
		}},
	} {
		if err = start.manager.Start(ctx, TransportBindings{
			SSU2: start.conn, LocalInfo: start.local, Clock: WallClock{},
			HandleI2NPContext: func(_ context.Context, _ ivnp.Hash, message i2np.Message, now uint64, floodfill bool) error {
				return start.handler(message, now, floodfill)
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = aliceManager.Close()
		_ = bobManager.Close()
		_ = charlieManager.Close()
		if err := aliceManager.Wait(); err != nil {
			t.Errorf("Alice manager wait: %v", err)
		}
		if err := bobManager.Wait(); err != nil {
			t.Errorf("Bob manager wait: %v", err)
		}
		if err := charlieManager.Wait(); err != nil {
			t.Errorf("Charlie manager wait: %v", err)
		}
	})

	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err = bobManager.Send(sendCtx, charlie.Hash(), i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 70, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 12),
	}); err != nil {
		t.Fatalf("establish Bob-Charlie session: %v", err)
	}
	const relayTag = 0x10203040
	bobHash := bob.Hash()
	time.Sleep(time.Millisecond)
	if err = alice.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "i", Value: ivnp.EncodeI2PBase64(aliceIntro)},
			{Key: "s", Value: ivnp.EncodeI2PBase64(ecdhPublic(aliceStatic))},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatalf("publish firewalled Alice address: %v", err)
	}
	alice.SetReachability(ReachabilityFirewalled)
	if err = alice.Publish(ctx); err != nil {
		t.Fatalf("publish firewalled Alice RouterInfo: %v", err)
	}
	if _, err = selectSSU2Address(alice.Snapshot()); err == nil {
		t.Fatal("firewalled Alice RouterInfo retained a direct endpoint")
	}
	if err = charlie.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "i", Value: ivnp.EncodeI2PBase64(charlieIntro)},
			{Key: "ih0", Value: ivnp.EncodeI2PBase64(bobHash[:])},
			{Key: "itag0", Value: "270544960"},
			{Key: "s", Value: ivnp.EncodeI2PBase64(ecdhPublic(charlieStatic))},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatalf("publish firewalled Charlie address: %v", err)
	}
	charlie.SetReachability(ReachabilityFirewalled)
	if err = charlie.Publish(ctx); err != nil {
		t.Fatalf("publish firewalled Charlie RouterInfo: %v", err)
	}
	if err = aliceDB.AdmitRouterInfo(charlie.Snapshot(), false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit firewalled Charlie RouterInfo: %v", err)
	}
	if ref, found := aliceDB.Routers().Get(charlie.Hash()); !found {
		t.Fatal("firewalled Charlie RouterInfo was not admitted")
	} else if _, err = selectSSU2Address(ref.Info); err == nil {
		t.Fatal("firewalled Charlie RouterInfo retained a direct endpoint")
	}
	if err = bobManager.RegisterIntroducer(relayTag, charlie.Hash()); err != nil {
		t.Fatal(err)
	}
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: 71, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: []byte("introduced SSU2 session"),
	}
	if err = aliceManager.Send(sendCtx, charlie.Hash(), message); err != nil {
		t.Fatalf("send through automatic native SSU2 introduction: %v", err)
	}
	if _, found := charlieDB.Routers().Get(alice.Hash()); !found {
		t.Fatal("relay DatabaseStore did not admit Alice RouterInfo at Charlie")
	}
	for {
		select {
		case got := <-received:
			if got.Header.ID == message.Header.ID && bytes.Equal(got.Payload, message.Payload) {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatal("introduced native SSU2 session did not deliver I2NP")
		}
	}
}

func waitForSSU2SentPackets(manager *SSU2Manager, peer ivnp.Hash, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		manager.mu.RLock()
		session := manager.sessionsByPeer[peer]
		manager.mu.RUnlock()
		if session != nil {
			session.sendMu.Lock()
			pending := len(session.sent)
			session.sendMu.Unlock()
			if pending == 0 {
				return true
			}
		}
		select {
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}

type dropSSU2PacketConn struct {
	net.PacketConn
	drop atomic.Int32
}

func (c *dropSSU2PacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	if c.drop.Load() > 0 && c.drop.Add(-1) >= 0 {
		return len(packet), nil
	}
	return c.PacketConn.WriteTo(packet, address)
}

func TestSSU2SessionEvictionRemovesBothIndexes(t *testing.T) {
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		StaticPrivate: static.Bytes(),
		IntroKey:      make([]byte, 32),
		IdleTimeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var peer ivnp.Hash
	peer[0] = 1
	now := time.Now()
	session := &ssu2TransportSession{
		peer:         peer,
		receiveID:    2,
		sent:         make(map[uint32]*ssu2SentPacket),
		lastActivity: now.Add(-time.Second),
	}
	manager.sessionsByPeer[peer] = session
	manager.sessionsByID[session.receiveID] = session
	if !session.idle(now, manager.idleTimeout) {
		t.Fatal("expired SSU2 session remained active")
	}
	manager.removeSession(session)
	if manager.sessionsByPeer[peer] != nil || manager.sessionsByID[session.receiveID] != nil {
		t.Fatal("SSU2 session eviction left a live index")
	}

	session.lastActivity = now
	session.sent[1] = &ssu2SentPacket{sentAt: now.Add(-ssu2RetransmitInterval), attempts: ssu2MaxRetransmits}
	manager.sessionsByPeer[peer] = session
	manager.sessionsByID[session.receiveID] = session
	if !manager.retransmitOne(session, now) {
		t.Fatal("retransmission exhaustion did not evict the SSU2 session")
	}
	manager.removeSession(session)
	if manager.sessionsByPeer[peer] != nil || manager.sessionsByID[session.receiveID] != nil {
		t.Fatal("retransmission eviction left a live SSU2 session index")
	}
}

func TestSSU2SessionReleaseSynchronizesWithReceive(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	header1 := bytes.Repeat([]byte{2}, 32)
	header2 := bytes.Repeat([]byte{3}, 32)
	send, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	session := &ssu2TransportSession{
		sendID: 7, receiveID: 7, send: send, receive: receive,
		sent: make(map[uint32]*ssu2SentPacket), fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	payload := []byte{ssu2.BlockPadding, 0, 5, 0, 0, 0, 0, 0}
	packet, err := send.SealDataTo(make([]byte, ssu2.MaxIPv4PacketLen), ssu2.ShortHeader{DestinationID: 7, PacketNumber: 1, Type: ssu2.Data}, payload)
	if err != nil {
		t.Fatal(err)
	}
	manager := &SSU2Manager{bindings: TransportBindings{Clock: WallClock{}}}
	session.receiveMu.Lock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		manager.handleDataFrom(session, append([]byte(nil), packet...), netip.AddrPort{})
	}()
	go func() {
		defer wg.Done()
		session.ReleaseSensitive()
	}()
	session.receiveMu.Unlock()
	wg.Wait()
	session.ReleaseSensitive()
	if session.send != nil || session.receive != nil || session.remote != nil {
		t.Fatal("SSU2 session retained cipher or endpoint state after close/receive race")
	}

	send, err = ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receive, err = ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	sendSession := &ssu2TransportSession{
		peer: ivnp.Hash{1}, sendID: 9, receiveID: 10, remote: remote,
		send: send, receive: receive, nextPacket: 2,
		sent:      map[uint32]*ssu2SentPacket{1: {payload: append([]byte(nil), payload...), sentAt: time.Time{}}},
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	activeManager := &SSU2Manager{
		started: true, ctx: context.Background(),
		sessionsByPeer: map[ivnp.Hash]*ssu2TransportSession{sendSession.peer: sendSession},
		sessionsByID:   map[uint64]*ssu2TransportSession{sendSession.receiveID: sendSession},
		bindings:       TransportBindings{Clock: WallClock{}},
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		_ = activeManager.sendSessionDataTo(sendSession, remote, payload)
	}()
	go func() {
		defer wg.Done()
		_ = activeManager.retransmitOne(sendSession, time.Now().Add(ssu2RetransmitInterval))
	}()
	go func() {
		defer wg.Done()
		sendSession.ReleaseSensitive()
	}()
	wg.Wait()
	if sendSession.send != nil || sendSession.receive != nil {
		t.Fatal("SSU2 session retained cipher state after close/send/retransmit race")
	}
}

func TestSSU2SessionReleaseWaitsForAuthenticatedDispatch(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	header1 := bytes.Repeat([]byte{5}, 32)
	header2 := bytes.Repeat([]byte{6}, 32)
	sealer, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	message := managerHotPathMessage()
	var frame [ssu2.MaxIPv4PacketLen]byte
	payload, err := marshalSSU2I2NPTo(frame[:], message)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealer.SealDataTo(make([]byte, ssu2.MaxIPv4PacketLen), ssu2.ShortHeader{
		DestinationID: 17, PacketNumber: 1, Type: ssu2.Data,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	resume := make(chan struct{})
	manager := &SSU2Manager{
		ctx: context.Background(),
		bindings: TransportBindings{
			Clock: WallClock{},
			HandleI2NPContext: func(context.Context, ivnp.Hash, i2np.Message, uint64, bool) error {
				close(entered)
				<-resume
				return nil
			},
		},
	}
	session := &ssu2TransportSession{
		receiveID: 17, receive: receiver, sent: make(map[uint32]*ssu2SentPacket),
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	receiveDone := make(chan struct{})
	go func() {
		manager.handleDataFrom(session, packet, netip.AddrPort{})
		close(receiveDone)
	}()
	<-entered
	releaseDone := make(chan struct{})
	go func() {
		session.ReleaseSensitive()
		close(releaseDone)
	}()
	select {
	case <-releaseDone:
		t.Fatal("session release passed an in-flight authenticated dispatch")
	case <-time.After(25 * time.Millisecond):
	}
	close(resume)
	select {
	case <-receiveDone:
	case <-time.After(time.Second):
		t.Fatal("authenticated dispatch did not finish")
	}
	select {
	case <-releaseDone:
	case <-time.After(time.Second):
		t.Fatal("session release did not finish after dispatch")
	}
	if session.receive != nil {
		t.Fatal("session receive cipher survived terminal release")
	}
}

func TestSSU2EstablishReleasesEvictedIdleSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	send, err := ssu2.NewDataCipher(key, key, key)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := ssu2.NewDataCipher(key, key, key)
	if err != nil {
		t.Fatal(err)
	}
	peer := ivnp.Hash{3}
	stale := &ssu2TransportSession{
		peer: peer, sendID: 1, receiveID: 2, send: send, receive: receive,
		lastActivity: time.Now().Add(-time.Hour), sent: make(map[uint32]*ssu2SentPacket),
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	manager := &SSU2Manager{
		started: true, ctx: context.Background(), idleTimeout: time.Second,
		bindings:       TransportBindings{Clock: WallClock{}},
		sessionsByPeer: map[ivnp.Hash]*ssu2TransportSession{peer: stale},
		sessionsByID:   map[uint64]*ssu2TransportSession{stale.receiveID: stale},
		outbound:       make(map[ivnp.Hash]*ssu2OutboundPending),
		outboundAddr:   make(map[netip.AddrPort]*ssu2OutboundPending),
	}
	if _, err = manager.establish(context.Background(), peer); !errors.Is(err, ErrSSU2Session) {
		t.Fatalf("establish without database = %v, want ErrSSU2Session", err)
	}
	if stale.send != nil || stale.receive != nil {
		t.Fatal("idle session eviction retained transport ciphers")
	}
}

func TestSSU2OutboundInitiatorCannotBeSupersededOrReleasedDuringParse(t *testing.T) {
	remoteStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var intro [32]byte
	if _, err = rand.Read(intro[:]); err != nil {
		t.Fatal(err)
	}
	initiator, err := ssu2.NewInitiator(remoteStatic.PublicKey().Bytes(), intro[:], 11, 12)
	if err != nil {
		t.Fatal(err)
	}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:32001"))
	peer := ivnp.Hash{7}
	pending := &ssu2OutboundPending{
		peer: peer, remote: remote, initiator: initiator,
		destinationID: 11, sourceID: 12, ready: make(chan struct{}),
	}
	endpoint, _ := addrPortKey(remote)
	manager := &SSU2Manager{
		started: true, ctx: context.Background(),
		outbound:     map[ivnp.Hash]*ssu2OutboundPending{peer: pending},
		outboundAddr: map[netip.AddrPort]*ssu2OutboundPending{endpoint: pending},
		bindings:     TransportBindings{Clock: WallClock{}},
	}
	manager.sendSessionRequest(pending, 1)
	if pending.initiator != initiator {
		t.Fatal("SessionRequest transition superseded the one pending Initiator")
	}

	pending.parseMu.Lock()
	released := make(chan struct{})
	go func() {
		manager.failOutbound(pending, ErrSSU2Session)
		close(released)
	}()
	select {
	case <-released:
		t.Fatal("pending Initiator released while parse ownership was held")
	case <-time.After(20 * time.Millisecond):
	}
	if pending.initiator == nil {
		t.Fatal("pending Initiator was cleared before parse completed")
	}
	pending.parseMu.Unlock()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("pending Initiator release did not complete after parse ownership ended")
	}
	if pending.initiator != nil {
		t.Fatal("terminal pending state retained its Initiator")
	}
}

func TestSSU2RetryTokensAreStatelessAndEndpointBound(t *testing.T) {
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intro := make([]byte, 32)
	if _, err = rand.Read(intro); err != nil {
		t.Fatal(err)
	}
	lifetime := 7 * time.Minute
	manager, err := NewSSU2Manager(SSU2ManagerConfig{StaticPrivate: static.Bytes(), IntroKey: intro, TokenLifetime: lifetime})
	if err != nil {
		t.Fatal(err)
	}
	if manager.tokenLifetime != lifetime {
		t.Fatalf("token lifetime = %v, want %v", manager.tokenLifetime, lifetime)
	}
	manager.mu.Lock()
	manager.bindings.Clock = WallClock{}
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	token, err := manager.newTokenLocked(remote, 1, 2)
	if err != nil || token == 0 {
		manager.mu.Unlock()
		t.Fatalf("new retry token = %d, %v", token, err)
	}
	if !manager.consumeTokenLocked(token, remote, 1, 2) {
		manager.mu.Unlock()
		t.Fatal("fresh retry token was rejected")
	}
	if manager.consumeTokenLocked(token, &net.UDPAddr{IP: remote.IP, Port: 1235}, 1, 2) {
		manager.mu.Unlock()
		t.Fatal("retry token was accepted from another endpoint")
	}
	if manager.consumeTokenLocked(token, remote, 2, 1) {
		manager.mu.Unlock()
		t.Fatal("retry token was accepted for other connection IDs")
	}
	manager.mu.Unlock()
}
func TestValidateSSU2ConfirmedPayloadInflatesGzipRouterInfo(t *testing.T) {
	owner, static, intro := newSSU2TestLocal(t, "127.0.0.1:1")
	compressed := gzipSSU2TestBytes(t, owner.Snapshot().Bytes())
	data := append([]byte{2, 1}, compressed...)
	payload, err := ssu2.MarshalBlock(nil, ssu2.BlockRouterInfo, data)
	if err != nil {
		t.Fatal(err)
	}
	info, gotIntro, err := validateSSU2ConfirmedPayload(payload, ecdhPublic(static))
	if err != nil || info.Hash() != owner.Hash() || !bytes.Equal(gotIntro, intro) {

		t.Fatalf("gzip RouterInfo = %s, %x, %v", info.Hash(), gotIntro, err)
	}

	oversized := append([]byte{2, 1}, gzipSSU2TestBytes(t, make([]byte, netdb.MaxRouterInfoBytes+1))...)
	payload, err = ssu2.MarshalBlock(nil, ssu2.BlockRouterInfo, oversized)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = validateSSU2ConfirmedPayload(payload, ecdhPublic(static)); err == nil {
		t.Fatal("oversized gzip RouterInfo was accepted")
	}
}

func gzipSSU2TestBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func newSSU2TestLocal(t *testing.T, endpoint string) (*LocalRouterInfo, []byte, []byte) {
	t.Helper()
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intro := make([]byte, 32)
	if _, err = rand.Read(intro); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "host", Value: host},
			{Key: "i", Value: ivnp.EncodeI2PBase64(intro)},
			{Key: "port", Value: port},
			{Key: "s", Value: ivnp.EncodeI2PBase64(static.PublicKey().Bytes())},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(ReachabilityReachable)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	return owner, static.Bytes(), intro
}
