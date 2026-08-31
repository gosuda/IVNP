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
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/transport/ssu2"
)

type recoverableEgressBatchConn struct {
	writes atomic.Uint32
	err    error
}

func (c *recoverableEgressBatchConn) ReadBatch(*ssu2.Batch) (int, error) {
	return 0, net.ErrClosed
}

func (c *recoverableEgressBatchConn) WriteBatchPrefix(_ *ssu2.Batch, count int) (int, error) {
	if c.writes.Add(1) == 1 {
		return 0, c.err
	}
	return count, nil
}

func (c *recoverableEgressBatchConn) KernelDrops() uint64 { return 0 }
func (c *recoverableEgressBatchConn) Close() error        { return nil }

func TestSSU2I2NPFragmentsStartAtJavaMinimumMTU(t *testing.T) {
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: 1, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 2_000),
	}
	var frame [ssu2.MaxIPv4PacketLen]byte
	fragments, finalFragments := 0, 0
	err := forEachSSU2I2NPFragment(frame[:], message, ssu2MinimumIPv4PacketSize, func(fragment []byte, last bool) error {
		fragments++
		if last {
			finalFragments++
		}
		packetSize := ssu2.ShortHeaderLen + len(fragment) + ssu2.PacketTagLen
		if packetSize > ssu2MinimumIPv4PacketSize {
			t.Fatalf("fragment packet size = %d, max %d", packetSize, ssu2MinimumIPv4PacketSize)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fragments < 2 {
		t.Fatalf("fragment count = %d, want at least 2", fragments)
	}
	if finalFragments != 1 {
		t.Fatalf("final fragment markers = %d, want 1", finalFragments)
	}
	ipv6 := &ssu2TransportSession{remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:1234"))}
	if size := ssu2SessionPacketSize(ipv6); size != ssu2MinimumIPv6PacketSize {
		t.Fatalf("IPv6 packet size = %d, want %d", size, ssu2MinimumIPv6PacketSize)
	}
}
func TestSSU2ImmediateACKPolicyUsesRemainingWindow(t *testing.T) {
	session := &ssu2TransportSession{sendWindowBytes: 3 * ssu2MinimumNetworkMTU}
	session.sendWindowRemaining = session.sendWindowBytes / 3
	if session.shouldRequestImmediateACKLocked() {
		t.Fatal("window boundary requested an immediate ACK")
	}
	session.sendWindowRemaining--
	if !session.shouldRequestImmediateACKLocked() {
		t.Fatal("congested window did not request an immediate ACK")
	}
}

func TestSSU2AcknowledgementGrowsWindowAndProbesMTU(t *testing.T) {
	session := new(ssu2TransportSession)
	session.initReliability(ssu2MaximumNetworkMTU)
	sentAt := time.Unix(1, 0)
	sent := session.retainPayload([]byte("tracked packet"), sentAt)
	sent.windowBytes = ssu2MinimumNetworkMTU
	sent.packetSize = ssu2MinimumNetworkMTU
	sent.latestPacket = 1
	session.sent[1] = sent
	session.sendWindowRemaining -= sent.windowBytes
	session.packetsTransmitted = 1

	session.acknowledge([]ssu2.ACKRange{{Start: 1, End: 1}}, sentAt.Add(100*time.Millisecond))
	if session.sendWindowBytes != 4*ssu2MinimumNetworkMTU || session.sendWindowRemaining != session.sendWindowBytes {
		t.Fatalf("ACK window = %d/%d", session.sendWindowRemaining, session.sendWindowBytes)
	}
	if mtu := session.mtu.Load(); mtu != ssu2MinimumNetworkMTU+ssu2MTUStep {
		t.Fatalf("ACK MTU = %d, want %d", mtu, ssu2MinimumNetworkMTU+ssu2MTUStep)
	}
	if session.rto != ssu2RetransmitInterval {
		t.Fatalf("ACK RTO = %s, want %s", session.rto, ssu2RetransmitInterval)
	}
	if len(session.sent) != 0 {
		t.Fatalf("ACK retained %d packets", len(session.sent))
	}
}

func TestSSU2AcknowledgementAccountsRetransmissionAliasesOnce(t *testing.T) {
	session := new(ssu2TransportSession)
	session.initReliability(ssu2MaximumNetworkMTU)
	sent := session.retainPayload([]byte("retransmitted packet"), time.Unix(1, 0))
	sent.windowBytes = ssu2MinimumNetworkMTU
	sent.packetSize = ssu2MinimumNetworkMTU
	sent.latestPacket = 2
	sent.attempts = 1
	session.sent[1] = sent
	session.sent[2] = sent
	session.sendWindowRemaining = 0

	session.acknowledge([]ssu2.ACKRange{{Start: 1, End: 2}}, time.Unix(2, 0))
	if session.sendWindowRemaining != ssu2MinimumNetworkMTU {
		t.Fatalf("aliased ACK restored %d bytes, want %d", session.sendWindowRemaining, ssu2MinimumNetworkMTU)
	}
	if len(session.sent) != 0 || sent.inUse {
		t.Fatalf("aliased ACK retained map=%d inUse=%t", len(session.sent), sent.inUse)
	}
}

func TestSSU2RetransmissionContractsWindowAndMTU(t *testing.T) {
	session := new(ssu2TransportSession)
	session.initReliability(ssu2MaximumNetworkMTU)
	session.mtu.Store(ssu2MinimumNetworkMTU + ssu2MTUStep)
	session.sendWindowBytes = 4 * ssu2MinimumNetworkMTU
	session.sendWindowRemaining = 1_000
	session.packetsTransmitted = 10
	sent := &ssu2SentPacket{packetSize: ssu2MinimumNetworkMTU + ssu2MTUStep}

	session.noteCongestionLocked(time.Unix(1, 0), sent)
	if session.sendWindowBytes != ssu2MaximumNetworkMTU || session.sendWindowRemaining != 1_000 {
		t.Fatalf("congested window = %d/%d", session.sendWindowRemaining, session.sendWindowBytes)
	}
	if session.rto != 2*ssu2RetransmitInterval {
		t.Fatalf("congested RTO = %s, want %s", session.rto, 2*ssu2RetransmitInterval)
	}
	if mtu := session.mtu.Load(); mtu != ssu2MinimumNetworkMTU {
		t.Fatalf("congested MTU = %d, want %d", mtu, ssu2MinimumNetworkMTU)
	}
}

func TestSSU2SessionConfirmedFragmentsUseJavaAdvertisedMTU(t *testing.T) {
	routerInfo := bytes.Repeat([]byte{0x5a}, 1_400)
	routerInfo[0], routerInfo[1] = 0, 1
	payload, err := ssu2.MarshalBlock(nil, ssu2.BlockRouterInfo, routerInfo)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		remote     *net.UDPAddr
		networkMTU int
		maxPacket  int
	}{
		{name: "IPv4 default", remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1234")), maxPacket: ssu2MaximumNetworkMTU - 20 - 8},
		{name: "IPv6 default", remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:1234")), maxPacket: ssu2MaximumNetworkMTU - 40 - 8},
		{name: "IPv4 advertised", remote: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1234")), networkMTU: 1360, maxPacket: 1360 - 20 - 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initiator, staticPrivate := newSSU2ConfirmedInitiator(t)
			packets, buildErr := buildSSU2SessionConfirmedFragments(&ssu2OutboundPending{
				initiator: initiator,
				remote:    test.remote,
				address:   ssu2PeerAddress{mtu: test.networkMTU},
			}, staticPrivate, payload)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if len(packets) < 2 {
				t.Fatalf("fragment count = %d, want at least 2", len(packets))
			}
			for index, packet := range packets {
				if len(packet) > test.maxPacket {
					t.Fatalf("fragment %d size = %d, max %d", index, len(packet), test.maxPacket)
				}
			}
		})
	}
}

func newSSU2ConfirmedInitiator(t *testing.T) (*ssu2.Initiator, []byte) {
	t.Helper()
	curve := ecdh.X25519()
	remoteStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	localStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intro := bytes.Repeat([]byte{0x33}, 32)
	initiator, err := ssu2.NewInitiator(remoteStatic.PublicKey().Bytes(), intro, 11, 12)
	if err != nil {
		t.Fatal(err)
	}
	requestPayload, err := ssu2DateTimePayload(time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	request, err := initiator.BuildSessionRequest(make([]byte, ssu2.MaxIPv4PacketLen), requestPayload, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, _, _, err := ssu2.ParseSessionRequest(append([]byte(nil), request...), remoteStatic.Bytes(), intro)
	if err != nil {
		t.Fatal(err)
	}
	createdPayload, err := ssu2DateTimePayload(time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	created, err := responder.BuildSessionCreated(make([]byte, ssu2.MaxIPv4PacketLen), createdPayload, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = initiator.ParseSessionCreated(append([]byte(nil), created...)); err != nil {
		t.Fatal(err)
	}
	return initiator, localStatic.Bytes()
}

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
	database := netdb.NewDatabase(foundation.Hash{}, 16)
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
	manager := &SSU2Manager{routerInfoStores: make(map[foundation.Hash]ssu2RouterInfoStoreSnapshot)}

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
			{Key: "i", Value: foundation.EncodeI2PBase64(intro)},
			{Key: "port", Value: "23457"},
			{Key: "s", Value: foundation.EncodeI2PBase64(private.PublicKey().Bytes())},
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
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, _ i2np.Message, nowMillis uint64, _ bool) error {
			deliveredAt = nowMillis
			return nil
		},
	}}
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: uint64(now.Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 12),
	}
	if err := manager.dispatchI2NP(foundation.Hash{1}, message); err != nil {
		t.Fatalf("dispatch current I2NP: %v", err)
	}
	if deliveredAt != uint64(now.UnixMilli()) {
		t.Fatalf("dispatch now = %d, want %d", deliveredAt, now.UnixMilli())
	}

	service := NewService(netdb.NewDatabase(foundation.Hash{}, 16))
	manager = &SSU2Manager{ctx: context.Background(), bindings: TransportBindings{
		Clock: fixedClock{now: now},
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message i2np.Message, nowMillis uint64, floodfill bool) error {
			return service.HandleI2NP(message, nowMillis, floodfill)
		},
	}}
	message.Header.ID++
	message.Header.Expiration = uint64(now.Add(-time.Duration(i2npMessageClockSkewMillis+1) * time.Millisecond).UnixMilli())
	if err := manager.dispatchI2NP(foundation.Hash{1}, message); err != ErrExpired {
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
	ctx := t.Context()

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
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message i2np.Message, nowMillis uint64, _ bool) error {
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
		HandleI2NPContext: func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error {
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
		expiration, ok := i2np.EncodeTransportExpiration(message.Header.Expiration)
		if !ok {
			t.Fatal("test expiration is not encodable")
		}
		if got.Header.Type != message.Header.Type || got.Header.ID != message.Header.ID || got.Header.Expiration != i2np.DecodeTransportExpiration(expiration) {
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
	ctx := t.Context()
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
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message i2np.Message, now uint64, floodfill bool) error {
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
	published := alice.Snapshot().Published
	waitForSSU2Live(t, time.Second, func() bool {
		return uint64(time.Now().UnixMilli()) > published
	}, "new RouterInfo publication timestamp")
	if err = alice.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "i", Value: foundation.EncodeI2PBase64(aliceIntro)},
			{Key: "s", Value: foundation.EncodeI2PBase64(testECDHPublic(t, aliceStatic))},
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
			{Key: "i", Value: foundation.EncodeI2PBase64(charlieIntro)},
			{Key: "ih0", Value: foundation.EncodeI2PBase64(bobHash[:])},
			{Key: "itag0", Value: "270544960"},
			{Key: "s", Value: foundation.EncodeI2PBase64(testECDHPublic(t, charlieStatic))},
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

func waitForSSU2SentPackets(manager *SSU2Manager, peer foundation.Hash, timeout time.Duration) bool {
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
	var peer foundation.Hash
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
	session.sent[1] = &ssu2SentPacket{sentAt: now.Add(-ssu2RetransmitInterval), latestPacket: 1, attempts: ssu2MaxRetransmits, inUse: true}
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
		peer: foundation.Hash{1}, sendID: 9, receiveID: 10, remote: remote,
		send: send, receive: receive, nextPacket: 2,
		sent:      map[uint32]*ssu2SentPacket{1: {payload: append([]byte(nil), payload...), sentAt: time.Time{}}},
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	activeManager := &SSU2Manager{
		started: true, ctx: context.Background(),
		sessionsByPeer: map[foundation.Hash]*ssu2TransportSession{sendSession.peer: sendSession},
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

func TestSSU2ReplayDropsACKAndPathChallengeBlocks(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	header1 := bytes.Repeat([]byte{2}, 32)
	header2 := bytes.Repeat([]byte{3}, 32)
	sealer, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := ssu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := ssu2.MarshalACKRanges(nil, []ssu2.ACKRange{{Start: 7, End: 7}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ssu2.MarshalBlock(nil, ssu2.BlockACK, ack)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = ssu2.MarshalPathChallengeBlock(payload, ssu2.PathChallenge{Data: [8]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealer.SealDataTo(make([]byte, ssu2.MaxIPv4PacketLen), ssu2.ShortHeader{
		DestinationID: 17, PacketNumber: 1, Type: ssu2.Data,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	expected := netip.MustParseAddrPort("127.0.0.1:12345")
	session := &ssu2TransportSession{
		receiveID: 17,
		receive:   receiver,
		remote:    net.UDPAddrFromAddrPort(expected),
		sent:      map[uint32]*ssu2SentPacket{7: {inUse: true}},
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	manager := &SSU2Manager{bindings: TransportBindings{Clock: WallClock{}}}
	manager.handleDataFrom(session, append([]byte(nil), packet...), expected)
	if len(session.sent) != 0 {
		t.Fatal("new packet did not apply its ACK block")
	}

	session.sent[7] = &ssu2SentPacket{inUse: true}
	replaySource := netip.MustParseAddrPort("127.0.0.1:12346")
	manager.handleDataFrom(session, append([]byte(nil), packet...), replaySource)
	if len(session.sent) != 1 {
		t.Fatal("replayed ACK block changed send state")
	}
	session.pathMu.Lock()
	candidate := session.candidate
	session.pathMu.Unlock()
	if candidate != nil {
		t.Fatal("replayed PathChallenge created a migration candidate")
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
			HandleI2NPContext: func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error {
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
	peer := foundation.Hash{3}
	stale := &ssu2TransportSession{
		peer: peer, sendID: 1, receiveID: 2, send: send, receive: receive,
		lastActivity: time.Now().Add(-time.Hour), sent: make(map[uint32]*ssu2SentPacket),
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	manager := &SSU2Manager{
		started: true, ctx: context.Background(), idleTimeout: time.Second,
		bindings:       TransportBindings{Clock: WallClock{}},
		sessionsByPeer: map[foundation.Hash]*ssu2TransportSession{peer: stale},
		sessionsByID:   map[uint64]*ssu2TransportSession{stale.receiveID: stale},
		outbound:       make(map[foundation.Hash]*ssu2OutboundPending),
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
	peer := foundation.Hash{7}
	pending := &ssu2OutboundPending{
		peer: peer, remote: remote, initiator: initiator,
		destinationID: 11, sourceID: 12, ready: make(chan struct{}),
	}
	endpoint, _ := addrPortKey(remote)
	manager := &SSU2Manager{
		started: true, ctx: context.Background(),
		outbound:     map[foundation.Hash]*ssu2OutboundPending{peer: pending},
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
	info, gotIntro, err := validateSSU2ConfirmedPayload(payload, testECDHPublic(t, static))
	if err != nil || info.Hash() != owner.Hash() || !bytes.Equal(gotIntro, intro) {

		t.Fatalf("gzip RouterInfo = %s, %x, %v", info.Hash(), gotIntro, err)
	}

	oversized := append([]byte{2, 1}, gzipSSU2TestBytes(t, make([]byte, netdb.MaxRouterInfoBytes+1))...)
	payload, err = ssu2.MarshalBlock(nil, ssu2.BlockRouterInfo, oversized)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = validateSSU2ConfirmedPayload(payload, testECDHPublic(t, static)); err == nil {
		t.Fatal("oversized gzip RouterInfo was accepted")
	}
}

func TestLocalConfirmedPayloadCompressesFragmentedRouterInfo(t *testing.T) {
	options := make([]MappingOption, 12)
	for index := range options {
		options[index] = MappingOption{
			Key:   string([]byte{'a', byte('a' + index)}),
			Value: string(bytes.Repeat([]byte{'z'}, 80)),
		}
	}
	owner, static, intro := newSSU2TestLocal(t, "127.0.0.1:1", options...)
	manager := &SSU2Manager{
		staticPrivate: static,
		introKey:      intro,
		bindings:      TransportBindings{LocalInfo: owner},
	}
	payload, err := manager.localConfirmedPayload(ssu2.MinPacketLen)
	if err != nil {
		t.Fatal(err)
	}
	iterator := ssu2.NewBlockIterator(payload)
	block, ok, err := iterator.Next()
	if err != nil || !ok || block.Type != ssu2.BlockRouterInfo {
		t.Fatalf("confirmed RouterInfo block = %d, %t, %v", block.Type, ok, err)
	}
	if len(block.Data) < 3 || block.Data[0]&2 == 0 {
		t.Fatal("fragmented SessionConfirmed RouterInfo was not gzip-compressed")
	}
	raw, err := inflateSSU2RouterInfo(block.Data[2:])
	if err != nil || !bytes.Equal(raw, owner.Snapshot().Bytes()) {
		t.Fatalf("compressed RouterInfo round trip = %d bytes, %v", len(raw), err)
	}
}

func TestSSU2EgressBackpressuresWhenSlotsAreBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		free := make(chan *ssu2EgressSlot, 1)
		free <- &ssu2EgressSlot{done: make(chan error, 1)}
		queue := make(chan *ssu2EgressSlot, 1)
		manager := &SSU2Manager{
			started:     true,
			ctx:         ctx,
			egressFree:  free,
			egressQueue: queue,
		}
		remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234"))
		firstResult := make(chan error, 1)
		go func() { firstResult <- manager.writeTo([]byte{1}, remote) }()
		first := <-queue

		secondResult := make(chan error, 1)
		go func() { secondResult <- manager.writeTo([]byte{2}, remote) }()
		synctest.Wait()
		select {
		case err := <-secondResult:
			t.Fatalf("second write returned instead of applying backpressure: %v", err)
		default:
		}

		first.done <- nil
		if err := <-firstResult; err != nil {
			t.Fatalf("first write: %v", err)
		}
		second := <-queue
		second.done <- nil
		if err := <-secondResult; err != nil {
			t.Fatalf("second write: %v", err)
		}
		if dropped := manager.IOStats().Dropped; dropped != 0 {
			t.Fatalf("backpressured writes counted as dropped: %d", dropped)
		}
	})
}

func TestSSU2EgressContinuesAfterDestinationWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	free := make(chan *ssu2EgressSlot, 2)
	for range 2 {
		free <- &ssu2EgressSlot{done: make(chan error, 1)}
	}
	writeErr := errors.New("destination unavailable")
	manager := &SSU2Manager{
		started:     true,
		ctx:         ctx,
		batchConn:   &recoverableEgressBatchConn{err: writeErr},
		egressFree:  free,
		egressQueue: make(chan *ssu2EgressSlot, 2),
	}
	manager.wg.Add(1)
	go manager.egressLoop()
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234"))
	if err := manager.writeTo([]byte{1}, remote); !errors.Is(err, writeErr) {
		t.Fatalf("first write = %v, want %v", err, writeErr)
	}
	if err := manager.writeTo([]byte{2}, remote); err != nil {
		t.Fatalf("write after destination error = %v", err)
	}
	cancel()
	manager.wg.Wait()
}

func TestSSU2CanceledEgressConsumesSealedPacketNumber(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		send, err := ssu2.NewDataCipher(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
		if err != nil {
			t.Fatal(err)
		}
		peer := foundation.Hash{1}
		session := &ssu2TransportSession{
			peer:         peer,
			sendID:       9,
			receiveID:    10,
			remote:       net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234")),
			send:         send,
			nextPacket:   1,
			lastActivity: time.Now(),
		}
		session.initReliability(ssu2MaximumNetworkMTU)
		managerCtx, stopManager := context.WithCancel(t.Context())
		defer stopManager()
		manager := &SSU2Manager{
			started:        true,
			ctx:            managerCtx,
			idleTimeout:    time.Hour,
			sessionsByPeer: map[foundation.Hash]*ssu2TransportSession{peer: session},
			sessionsByID:   map[uint64]*ssu2TransportSession{session.receiveID: session},
			bindings:       TransportBindings{Clock: WallClock{}},
			egressFree:     make(chan *ssu2EgressSlot),
			egressQueue:    make(chan *ssu2EgressSlot, 1),
		}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			result <- manager.Send(ctx, peer, managerHotPathMessage())
		}()
		synctest.Wait()

		cancel()
		synctest.Wait()
		if err = <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled send = %v, want %v", err, context.Canceled)
		}
		if session.nextPacket != 2 {
			t.Fatalf("canceled sealed packet left next packet at %d, want 2", session.nextPacket)
		}
		if session.packetsTransmitted != 0 {
			t.Fatalf("canceled egress counted %d transmitted packets", session.packetsTransmitted)
		}
		if session.sendWindowRemaining != session.sendWindowBytes || len(session.sent) != 0 {
			t.Fatalf("canceled egress retained window %d/%d or %d packets", session.sendWindowRemaining, session.sendWindowBytes, len(session.sent))
		}
		if queued := len(manager.egressQueue); queued != 0 {
			t.Fatalf("canceled send queued %d datagrams", queued)
		}
	})
}

func TestSSU2SendWaitsForWindowAndResumesAfterACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		sentAt := time.Unix(1, 0)
		sent := session.retainPayload([]byte("previous packet"), sentAt)
		sent.windowBytes = ssu2MinimumNetworkMTU
		sent.packetSize = ssu2MinimumNetworkMTU
		sent.latestPacket = 1
		session.sent[1] = sent
		session.sendWindowRemaining = 0
		session.nextPacket = 2

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- manager.sendDataContext(ctx, session, bytes.Repeat([]byte{1}, 8))
		}()
		synctest.Wait()
		if queued := len(manager.egressQueue); queued != 0 {
			t.Fatalf("window-exhausted send queued %d datagrams", queued)
		}
		if !session.sendMu.TryLock() {
			t.Fatal("window-exhausted send retained sendMu")
		}
		session.sendMu.Unlock()

		session.acknowledge([]ssu2.ACKRange{{Start: 1, End: 1}}, sentAt.Add(time.Millisecond))
		synctest.Wait()
		slot := <-manager.egressQueue
		slot.done <- nil
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("ACK-resumed send = %v", err)
		}
	})
}

func TestSSU2SessionReleaseWakesWindowBlockedSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		session.sendWindowRemaining = 0
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- manager.Send(ctx, session.peer, managerHotPathMessage())
		}()
		synctest.Wait()

		removed := make(chan struct{})
		go func() {
			manager.removeSession(session)
			close(removed)
		}()
		synctest.Wait()
		select {
		case <-removed:
		default:
			cancel()
			synctest.Wait()
			t.Fatal("session release remained blocked behind a window waiter")
		}
		if err := <-result; !errors.Is(err, ErrSSU2Session) {
			t.Fatalf("released session send = %v, want %v", err, ErrSSU2Session)
		}
	})
}

func TestSSU2ReleaseWakesSaturatedReliableControlHoldingLifetimeRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		for range ssu2MaxTrackedPackets {
			if retained := session.retainPayload([]byte("saturated"), time.Unix(1, 0)); retained == nil {
				t.Fatal("failed to saturate retained payload slots")
			}
		}

		result := make(chan error, 1)
		go func() {
			session.lifetimeMu.RLock()
			err := manager.sendSessionData(session, bytes.Repeat([]byte{4}, 8), true)
			session.lifetimeMu.RUnlock()
			result <- err
		}()
		synctest.Wait()

		released := make(chan struct{})
		go func() {
			session.ReleaseSensitive()
			close(released)
		}()
		synctest.Wait()
		select {
		case <-released:
		default:
			t.Fatal("release remained blocked behind a lifetime-held retained-slot waiter")
		}
		if err := <-result; !errors.Is(err, ErrSSU2Session) {
			t.Fatalf("released reliable control send = %v, want %v", err, ErrSSU2Session)
		}
	})
}

func TestSSU2ACKProceedsWhileEgressCompletionIsPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- manager.sendDataContext(ctx, session, bytes.Repeat([]byte{2}, 8))
		}()
		synctest.Wait()
		slot := <-manager.egressQueue
		if !session.sendMu.TryLock() {
			t.Fatal("egress completion wait retained sendMu")
		}
		session.sendMu.Unlock()

		session.acknowledge([]ssu2.ACKRange{{Start: 1, End: 1}}, time.Now())
		if len(session.sent) != 0 {
			t.Fatalf("ACK during egress retained %d packets", len(session.sent))
		}
		slot.done <- nil
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("egress-completed send = %v", err)
		}
	})
}

func TestSSU2PacketNumberAliasesDoNotExhaustRetainedPayloadSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		sent := session.retainPayload([]byte("aliased packet"), time.Unix(1, 0))
		sent.latestPacket = ssu2MaxTrackedPackets
		for packetNumber := uint32(1); packetNumber <= ssu2MaxTrackedPackets; packetNumber++ {
			session.sent[packetNumber] = sent
		}
		session.nextPacket = ssu2MaxTrackedPackets + 1

		result := make(chan error, 1)
		go func() {
			result <- manager.sendSessionDataContext(t.Context(), session, bytes.Repeat([]byte{3}, 8), ssu2SessionDataOptions{
				reliable:   true,
				waitEgress: true,
			})
		}()
		synctest.Wait()
		slot := <-manager.egressQueue
		slot.done <- nil
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatalf("send with packet aliases = %v", err)
		}
		inUse := 0
		for index := range session.sentSlots {
			if session.sentSlots[index].inUse {
				inUse++
			}
		}
		if inUse != 2 {
			t.Fatalf("retained payload slots = %d, want 2", inUse)
		}
	})
}

func TestSSU2EgressCollectsOnlyReadyDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	manager := &SSU2Manager{started: true, ctx: ctx, egressQueue: make(chan *ssu2EgressSlot, ssu2EgressSlots)}
	for index := range 3 {
		manager.egressQueue <- &ssu2EgressSlot{length: index + 1}
	}
	var slots [ssu2EgressSlots]*ssu2EgressSlot
	count, ok := manager.collectEgressBatch(&slots)
	if !ok || count != 3 {
		t.Fatalf("collected batch = (%d, %t), want (3, true)", count, ok)
	}
}

func TestSSU2QueuedWriteReturnsBeforeSocketCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	free := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager := &SSU2Manager{
		started:     true,
		ctx:         ctx,
		egressFree:  free,
		egressQueue: make(chan *ssu2EgressSlot, 1),
	}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234"))
	if err := manager.writeToQueued([]byte{1}, remote); err != nil {
		t.Fatalf("queue write: %v", err)
	}
	slot := <-manager.egressQueue
	if slot.wait {
		t.Fatal("queued write requested synchronous completion")
	}
	slots := []*ssu2EgressSlot{slot}
	manager.completeEgressSlots(slots, 1, nil)
	if available := len(manager.egressFree); available != 1 {
		t.Fatalf("recycled egress slots = %d, want 1", available)
	}
}

func TestSSU2QueuesOnePendingACKPerSession(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	manager := &SSU2Manager{started: true, ctx: ctx, ackQueue: make(chan *ssu2TransportSession, 4)}
	session := new(ssu2TransportSession)
	for range 3 {
		manager.queueACK(session)
	}
	if queued := len(manager.ackQueue); queued != 1 {
		t.Fatalf("queued ACK sessions = %d, want 1", queued)
	}
	if got := <-manager.ackQueue; got != session {
		t.Fatal("ACK queue returned another session")
	}
}

func newSSU2SendTestHarness(t *testing.T) (*SSU2Manager, *ssu2TransportSession) {
	t.Helper()
	send, err := ssu2.NewDataCipher(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{1}
	session := &ssu2TransportSession{
		peer:         peer,
		sendID:       9,
		receiveID:    10,
		remote:       net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234")),
		send:         send,
		nextPacket:   1,
		lastActivity: time.Now(),
	}
	session.initReliability(ssu2MaximumNetworkMTU)
	managerCtx, cancel := context.WithCancel(t.Context())
	free := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager := &SSU2Manager{
		started:        true,
		ctx:            managerCtx,
		idleTimeout:    time.Hour,
		sessionsByPeer: map[foundation.Hash]*ssu2TransportSession{peer: session},
		sessionsByID:   map[uint64]*ssu2TransportSession{session.receiveID: session},
		bindings:       TransportBindings{Clock: WallClock{}},
		egressFree:     free,
		egressQueue:    make(chan *ssu2EgressSlot, 1),
	}
	t.Cleanup(session.ReleaseSensitive)
	t.Cleanup(cancel)
	return manager, session
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

func newSSU2TestLocal(t *testing.T, endpoint string, options ...MappingOption) (*LocalRouterInfo, []byte, []byte) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
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
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []MappingOption{
			{Key: "host", Value: host},
			{Key: "i", Value: foundation.EncodeI2PBase64(intro)},
			{Key: "port", Value: port},
			{Key: "s", Value: foundation.EncodeI2PBase64(static.PublicKey().Bytes())},
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
