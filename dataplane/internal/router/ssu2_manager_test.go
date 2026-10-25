package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"weak"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/simnet"
)

type recoverableEgressBatchConn struct {
	writes atomic.Uint32
	err    error
}

func (c *recoverableEgressBatchConn) ReadBatch(*dataplanessu2.Batch) (int, error) {
	return 0, net.ErrClosed
}

func (c *recoverableEgressBatchConn) WriteBatchPrefix(_ *dataplanessu2.Batch, count int) (int, error) {
	if c.writes.Add(1) == 1 {
		return 0, c.err
	}
	return count, nil
}

func (c *recoverableEgressBatchConn) KernelDrops() uint64 { return 0 }
func (c *recoverableEgressBatchConn) Close() error        { return nil }

func TestSSU2ManagerUnstartedCloseWaitClearsKeys(t *testing.T) {
	staticPrivate := bytes.Repeat([]byte{1}, 32)
	introKey := bytes.Repeat([]byte{2}, 32)
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2,
		StaticPrivate: staticPrivate,
		IntroKey:      introKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownedStatic, ownedIntro := manager.staticPrivate, manager.introKey
	ownedToken := manager.tokenSecret[:]
	if err := manager.Close(); err != nil {
		t.Errorf("close unstarted manager: %v", err)
	}
	if err := manager.Wait(); err != nil {
		t.Errorf("wait for unstarted manager: %v", err)
	}
	for name, secret := range map[string][]byte{
		"static private key": ownedStatic,
		"introduction key":   ownedIntro,
		"token secret":       ownedToken,
	} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Errorf("unstarted manager retained %s", name)
		}
	}
	if !bytes.Equal(staticPrivate, bytes.Repeat([]byte{1}, 32)) ||
		!bytes.Equal(introKey, bytes.Repeat([]byte{2}, 32)) {
		t.Error("manager cleanup overwrote caller-owned keys")
	}
}

func TestSSU2I2NPFragmentsStartAtJavaMinimumMTU(t *testing.T) {
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 1, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 2_000),
	}
	var frame [dataplanessu2.MaxIPv4PacketLen]byte
	fragments, finalFragments := 0, 0
	err := forEachSSU2I2NPFragment(frame[:], message, ssu2MinimumIPv4PacketSize, func(fragment []byte, last bool) error {
		fragments++
		if last {
			finalFragments++
		}
		packetSize := dataplanessu2.ShortHeaderLen + len(fragment) + dataplanessu2.PacketTagLen
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

	session.acknowledge([]dataplanessu2.ACKRange{{Start: 1, End: 1}}, sentAt.Add(100*time.Millisecond))
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

	session.acknowledge([]dataplanessu2.ACKRange{{Start: 1, End: 2}}, time.Unix(2, 0))
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

	session.sendMu.Lock()
	session.noteCongestionLocked(time.Unix(1, 0), sent)
	session.sendMu.Unlock()
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
	payload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockRouterInfo, routerInfo)
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

func newSSU2ConfirmedInitiator(t *testing.T) (*dataplanessu2.Initiator, []byte) {
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
	initiator, err := dataplanessu2.NewInitiator(remoteStatic.PublicKey().Bytes(), intro, 11, 12, 2)
	if err != nil {
		t.Fatal(err)
	}
	requestPayload, err := ssu2DateTimePayload(time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	request, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, _, _, err := dataplanessu2.ParseSessionRequest(append([]byte(nil), request...), remoteStatic.Bytes(), intro, 2)
	if err != nil {
		t.Fatal(err)
	}
	createdPayload, err := ssu2DateTimePayload(time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	created, err := responder.BuildSessionCreated(make([]byte, dataplanessu2.MaxIPv4PacketLen), createdPayload, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = initiator.ParseSessionCreated(append([]byte(nil), created...)); err != nil {
		t.Fatal(err)
	}
	return initiator, localStatic.Bytes()
}

func TestSSU2RouterInfoStorePreservesSignedWireBytes(t *testing.T) {
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
	store, err := foundation.I2NPParseDatabaseStore(first.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Data) < 2 || store.Data[0] != 0x1f || store.Data[1] != 0x8b {
		t.Fatalf("RouterInfo store is not gzip: %x", store.Data[:min(2, len(store.Data))])
	}
	raw, err := inflateSSU2RouterInfo(store.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, local.Snapshot().Bytes()) {
		t.Fatal("RouterInfo store changed the signed advertisement")
	}
}

// +checklocksignore
func TestSSU2RelayRouterInfoStoreCacheReusesAndRefreshesLocalSnapshot(t *testing.T) {
	local, static, intro := newSSU2TestLocal(t, "127.0.0.1:23456")
	now := time.UnixMilli(1_700_000_000_000)
	manager, _ := newSSU2ConfiguredManager(t, nil)

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
	reusedStore, err := foundation.I2NPParseDatabaseStore(reused.Payload)
	if err != nil || !bytes.Equal(reusedStore.Data, sentinel) {
		t.Fatalf("relay store recompressed cached RouterInfo: %x, %v", reusedStore.Data, err)
	}

	private, err := ecdh.X25519().NewPrivateKey(static)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceAddresses([]transportTestAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []transportTestOption{
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
	refreshedStore, err := foundation.I2NPParseDatabaseStore(refreshed.Payload)
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
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.ctx = context.Background()
	manager.bindings = TransportBindings{
		Clock: transportTestClock{now: now},
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, _ foundation.I2NPMessage, nowMillis uint64, _ bool) error {
			deliveredAt = nowMillis
			return nil
		},
	}
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 1, Expiration: uint64(now.Add(time.Minute).UnixMilli())},
		Payload: make([]byte, 12),
	}
	if err := manager.dispatchI2NP(foundation.Hash{1}, message); err != nil {
		t.Fatalf("dispatch current I2NP: %v", err)
	}
	if deliveredAt != uint64(now.UnixMilli()) {
		t.Fatalf("dispatch now = %d, want %d", deliveredAt, now.UnixMilli())
	}

	service := NewService(Sinks{})
	manager, _ = newSSU2ConfiguredManager(t, nil)
	manager.ctx = context.Background()
	manager.bindings = TransportBindings{
		Clock: transportTestClock{now: now},
		HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, floodfill bool) error {
			return service.HandleI2NP(message, nowMillis, floodfill)
		},
	}
	message.Header.ID++
	message.Header.Expiration = uint64(now.Add(-time.Duration(i2npMessageClockSkewMillis+1) * time.Millisecond).UnixMilli())
	if err := manager.dispatchI2NP(foundation.Hash{1}, message); err != ErrExpired {
		t.Fatalf("expired SSU2 I2NP error = %v, want %v", err, ErrExpired)
	}
}

type dropOnceSSU2Conn struct {
	*simnet.UDPConn
	drop atomic.Int32
}

func (c *dropOnceSSU2Conn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c.drop.Load() > 0 && c.drop.Add(-1) >= 0 {
		return len(b), nil
	}
	return c.UDPConn.WriteToUDPAddrPort(b, addr)
}

func TestSSU2ManagerAuthenticatesAndRoutesI2NP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceRawConn := newSSU2SimConn(t, net_, "alice")
		aliceConn := &dropOnceSSU2Conn{UDPConn: aliceRawConn}
		bobConn := newSSU2SimConn(t, net_, "bob")
		ctx := t.Context()

		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		if err := aliceDB.AdmitRouterInfo(bob.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit Bob RouterInfo: %v", err)
		}

		aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: aliceDB, StaticPrivate: aliceStatic, IntroKey: aliceIntro})
		if err != nil {
			t.Fatal(err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		received := make(chan foundation.I2NPMessage, 4)
		var deliveredAt atomic.Uint64
		if err = bobManager.Start(ctx, TransportBindings{
			SSU2:      bobConn,
			LocalInfo: bob,
			Clock:     WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, _ bool) error {
				deliveredAt.Store(nowMillis)
				received <- foundation.I2NPMessage{
					Header:  message.Header,
					Payload: append([]byte(nil), message.Payload...),
				}
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		if err = aliceManager.Start(ctx, TransportBindings{
			SSU2:      aliceConn,
			LocalInfo: alice,
			Clock:     WallClock{},
			HandleI2NPContext: func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error {
				return nil
			},
		}); err != nil {
			_ = bobManager.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		expires := uint64(time.Now().Add(time.Minute).UnixMilli())
		message := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 9, Expiration: expires},
			Payload: make([]byte, 12),
		}
		if err = aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatalf("authenticate SSU2 session: %v", err)
		}
		if err = aliceManager.Send(ctx, bob.Hash(), message); err != nil {
			t.Fatalf("Send over native SSU2: %v", err)
		}
		got := <-received
		expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
		if !ok {
			t.Fatal("test expiration is not encodable")
		}
		if got.Header.Type != message.Header.Type || got.Header.ID != message.Header.ID || got.Header.Expiration != foundation.I2NPDecodeTransportExpiration(expiration) {
			t.Fatalf("received I2NP header = %#v, want %#v", got.Header, message.Header)
		}
		if deliveredAt.Load() == 0 {
			t.Fatal("SSU2 delivery used a zero current time")
		}
		if _, ok := bobDB.RouterInfo(alice.Hash()); !ok {
			t.Fatal("authenticated Alice RouterInfo was not admitted")
		}
		net_.Advance(50 * time.Millisecond)

		largePayload := make([]byte, 4096)
		for index := range largePayload {
			largePayload[index] = byte(index)
		}
		large := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 10, Expiration: expires},
			Payload: largePayload,
		}
		if err = aliceManager.Send(ctx, bob.Hash(), large); err != nil {
			t.Fatalf("Send fragmented native SSU2 message: %v", err)
		}
		got = <-received
		if got.Header.Type != large.Header.Type || got.Header.ID != large.Header.ID || !bytes.Equal(got.Payload, large.Payload) {
			t.Fatalf("received fragmented I2NP = %#v, payload length %d", got.Header, len(got.Payload))
		}
		net_.Advance(50 * time.Millisecond)

		retransmitted := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 11, Expiration: expires},
			Payload: []byte("reliable SSU2 retransmission"),
		}
		aliceConn.drop.Store(1)
		if err = aliceManager.Send(ctx, bob.Hash(), retransmitted); err != nil {
			t.Fatalf("Send retransmitted native SSU2 message: %v", err)
		}
		net_.Advance(ssu2RetransmitInterval + 100*time.Millisecond)
		got = <-received
		if got.Header.ID != retransmitted.Header.ID || !bytes.Equal(got.Payload, retransmitted.Payload) {
			t.Fatalf("received retransmitted I2NP = %#v, %x", got.Header, got.Payload)
		}
		net_.Advance(50 * time.Millisecond)
		if !aliceManager.Status().Running || !bobManager.Status().Running {
			t.Fatal("native SSU2 managers stopped during a live session")
		}
	})
}

func TestSSU2ManagerStagesEarlyPacketsBeforeSessionConfirmed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		ctx := t.Context()

		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobDB := newTransportTestPeers()
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit Alice RouterInfo: %v", err)
		}

		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		received := make(chan foundation.I2NPMessage, 1)
		if err = bobManager.Start(ctx, TransportBindings{
			SSU2:      bobConn,
			LocalInfo: bob,
			Clock:     WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage, _ uint64, _ bool) error {
				received <- foundation.I2NPMessage{
					Header:  message.Header,
					Payload: append([]byte(nil), message.Payload...),
				}
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, bobManager)
		})

		bobPriv, err := ecdh.X25519().NewPrivateKey(bobStatic)
		if err != nil {
			t.Fatal(err)
		}
		bobPub := bobPriv.PublicKey().Bytes()

		initiator, err := dataplanessu2.NewInitiator(bobPub, bobIntro, 100, 200, 2)
		if err != nil {
			t.Fatal(err)
		}
		var dateTime [4]byte
		binary.BigEndian.PutUint32(dateTime[:], uint32(time.Now().Unix()))
		requestPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockDateTime, dateTime[:])
		if err != nil {
			t.Fatal(err)
		}
		requestPayload, err = dataplanessu2.MarshalBlock(requestPayload, dataplanessu2.BlockPadding, nil)
		if err != nil {
			t.Fatal(err)
		}
		bobManager.mu.Lock()
		token, err := bobManager.newTokenLocked(aliceConn.LocalAddr(), 100, 200)
		bobManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		requestPacket, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aliceConn.WriteTo(requestPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		createdBuf := make([]byte, dataplanessu2.MaxIPv4PacketLen)
		n, _, err := aliceConn.ReadFrom(createdBuf)
		if err != nil {
			t.Fatalf("read SessionCreated: %v", err)
		}
		if _, _, err = initiator.ParseSessionCreated(createdBuf[:n]); err != nil {
			t.Fatalf("parse SessionCreated: %v", err)
		}

		aliceRouterInfoBytes := alice.Snapshot().Bytes()
		confirmedPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockRouterInfo, append([]byte{0, 1}, aliceRouterInfoBytes...))
		if err != nil {
			t.Fatal(err)
		}
		confirmedPacket, err := initiator.BuildSessionConfirmed(make([]byte, dataplanessu2.MaxIPv4PacketLen), aliceStatic[:32], confirmedPayload)
		if err != nil {
			t.Fatal(err)
		}

		aliceSend, _, err := initiator.DataCiphers(aliceIntro)
		if err != nil {
			t.Fatal(err)
		}

		i2npPayload := []byte("early 0.5-RTT data payload")
		msg := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 42, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
			Payload: i2npPayload,
		}
		var rawMsg [1024]byte
		dataPayload, err := marshalSSU2I2NPTo(rawMsg[:], msg)
		if err != nil {
			t.Fatalf("marshal I2NP: %v", err)
		}
		dataPacket, err := aliceSend.SealDataTo(make([]byte, dataplanessu2.MaxIPv4PacketLen), dataplanessu2.ShortHeader{
			DestinationID: 100,
			PacketNumber:  1,
			Type:          dataplanessu2.Data,
		}, dataPayload)
		if err != nil {
			t.Fatal(err)
		}

		if _, err = aliceConn.WriteTo(dataPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		select {
		case unexpected := <-received:
			t.Fatalf("early data packet dispatched before SessionConfirmed: %#v", unexpected)
		default:
		}

		if _, err = aliceConn.WriteTo(confirmedPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		got := <-received
		if got.Header.ID != 42 || !bytes.Equal(got.Payload, i2npPayload) {
			t.Fatalf("received I2NP = %#v, %q; want ID 42 and %q", got.Header, got.Payload, i2npPayload)
		}
	})
}

func TestSSU2ManagerCapsStagedEarlyPacketsAtEight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		ctx := t.Context()

		alice, aliceStatic, aliceIntro := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobDB := newTransportTestPeers()
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit Alice RouterInfo: %v", err)
		}

		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		var receivedMu sync.Mutex
		received := make(map[uint32]int)
		if err = bobManager.Start(ctx, TransportBindings{
			SSU2:      bobConn,
			LocalInfo: bob,
			Clock:     WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage, _ uint64, _ bool) error {
				receivedMu.Lock()
				received[message.Header.ID]++
				receivedMu.Unlock()
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, bobManager)
		})

		bobPriv, err := ecdh.X25519().NewPrivateKey(bobStatic)
		if err != nil {
			t.Fatal(err)
		}
		bobPub := bobPriv.PublicKey().Bytes()

		initiator, err := dataplanessu2.NewInitiator(bobPub, bobIntro, 101, 201, 2)
		if err != nil {
			t.Fatal(err)
		}
		var dateTime [4]byte
		binary.BigEndian.PutUint32(dateTime[:], uint32(time.Now().Unix()))
		requestPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockDateTime, dateTime[:])
		if err != nil {
			t.Fatal(err)
		}
		requestPayload, err = dataplanessu2.MarshalBlock(requestPayload, dataplanessu2.BlockPadding, nil)
		if err != nil {
			t.Fatal(err)
		}
		bobManager.mu.Lock()
		token, err := bobManager.newTokenLocked(aliceConn.LocalAddr(), 101, 201)
		bobManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		requestPacket, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aliceConn.WriteTo(requestPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		createdBuf := make([]byte, dataplanessu2.MaxIPv4PacketLen)
		n, _, err := aliceConn.ReadFrom(createdBuf)
		if err != nil {
			t.Fatalf("read SessionCreated: %v", err)
		}
		if _, _, err = initiator.ParseSessionCreated(createdBuf[:n]); err != nil {
			t.Fatalf("parse SessionCreated: %v", err)
		}

		confirmedPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockRouterInfo, append([]byte{0, 1}, alice.Snapshot().Bytes()...))
		if err != nil {
			t.Fatal(err)
		}
		confirmedPacket, err := initiator.BuildSessionConfirmed(make([]byte, dataplanessu2.MaxIPv4PacketLen), aliceStatic[:32], confirmedPayload)
		if err != nil {
			t.Fatal(err)
		}

		aliceSend, _, err := initiator.DataCiphers(aliceIntro)
		if err != nil {
			t.Fatal(err)
		}

		for i := 1; i <= 10; i++ {
			msg := foundation.I2NPMessage{
				Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: uint32(i), Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
				Payload: []byte{byte(i)},
			}
			var rawMsg [256]byte
			dataPayload, err := marshalSSU2I2NPTo(rawMsg[:], msg)
			if err != nil {
				t.Fatal(err)
			}
			dataPacket, err := aliceSend.SealDataTo(make([]byte, dataplanessu2.MaxIPv4PacketLen), dataplanessu2.ShortHeader{
				DestinationID: 101,
				PacketNumber:  uint32(i),
				Type:          dataplanessu2.Data,
			}, dataPayload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = aliceConn.WriteTo(dataPacket, bobConn.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}

		net_.Advance(20 * time.Millisecond)

		if _, err = aliceConn.WriteTo(confirmedPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(50 * time.Millisecond)

		receivedMu.Lock()
		defer receivedMu.Unlock()
		if len(received) != ssu2MaxStagedEarlyPackets {
			t.Fatalf("received %d distinct staged early packets, want %d", len(received), ssu2MaxStagedEarlyPackets)
		}
		for id, count := range received {
			if id < 1 || id > 10 {
				t.Fatalf("delivered message ID %d is outside the sent IDs 1-10", id)
			}
			if count != 1 {
				t.Fatalf("message ID %d was delivered %d times", id, count)
			}
		}
	})
}

func TestSSU2ManagerRelaysIntroductionAndHolePunch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		charlieConn := newSSU2SimConn(t, net_, "charlie")
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
		aliceDB := newTransportTestPeers()
		bobDB := newTransportTestPeers()
		charlieDB := newTransportTestPeers()
		now := uint64(time.Now().UnixMilli())
		for _, admission := range []struct {
			database *transportTestPeers
			info     foundation.NetworkDatabaseRouterInfo
		}{
			{aliceDB, bob.Snapshot()},
			{aliceDB, charlie.Snapshot()},
			{bobDB, alice.Snapshot()},
			{bobDB, charlie.Snapshot()},
			{charlieDB, bob.Snapshot()},
		} {
			if err = admission.database.AdmitRouterInfo(admission.info, now); err != nil {
				t.Fatalf("admit relay RouterInfo: %v", err)
			}
		}
		received := make(chan foundation.I2NPMessage, 4)
		aliceManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: aliceDB, StaticPrivate: aliceStatic,
			IntroKey: aliceIntro,
			SignControl: func(message []byte) ([]byte, error) {
				return alice.Sign(message), nil
			},
			IntroductionEndpoint: func() (netip.AddrPort, error) {
				return aliceEndpoint, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		charlieManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: charlieDB, StaticPrivate: charlieStatic,
			IntroKey: charlieIntro,
			SignControl: func(message []byte) ([]byte, error) {
				return charlie.Sign(message), nil
			},
			IntroductionEndpoint: func() (netip.AddrPort, error) {
				return charlieEndpoint, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		for _, start := range []struct {
			manager *SSU2Manager
			conn    *simnet.UDPConn
			local   *transportTestLocal
			handler func(foundation.I2NPMessage, uint64, bool) error
		}{
			{aliceManager, aliceConn, alice, func(foundation.I2NPMessage, uint64, bool) error { return nil }},
			{bobManager, bobConn, bob, func(foundation.I2NPMessage, uint64, bool) error { return nil }},
			{charlieManager, charlieConn, charlie, func(message foundation.I2NPMessage, nowMillis uint64, _ bool) error {
				if message.Header.Type == foundation.I2NPData {
					received <- foundation.I2NPMessage{
						Header:  message.Header,
						Payload: append([]byte(nil), message.Payload...),
					}
					return nil
				}
				if message.Header.Type == foundation.I2NPDatabaseStore {
					return charlieDB.Store(message, nowMillis)
				}
				return nil
			}},
		} {
			startSSU2SimManager(t, ctx, start.manager, start.conn, start.local, start.handler)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
			closeSSU2LiveManager(t, charlieManager)
		})

		if err = bobManager.EnsureSession(ctx, charlie.Hash()); err != nil {
			t.Fatalf("authenticate Bob-Charlie session: %v", err)
		}
		if err = bobManager.Send(ctx, charlie.Hash(), foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 70, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
			Payload: make([]byte, 12),
		}); err != nil {
			t.Fatalf("establish Bob-Charlie session: %v", err)
		}
		const relayTag = 0x10203040
		bobHash := bob.Hash()
		net_.Advance(20 * time.Millisecond)
		if err = alice.ReplaceAddresses([]transportTestAddress{{
			Transport: "SSU",
			Cost:      3,
			Options: []transportTestOption{
				{Key: "i", Value: foundation.EncodeI2PBase64(aliceIntro)},
				{Key: "s", Value: foundation.EncodeI2PBase64(testECDHPublic(t, aliceStatic))},
				{Key: "v", Value: "2"},
			},
		}}); err != nil {
			t.Fatalf("publish firewalled Alice address: %v", err)
		}
		alice.SetReachability(transportTestFirewalled)
		if err = alice.Publish(ctx); err != nil {
			t.Fatalf("publish firewalled Alice RouterInfo: %v", err)
		}
		if _, err = selectSSU2Address(alice.Snapshot()); err == nil {
			t.Fatal("firewalled Alice RouterInfo retained a direct endpoint")
		}
		net_.Advance(20 * time.Millisecond)
		if err = charlie.ReplaceAddresses([]transportTestAddress{{
			Transport: "SSU",
			Cost:      3,
			Options: []transportTestOption{
				{Key: "i", Value: foundation.EncodeI2PBase64(charlieIntro)},
				{Key: "ih0", Value: foundation.EncodeI2PBase64(bobHash[:])},
				{Key: "itag0", Value: "270544960"},
				{Key: "s", Value: foundation.EncodeI2PBase64(testECDHPublic(t, charlieStatic))},
				{Key: "v", Value: "2"},
			},
		}}); err != nil {
			t.Fatalf("publish firewalled Charlie address: %v", err)
		}
		charlie.SetReachability(transportTestFirewalled)
		if err = charlie.Publish(ctx); err != nil {
			t.Fatalf("publish firewalled Charlie RouterInfo: %v", err)
		}
		if err = aliceDB.AdmitRouterInfo(charlie.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit firewalled Charlie RouterInfo: %v", err)
		}
		if ref, found := aliceDB.Get(charlie.Hash()); !found {
			t.Fatal("firewalled Charlie RouterInfo was not admitted")
		} else if _, err = selectSSU2Address(ref.Info); err == nil {
			t.Fatal("firewalled Charlie RouterInfo retained a direct endpoint")
		}
		if err = bobManager.RegisterIntroducer(relayTag, charlie.Hash()); err != nil {
			t.Fatal(err)
		}
		message := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 71, Expiration: uint64(time.Now().Add(time.Minute).UnixMilli())},
			Payload: []byte("introduced SSU2 session"),
		}
		if err = aliceManager.EnsureSession(ctx, charlie.Hash()); err != nil {
			net_.Advance(50 * time.Millisecond)
			err = aliceManager.EnsureSession(ctx, charlie.Hash())
		}
		if err != nil {
			_, aliceAtCharlie := charlieDB.Get(alice.Hash())
			t.Fatalf("establish introduced SSU2 session: %v (alice->bob=%v bob->alice=%v bob->charlie=%v aliceAtCharlie=%v)",
				err,
				aliceManager.HasSession(bob.Hash()),
				bobManager.HasSession(alice.Hash()),
				bobManager.HasSession(charlie.Hash()),
				aliceAtCharlie,
			)
		}
		if err = aliceManager.Send(ctx, charlie.Hash(), message); err != nil {
			t.Fatalf("send through automatic native SSU2 introduction: %v", err)
		}
		net_.Advance(50 * time.Millisecond)
		if _, found := charlieDB.Get(alice.Hash()); !found {
			t.Fatal("relay DatabaseStore did not admit Alice RouterInfo at Charlie")
		}
		got := <-received
		if got.Header.ID != message.Header.ID || !bytes.Equal(got.Payload, message.Payload) {
			t.Fatalf("introduced native SSU2 session delivered (%d, %q), want (%d, %q)", got.Header.ID, got.Payload, message.Header.ID, message.Payload)
		}
	})
}

func TestSSU2SessionEvictionRemovesBothIndexes(t *testing.T) {
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
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, 2*time.Second)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, 2*time.Second)
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		if !aliceManager.HasSession(bob.Hash()) || !bobManager.HasSession(alice.Hash()) {
			t.Fatal("established SSU2 session was not indexed")
		}
		net_.Advance(3 * time.Second)
		if aliceManager.HasSession(bob.Hash()) || bobManager.HasSession(alice.Hash()) {
			t.Fatal("idle-expired SSU2 session remained indexed")
		}

		// Re-establish and verify retransmission exhaustion evicts the session.
		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		aliceAddr := aliceConn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		bobAddr := bobConn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		net_.Blackhole(aliceAddr, bobAddr)
		if err := aliceManager.Send(ctx, bob.Hash(), ssu2LiveMessage(1)); err != nil {
			t.Fatal(err)
		}
		for range 35 {
			net_.Advance(time.Second)
			if !aliceManager.HasSession(bob.Hash()) {
				break
			}
		}
		if aliceManager.HasSession(bob.Hash()) {
			t.Fatal("retransmission exhaustion did not evict SSU2 session")
		}
	})
}

func TestSSU2SessionReleaseSynchronizesWithReceive(t *testing.T) {
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
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := range 8 {
				_ = aliceManager.Send(ctx, bob.Hash(), ssu2LiveMessage(uint32(100+i)))
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 8 {
				_ = bobManager.Send(ctx, alice.Hash(), ssu2LiveMessage(uint32(200+i)))
			}
		}()
		go func() {
			defer wg.Done()
			bobManager.DropSession(alice.Hash())
		}()
		wg.Wait()
		net_.Advance(20 * time.Millisecond)
		if bobManager.HasSession(alice.Hash()) {
			t.Fatal("dropped SSU2 session remained active after concurrent receive/send")
		}
	})
}

func TestSSU2SessionViableTracksCongestionDegradation(t *testing.T) {
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
		aliceManager := newSSU2LiveManager(t, aliceDB, aliceStatic, aliceIntro, time.Minute, 5*time.Minute)
		bobManager := newSSU2LiveManager(t, bobDB, bobStatic, bobIntro, time.Minute, 5*time.Minute)
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
			t.Fatal(err)
		}
		net_.Advance(20 * time.Millisecond)
		if !aliceManager.SessionViable(bob.Hash()) {
			t.Fatal("fresh SSU2 session was not viable")
		}

		aliceAddr := aliceConn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		bobAddr := bobConn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		// Blackhole Bob -> Alice so ACKs do not return, exhausting Alice's send window.
		net_.SetLink(bobAddr, aliceAddr, simnet.LinkConfig{DropRate: 1.0})
		chunk := foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: 1, Expiration: uint64(time.Now().Add(5 * time.Minute).UnixMilli())},
			Payload: bytes.Repeat([]byte{'x'}, 1100),
		}
		var stallErr error
		for i := range 6 {
			chunk.Header.ID = uint32(i + 1)
			if err := aliceManager.Send(ctx, bob.Hash(), chunk); err != nil {
				stallErr = err
				break
			}
		}
		if !errors.Is(stallErr, ErrSSU2SendStalled) {
			t.Fatalf("window-exhausted send error = %v, want %v", stallErr, ErrSSU2SendStalled)
		}
		if aliceManager.SessionViable(bob.Hash()) {
			t.Fatal("congestion-stalled SSU2 session remained viable")
		}
		if !aliceManager.HasSession(bob.Hash()) {
			t.Fatal("degraded SSU2 session lost its existence for retransmission bookkeeping")
		}

		// Heal the return path and advance past the degradation cooldown.
		net_.SetLink(bobAddr, aliceAddr, simnet.LinkConfig{Latency: time.Millisecond})
		net_.Advance(ssu2SessionDegradedCooldown + time.Second)
		if !aliceManager.SessionViable(bob.Hash()) {
			t.Fatal("SSU2 session did not recover viability after degradation cooldown")
		}

		aliceManager.DropSession(bob.Hash())
		if aliceManager.SessionViable(bob.Hash()) || aliceManager.HasSession(bob.Hash()) {
			t.Fatal("dropped SSU2 session remained viable or present")
		}
	})
}

func TestSSU2ReplayDropsACKAndPathChallengeBlocks(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	header1 := bytes.Repeat([]byte{2}, 32)
	header2 := bytes.Repeat([]byte{3}, 32)
	sealer, err := dataplanessu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := dataplanessu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := dataplanessu2.MarshalACKRanges(nil, []dataplanessu2.ACKRange{{Start: 7, End: 7}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockACK, ack)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = dataplanessu2.MarshalPathChallengeBlock(payload, dataplanessu2.PathChallenge{Data: [8]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealer.SealDataTo(make([]byte, dataplanessu2.MaxIPv4PacketLen), dataplanessu2.ShortHeader{
		DestinationID: 17, PacketNumber: 1, Type: dataplanessu2.Data,
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
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.bindings = TransportBindings{Clock: WallClock{}}
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
		ctx := t.Context()
		entered := make(chan struct{})
		resume := make(chan struct{})
		var once sync.Once
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		if err := bobManager.Start(ctx, TransportBindings{
			SSU2: bobConn, LocalInfo: bob, Clock: WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, _ foundation.I2NPMessage, _ uint64, _ bool) error {
				once.Do(func() { close(entered) })
				<-resume
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			select {
			case <-resume:
			default:
				close(resume)
			}
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

		waitDone := make(chan error, 1)
		go func() {
			_ = bobManager.Close()
			waitDone <- bobManager.Wait()
		}()
		synctest.Wait()
		select {
		case err := <-waitDone:
			t.Fatalf("manager Wait completed while authenticated dispatch was still in flight: %v", err)
		default:
		}

		close(resume)
		if err := <-waitDone; err != nil {
			t.Fatalf("manager Wait after dispatch completion: %v", err)
		}
		if bobManager.HasSession(alice.Hash()) {
			t.Fatal("closed SSU2 manager retained session after Wait")
		}
	})
}

func TestSSU2EstablishReleasesEvictedIdleSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	send, err := dataplanessu2.NewDataCipher(key, key, key)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := dataplanessu2.NewDataCipher(key, key, key)
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{3}
	stale := &ssu2TransportSession{
		peer: peer, sendID: 1, receiveID: 2, send: send, receive: receive,
		sent:      make(map[uint32]*ssu2SentPacket),
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	stale.touch(time.Now().Add(-time.Hour))
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = context.Background()
	manager.idleTimeout = time.Second
	manager.bindings = TransportBindings{Clock: WallClock{}}
	manager.sessionsByPeer[peer] = stale
	manager.sessionsByID[stale.receiveID] = stale
	if _, err = manager.establish(context.Background(), peer); !errors.Is(err, ErrSSU2Session) {
		t.Fatalf("establish without database = %v, want ErrSSU2Session", err)
	}
	if stale.send != nil || stale.receive != nil {
		t.Fatal("idle session eviction retained transport ciphers")
	}
}

func TestSSU2OutboundInitiatorCannotBeSupersededOrReleasedDuringParse(t *testing.T) {
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
		ctx := t.Context()
		startSSU2SimManager(t, ctx, aliceManager, aliceConn, alice, nil)
		startSSU2SimManager(t, ctx, bobManager, bobConn, bob, nil)
		t.Cleanup(func() {
			closeSSU2LiveManager(t, aliceManager)
			closeSSU2LiveManager(t, bobManager)
		})

		// Delay Bob -> Alice Retry/SessionCreated slightly so multiple concurrent EnsureSession
		// callers share and exercise the pending outbound handshake state and retry path.
		net_.SetLink(net_.Host("bob").Addr(), net_.Host("alice").Addr(), simnet.LinkConfig{Latency: 10 * time.Millisecond})
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := aliceManager.EnsureSession(ctx, bob.Hash()); err != nil {
					t.Errorf("concurrent EnsureSession: %v", err)
				}
			}()
		}
		wg.Wait()
		if !aliceManager.HasSession(bob.Hash()) {
			t.Fatal("concurrent outbound handshake did not establish session")
		}
	})
}

func TestSSU2SessionRequestSupersedesStaleSessionOnNewSourceID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		ctx := t.Context()

		alice, _, _ := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobDB := newTransportTestPeers()
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit Alice RouterInfo: %v", err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		if err = bobManager.Start(ctx, TransportBindings{
			SSU2:      bobConn,
			LocalInfo: bob,
			Clock:     WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, _ foundation.I2NPMessage, _ uint64, _ bool) error {
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, bobManager)
		})

		bobPriv, err := ecdh.X25519().NewPrivateKey(bobStatic)
		if err != nil {
			t.Fatal(err)
		}
		bobPub := bobPriv.PublicKey().Bytes()

		// A superseded session still occupies its connection-ID slot while it
		// drains; a cached NewToken lets a new initiator reuse that destination.
		stale := &ssu2TransportSession{
			peer: alice.Hash(), sendID: 200, receiveID: 100,
			remote:    aliceConn.LocalAddr(),
			sent:      make(map[uint32]*ssu2SentPacket),
			fragments: make(map[uint32]*ssu2FragmentAssembly),
		}
		stale.touch(time.Now())
		bobManager.mu.Lock()
		bobManager.sessionsByID[stale.receiveID] = stale
		bobManager.sessionsByPeer[alice.Hash()] = stale
		bobManager.mu.Unlock()

		initiator, err := dataplanessu2.NewInitiator(bobPub, bobIntro, 100, 300, 2)
		if err != nil {
			t.Fatal(err)
		}
		var dateTime [4]byte
		binary.BigEndian.PutUint32(dateTime[:], uint32(time.Now().Unix()))
		requestPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockDateTime, dateTime[:])
		if err != nil {
			t.Fatal(err)
		}
		requestPayload, err = dataplanessu2.MarshalBlock(requestPayload, dataplanessu2.BlockPadding, nil)
		if err != nil {
			t.Fatal(err)
		}
		bobManager.mu.Lock()
		token, err := bobManager.newTokenLocked(aliceConn.LocalAddr(), 100, 300)
		bobManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		requestPacket, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aliceConn.WriteTo(requestPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		createdBuf := make([]byte, dataplanessu2.MaxIPv4PacketLen)
		n, _, err := aliceConn.ReadFrom(createdBuf)
		if err != nil {
			t.Fatalf("read SessionCreated: %v", err)
		}
		if _, _, err = initiator.ParseSessionCreated(createdBuf[:n]); err != nil {
			t.Fatalf("parse SessionCreated: %v", err)
		}

		if bobManager.HasSession(alice.Hash()) {
			t.Fatal("stale session kept its peer slot before SessionConfirmed")
		}
	})
}

func TestSSU2SessionRequestSupersedesInboundWhenCapacityFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		aliceConn := newSSU2SimConn(t, net_, "alice")
		bobConn := newSSU2SimConn(t, net_, "bob")
		ctx := t.Context()

		alice, _, _ := newSSU2TestLocal(t, aliceConn.LocalAddr().String())
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobDB := newTransportTestPeers()
		if err := bobDB.AdmitRouterInfo(alice.Snapshot(), uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("admit Alice RouterInfo: %v", err)
		}
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: bobDB, StaticPrivate: bobStatic, IntroKey: bobIntro, MaxPending: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err = bobManager.Start(ctx, TransportBindings{
			SSU2:      bobConn,
			LocalInfo: bob,
			Clock:     WallClock{},
			HandleI2NPContext: func(_ context.Context, _ foundation.Hash, _ foundation.I2NPMessage, _ uint64, _ bool) error {
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeSSU2LiveManager(t, bobManager)
		})

		bobPriv, err := ecdh.X25519().NewPrivateKey(bobStatic)
		if err != nil {
			t.Fatal(err)
		}
		bobPub := bobPriv.PublicKey().Bytes()

		firstInitiator, err := dataplanessu2.NewInitiator(bobPub, bobIntro, 100, 200, 2)
		if err != nil {
			t.Fatal(err)
		}
		var dateTime [4]byte
		binary.BigEndian.PutUint32(dateTime[:], uint32(time.Now().Unix()))
		requestPayload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockDateTime, dateTime[:])
		if err != nil {
			t.Fatal(err)
		}
		requestPayload, err = dataplanessu2.MarshalBlock(requestPayload, dataplanessu2.BlockPadding, nil)
		if err != nil {
			t.Fatal(err)
		}
		bobManager.mu.Lock()
		firstToken, err := bobManager.newTokenLocked(aliceConn.LocalAddr(), 100, 200)
		bobManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		firstRequest, err := firstInitiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, firstToken)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aliceConn.WriteTo(firstRequest, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		createdBuf := make([]byte, dataplanessu2.MaxIPv4PacketLen)
		if _, _, err = aliceConn.ReadFrom(createdBuf); err != nil {
			t.Fatalf("read first SessionCreated: %v", err)
		}

		// Now MaxPending (1) is full with destinationID=100, sendID=200.
		// A new SessionRequest from the same endpoint on destinationID=100 with sendID=300 must supersede it.
		initiator, err := dataplanessu2.NewInitiator(bobPub, bobIntro, 100, 300, 2)
		if err != nil {
			t.Fatal(err)
		}
		bobManager.mu.Lock()
		token, err := bobManager.newTokenLocked(aliceConn.LocalAddr(), 100, 300)
		bobManager.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		requestPacket, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), requestPayload, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = aliceConn.WriteTo(requestPacket, bobConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}

		n, _, err := aliceConn.ReadFrom(createdBuf)
		if err != nil {
			t.Fatalf("read superseding SessionCreated: %v", err)
		}
		if _, _, err = initiator.ParseSessionCreated(createdBuf[:n]); err != nil {
			t.Fatalf("parse superseding SessionCreated: %v", err)
		}
	})
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
	manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: static.Bytes(), IntroKey: intro, TokenLifetime: lifetime})
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
	payload, err := dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockRouterInfo, data)
	if err != nil {
		t.Fatal(err)
	}
	info, gotIntro, err := validateSSU2ConfirmedPayload(payload, testECDHPublic(t, static))
	if err != nil || info.Hash() != owner.Hash() || !bytes.Equal(gotIntro, intro) {

		t.Fatalf("gzip RouterInfo = %s, %x, %v", info.Hash(), gotIntro, err)
	}

	oversized := append([]byte{2, 1}, gzipSSU2TestBytes(t, make([]byte, foundation.NetworkDatabaseMaxRouterInfoBytes+1))...)
	payload, err = dataplanessu2.MarshalBlock(nil, dataplanessu2.BlockRouterInfo, oversized)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = validateSSU2ConfirmedPayload(payload, testECDHPublic(t, static)); err == nil {
		t.Fatal("oversized gzip RouterInfo was accepted")
	}
}

func TestLocalConfirmedPayloadCompressesFragmentedRouterInfo(t *testing.T) {
	options := make([]transportTestOption, 12)
	for index := range options {
		options[index] = transportTestOption{
			Key:   string([]byte{'a', byte('a' + index)}),
			Value: string(bytes.Repeat([]byte{'z'}, 80)),
		}
	}
	owner, static, intro := newSSU2TestLocal(t, "127.0.0.1:1", options...)
	manager, err := NewSSU2Manager(SSU2ManagerConfig{
		NetworkID:     2,
		StaticPrivate: static,
		IntroKey:      intro,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.bindings = TransportBindings{LocalInfo: owner}
	payload, err := manager.localConfirmedPayload(dataplanessu2.MinPacketLen)
	if err != nil {
		t.Fatal(err)
	}
	iterator := dataplanessu2.NewBlockIterator(payload)
	block, ok, err := iterator.Next()
	if err != nil || !ok || block.Type != dataplanessu2.BlockRouterInfo {
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

type blockingWriteSSU2Conn struct {
	*simnet.UDPConn
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingWriteSSU2Conn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c.block.Load() {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.UDPConn.WriteToUDPAddrPort(b, addr)
}

func TestSSU2EgressBackpressuresWhenSlotsAreBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		rawConn := newSSU2SimConn(t, net_, "alice")
		receiver := newSSU2SimConn(t, net_, "bob")
		conn := &blockingWriteSSU2Conn{
			UDPConn: rawConn,
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		conn.block.Store(true)
		local, static, intro := newSSU2TestLocal(t, conn.LocalAddr().String())
		manager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, StaticPrivate: static, IntroKey: intro})
		if err != nil {
			t.Fatal(err)
		}
		ctx := t.Context()
		startSSU2SimManager(t, ctx, manager, conn, local, nil)
		t.Cleanup(func() {
			conn.block.Store(false)
			select {
			case <-conn.release:
			default:
				close(conn.release)
			}
			closeSSU2LiveManager(t, manager)
		})

		remote := receiver.LocalAddr()
		results := make([]chan error, ssu2EgressSlots)
		for i := range results {
			results[i] = make(chan error, 1)
			payload := []byte{byte(i + 1)}
			go func(ch chan error) {
				ch <- manager.writeTo(payload, remote)
			}(results[i])
		}
		<-conn.entered
		synctest.Wait()

		extraResult := make(chan error, 1)
		go func() {
			extraResult <- manager.writeTo([]byte{99}, remote)
		}()
		synctest.Wait()
		select {
		case err := <-extraResult:
			t.Fatalf("extra write returned instead of applying backpressure: %v", err)
		default:
		}
		if dropped := manager.IOStats().Dropped; dropped != 0 {
			t.Fatalf("backpressured writes counted as dropped while blocked: %d", dropped)
		}

		conn.block.Store(false)
		close(conn.release)
		for i, ch := range results {
			if err := <-ch; err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		if err := <-extraResult; err != nil {
			t.Fatalf("extra write: %v", err)
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
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = ctx
	manager.batchConn = &recoverableEgressBatchConn{err: writeErr}
	manager.egressFree = free
	manager.egressQueue = make(chan *ssu2EgressSlot, 2)
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
		send, err := dataplanessu2.NewDataCipher(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
		if err != nil {
			t.Fatal(err)
		}
		peer := foundation.Hash{1}
		session := &ssu2TransportSession{
			peer:       peer,
			sendID:     9,
			receiveID:  10,
			remote:     net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234")),
			send:       send,
			nextPacket: 1,
		}
		session.touch(time.Now())
		session.initReliability(ssu2MaximumNetworkMTU)
		managerCtx, stopManager := context.WithCancel(t.Context())
		defer stopManager()
		manager, _ := newSSU2ConfiguredManager(t, nil)
		manager.started = true
		manager.ctx = managerCtx
		manager.idleTimeout = time.Hour
		manager.sessionsByPeer[peer] = session
		manager.sessionsByID[session.receiveID] = session
		manager.bindings = TransportBindings{Clock: WallClock{}}
		manager.egressFree = make(chan *ssu2EgressSlot)
		manager.egressQueue = make(chan *ssu2EgressSlot, 1)
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
		session.sendMu.Unlock() // +checklocksignore

		session.acknowledge([]dataplanessu2.ACKRange{{Start: 1, End: 1}}, sentAt.Add(time.Millisecond))
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
		session.sendMu.Unlock() // +checklocksignore

		session.acknowledge([]dataplanessu2.ACKRange{{Start: 1, End: 1}}, time.Now())
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

func TestSSU2SentSlotsStartSmallAndGrowLazily(t *testing.T) {
	_, session := newSSU2SendTestHarness(t)
	if got := len(session.sentSlots); got != ssu2InitialTrackedPackets {
		t.Fatalf("initial sentSlots = %d, want %d", got, ssu2InitialTrackedPackets)
	}
	if got := len(session.sentChunks); got != 1 {
		t.Fatalf("initial sentChunks = %d, want 1", got)
	}

	held := make([]*ssu2SentPacket, 0, ssu2InitialTrackedPackets)
	for index := range ssu2InitialTrackedPackets {
		payload := bytes.Repeat([]byte{byte(index)}, 4)
		slot := session.retainPayload(payload, time.Unix(1, 0))
		if slot == nil {
			t.Fatalf("retainPayload %d = nil before exhausting initial slots", index)
		}
		held = append(held, slot)
	}
	if got := len(session.sentSlots); got != ssu2InitialTrackedPackets {
		t.Fatalf("sentSlots after filling initial capacity = %d, want %d (should not grow early)", got, ssu2InitialTrackedPackets)
	}

	// The initial capacity is now fully in-use; the next retain must grow.
	overflow := session.retainPayload([]byte("grown"), time.Unix(2, 0))
	if overflow == nil {
		t.Fatal("retainPayload returned nil instead of growing sentSlots")
	}
	if got, want := len(session.sentSlots), 2*ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots after growth = %d, want %d (doubling)", got, want)
	}
	if got := len(session.sentChunks); got != 2 {
		t.Fatalf("sentChunks after growth = %d, want 2", got)
	}

	for index, slot := range held {
		want := byte(index)
		if len(slot.payload) != 4 || slot.payload[0] != want {
			t.Fatalf("slot %d payload = %v, want first byte %d", index, slot.payload, want)
		}
	}
	if string(overflow.payload) != "grown" {
		t.Fatalf("grown slot payload = %q, want %q", overflow.payload, "grown")
	}
}

// TestSSU2SentSlotsShrinkAfterSustainedIdleAndFloorAtInitial checks that
// shrinkSentSlotsLocked releases a grown chunk once utilization has stayed
// low for ssu2SentSlotIdleShrinkTicks consecutive ticks, but never below
// ssu2InitialTrackedPackets, and that a still-in-use slot in the tail chunk
// defers the shrink instead of relocating or dropping it.
func TestSSU2SentSlotsShrinkAfterSustainedIdleAndFloorAtInitial(t *testing.T) {
	_, session := newSSU2SendTestHarness(t)
	session.growSentSlotsLocked(2 * ssu2InitialTrackedPackets)
	if got, want := len(session.sentSlots), 2*ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots after manual growth = %d, want %d", got, want)
	}

	// A packet still tracked in the grown tail chunk must block the shrink.
	// retainPayload always fills the lowest-index free slot, so mark the
	// tail slot in-use directly rather than relying on scan order.
	tail := session.sentSlots[len(session.sentSlots)-1]
	tail.inUse = true
	for i := 0; i < ssu2SentSlotIdleShrinkTicks+5; i++ {
		session.shrinkSentSlotsLocked()
	}
	if got, want := len(session.sentSlots), 2*ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots shrank to %d despite an in-use slot, want unchanged %d", got, want)
	}
	tail.inUse = false
	// The loop above left sentIdleTicks at some partial count depending on
	// how the blocked attempts landed relative to the threshold; pin it back
	// to zero so the boundary check below is exact rather than incidental.
	session.sentIdleTicks = 0

	for i := 0; i < ssu2SentSlotIdleShrinkTicks-1; i++ {
		session.shrinkSentSlotsLocked()
	}
	if got, want := len(session.sentSlots), 2*ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots shrank before ssu2SentSlotIdleShrinkTicks elapsed: %d, want unchanged %d", got, want)
	}
	session.shrinkSentSlotsLocked()
	if got, want := len(session.sentSlots), ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots after idle shrink = %d, want %d", got, want)
	}
	if got := len(session.sentChunks); got != 1 {
		t.Fatalf("sentChunks after idle shrink = %d, want 1", got)
	}

	// Floor: shrinking further must never drop below the initial chunk.
	for i := 0; i < 4*ssu2SentSlotIdleShrinkTicks; i++ {
		session.shrinkSentSlotsLocked()
	}
	if got, want := len(session.sentSlots), ssu2InitialTrackedPackets; got != want {
		t.Fatalf("sentSlots below floor = %d, want %d", got, want)
	}
}

func TestSSU2IdleShrinkReclaimsPayloadStorage(t *testing.T) {
	session := new(ssu2TransportSession)
	session.initReliability(ssu2MinimumNetworkMTU)
	t.Cleanup(session.ReleaseSensitive)
	for range ssu2MaxTrackedPackets {
		if session.retainPayload([]byte("retained payload"), time.Unix(1, 0)) == nil {
			t.Fatal("failed to fill retained payload capacity")
		}
	}
	var chunks []weak.Pointer[byte]
	for _, chunk := range session.sentChunks[1:] {
		chunks = append(chunks, weak.Make(&chunk[0]))
	}
	for _, slot := range session.sentSlots[1:] {
		slot.release()
	}
	for range 4 * ssu2SentSlotIdleShrinkTicks {
		session.maintainSentCapacity()
	}
	runtime.GC()
	runtime.GC()
	for index, chunk := range chunks {
		if chunk.Value() != nil {
			t.Errorf("idle shrink retained payload chunk %d after GC", index+1)
		}
	}
	if got := string(session.sentSlots[0].payload); got != "retained payload" {
		t.Errorf("idle shrink changed the active payload to %q", got)
	}
	runtime.KeepAlive(session)
}

func TestSSU2EgressCollectsOnlyReadyDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = ctx
	manager.egressQueue = make(chan *ssu2EgressSlot, ssu2EgressSlots)
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
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = ctx
	manager.egressFree = free
	manager.egressQueue = make(chan *ssu2EgressSlot, 1)
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
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = ctx
	manager.ackQueue = make(chan *ssu2TransportSession, 4)
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
	send, err := dataplanessu2.NewDataCipher(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{1}
	session := &ssu2TransportSession{
		peer:       peer,
		sendID:     9,
		receiveID:  10,
		remote:     net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234")),
		send:       send,
		nextPacket: 1,
	}
	session.touch(time.Now())
	session.initReliability(ssu2MaximumNetworkMTU)
	managerCtx, cancel := context.WithCancel(t.Context())
	free := make(chan *ssu2EgressSlot, 1)
	free <- &ssu2EgressSlot{done: make(chan error, 1)}
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = managerCtx
	manager.idleTimeout = time.Hour
	manager.sessionsByPeer[peer] = session
	manager.sessionsByID[session.receiveID] = session
	manager.bindings = TransportBindings{Clock: WallClock{}}
	manager.egressFree = free
	manager.egressQueue = make(chan *ssu2EgressSlot, 1)
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

func newSSU2TestLocal(t *testing.T, endpoint string, options ...transportTestOption) (*transportTestLocal, []byte, []byte) {
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
	owner, err := newTransportTestLocal(transportTestLocalConfig{Local: local, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]transportTestAddress{{
		Transport: "SSU",
		Cost:      3,
		Options: []transportTestOption{
			{Key: "host", Value: host},
			{Key: "i", Value: foundation.EncodeI2PBase64(intro)},
			{Key: "port", Value: port},
			{Key: "s", Value: foundation.EncodeI2PBase64(static.PublicKey().Bytes())},
			{Key: "v", Value: "2"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(transportTestReachable)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	return owner, static.Bytes(), intro
}

func TestSSU2SendDoesNotHoldFrameMuDuringCapacityWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		session.sendMu.Lock()
		session.sendWindowRemaining = 0
		session.sendMu.Unlock()
		sender := ssu2SessionSender{manager: manager, session: session}
		done := make(chan error, 1)
		go func() {
			done <- sender.Send(t.Context(), managerHotPathMessage())
		}()
		synctest.Wait()
		if !session.frameMu.mu.TryLock() {
			session.ReleaseSensitive()
			<-done
			t.Fatal("send held frameMu while waiting for send capacity")
		}
		session.frameMu.mu.Unlock() // +checklocksignore
		session.ReleaseSensitive()
		if err := <-done; !errors.Is(err, ErrSSU2Session) && !errors.Is(err, ErrSSU2SendStalled) {
			t.Fatalf("blocked send error = %v, want session teardown error", err)
		}
	})
}

func TestSSU2TerminationStillDrainsI2NPDispatchBatch(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	header1 := bytes.Repeat([]byte{8}, 32)
	header2 := bytes.Repeat([]byte{9}, 32)
	sealer, err := dataplanessu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := dataplanessu2.NewDataCipher(key, header1, header2)
	if err != nil {
		t.Fatal(err)
	}
	message := managerHotPathMessage()
	var frame [dataplanessu2.MaxIPv4PacketLen]byte
	payload, err := marshalSSU2I2NPTo(frame[:], message)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err = dataplanessu2.MarshalBlock(payload, dataplanessu2.BlockTermination, make([]byte, 9)); err != nil {
		t.Fatal(err)
	}
	packet, err := sealer.SealDataTo(make([]byte, dataplanessu2.MaxIPv4PacketLen), dataplanessu2.ShortHeader{
		DestinationID: 17, PacketNumber: 1, Type: dataplanessu2.Data,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	var delivered atomic.Int32
	manager, _ := newSSU2ConfiguredManager(t, nil)
	manager.started = true
	manager.ctx = context.Background()
	manager.dispatchFree = make(chan *ssu2DispatchBatch, ssu2DispatchQueueSize)
	manager.bindings = TransportBindings{
		Clock: WallClock{},
		HandleI2NPContext: func(context.Context, foundation.Hash, foundation.I2NPMessage, uint64, bool) error {
			delivered.Add(1)
			return nil
		},
	}
	manager.dispatchFreeBudget.Store(ssu2DispatchQueueSize)
	peer := foundation.Hash{9}
	session := &ssu2TransportSession{
		peer: peer, receiveID: 17, receive: receiver,
		sent:      make(map[uint32]*ssu2SentPacket),
		fragments: make(map[uint32]*ssu2FragmentAssembly),
	}
	manager.sessionsByPeer[peer] = session
	manager.sessionsByID[session.receiveID] = session
	manager.handleDataFrom(session, packet, netip.AddrPort{})
	if got := delivered.Load(); got != 1 {
		t.Fatalf("I2NP delivered %d times alongside termination, want 1", got)
	}
	released := <-manager.dispatchFree
	select {
	case again := <-manager.dispatchFree:
		t.Fatalf("dispatch batch released twice: first=%p again=%p", released, again)
	default:
	}
}

func TestSSU2RetransmitLoopSubSecondDeadlineAvoidsTickQuantization(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager, session := newSSU2SendTestHarness(t)
		ctx, cancel := context.WithCancel(t.Context())
		manager.ctx = ctx
		manager.relayTagPending = map[foundation.Hash]time.Time{session.peer: time.Now().Add(time.Hour)}
		t.Cleanup(func() {
			cancel()
			manager.wg.Wait()
		})
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case slot := <-manager.egressQueue:
					slot.done <- nil
					manager.egressFree <- slot
				}
			}
		}()
		manager.wg.Add(1)
		go manager.retransmitLoop()
		synctest.Wait()

		<-time.After(250 * time.Millisecond)
		payload := []byte{dataplanessu2.BlockPadding, 0, 5, 0, 0, 0, 0, 0}
		session.sendMu.Lock()
		sent := session.retainPayload(payload, time.Now())
		sent.latestPacket = 1
		session.sent[1] = sent
		session.nextPacket = 2
		session.sendMu.Unlock()

		<-time.After(750 * time.Millisecond)
		synctest.Wait()
		session.sendMu.Lock()
		attemptsAtTick := sent.attempts
		session.sendMu.Unlock()
		if attemptsAtTick != 0 {
			t.Fatalf("packet retransmitted before RTO at 1s tick: attempts=%d", attemptsAtTick)
		}

		<-time.After(250 * time.Millisecond)
		synctest.Wait()
		session.sendMu.Lock()
		attemptsAtDue := sent.attempts
		latestAtDue := sent.latestPacket
		session.sendMu.Unlock()
		if attemptsAtDue != 1 || latestAtDue != 2 {
			t.Fatalf("sub-second RTO deadline did not retransmit at t=1.25s: attempts=%d latest=%d", attemptsAtDue, latestAtDue)
		}
	})
}
