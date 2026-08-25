package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/network/transport/ntcp2"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
)

func TestNTCP2ManagerAuthenticatesAndRoutesI2NP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alice, aliceStatic, aliceIV := newNTCP2TestLocal(t, "127.0.0.1:1")
	bob, bobStatic, bobIV := newNTCP2TestLocal(t, listener.Addr().String())
	aliceDB := netdb.NewDatabase(alice.Hash(), 16)
	bobDB := netdb.NewDatabase(bob.Hash(), 16)
	bobInfo := bob.Snapshot()
	if err = aliceDB.AdmitRouterInfo(bobInfo, false, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit Bob RouterInfo: %v", err)
	}

	aliceManager, err := NewNTCP2Manager(NTCP2ManagerConfig{Database: aliceDB, StaticPrivate: aliceStatic, StaticIV: aliceIV})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewNTCP2Manager(NTCP2ManagerConfig{Database: bobDB, StaticPrivate: bobStatic, StaticIV: bobIV})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan i2np.Message, 1)
	rejected := make(chan struct{}, 1)
	bindingsAlice := TransportBindings{
		LocalInfo: alice,
		Clock:     WallClock{},
		HandleI2NP: func(i2np.Message, uint64, bool) error {
			return nil
		},
	}
	bindingsBob := TransportBindings{
		NTCP2:     listener,
		LocalInfo: bob,
		Clock:     WallClock{},
		HandleI2NP: func(message i2np.Message, _ uint64, _ bool) error {
			if message.Header.ID == 9 {
				rejected <- struct{}{}
				return errors.New("message policy rejection")
			}
			received <- message
			return nil
		},
	}
	if err = bobManager.Start(ctx, bindingsBob); err != nil {
		t.Fatal(err)
	}
	if err = aliceManager.Start(ctx, bindingsAlice); err != nil {
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

	now := uint64(time.Now().Add(time.Minute).UnixMilli())
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 9, Expiration: now},
		Payload: make([]byte, 12),
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err = aliceManager.Send(sendCtx, bob.Hash(), message); err != nil {
		t.Fatalf("Send rejected I2NP over native NTCP2: %v", err)
	}
	session := aliceManager.session(bob.Hash())
	if session == nil {
		t.Fatal("native NTCP2 session missing after send")
	}
	select {
	case <-rejected:
	case <-time.After(5 * time.Second):
		t.Fatal("native NTCP2 peer did not reject first I2NP")
	}
	time.Sleep(20 * time.Millisecond)
	if current := aliceManager.session(bob.Hash()); current != session {
		t.Fatal("message-level handler rejection closed the authenticated NTCP2 session")
	}
	message.Header.ID = 10
	if err = aliceManager.Send(sendCtx, bob.Hash(), message); err != nil {
		t.Fatalf("Send after message-level rejection: %v", err)
	}
	wantHeader := message.Header
	wantHeader.Expiration = wantHeader.Expiration / 1000 * 1000
	select {
	case got := <-received:
		if got.Header != wantHeader {
			t.Fatalf("received I2NP header = %#v, want %#v", got.Header, wantHeader)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native NTCP2 peer did not receive I2NP after a message-level rejection")
	}
	if bobDB.Routers().Len() != 1 {
		t.Fatalf("authenticated Alice RouterInfo was not admitted: len = %d", bobDB.Routers().Len())
	}
	if !aliceManager.Status().Running || !bobManager.Status().Running {
		t.Fatal("native NTCP2 managers stopped during a live session")
	}
}

func TestSelectNTCP2AddressAcceptsNativeI2PDShape(t *testing.T) {
	wire, err := os.ReadFile("testdata/i2pd-2.50.0-router.info")
	if err != nil {
		t.Fatal(err)
	}
	info, err := netdb.ParseRouterInfo(wire)
	if err != nil {
		t.Fatalf("parse native i2pd RouterInfo: %v", err)
	}
	valid, err := info.Verify()
	if err != nil || !valid {
		t.Fatalf("verify native i2pd RouterInfo: valid=%t err=%v", valid, err)
	}
	selected, err := selectNTCP2Address(info)
	if err != nil {
		t.Fatalf("select native i2pd NTCP2 address: %v", err)
	}
	static, err := ivnp.DecodeI2PBase64([]byte("9Lm8rFllOrFjaqhW-GJO0cKc-AoGA6ySWwa26Dool0c="))
	if err != nil {
		t.Fatal(err)
	}
	iv, err := ivnp.DecodeI2PBase64([]byte("eSToe7Gh5ZM45xq~qP3LoQ=="))
	if err != nil {
		t.Fatal(err)
	}
	if selected.host != "11.89.0.2" || selected.port != 28442 ||
		!bytes.Equal(selected.static[:], static) || !bytes.Equal(selected.iv[:], iv) {
		t.Fatalf("native i2pd NTCP2 address = %#v", selected)
	}
}

func TestNTCP2I2NPUsesTransportHeader(t *testing.T) {
	message := i2np.Message{
		Header: i2np.Header{
			Type:       i2np.DatabaseLookup,
			ID:         0x01020304,
			Expiration: 1_700_000_000_999,
		},
		Payload: []byte{1, 2, 3},
	}
	encoded, err := marshalNTCP2I2NP(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != i2np.TransportHeaderLen+len(message.Payload) {
		t.Fatalf("NTCP2 I2NP length = %d, want %d-byte transport header plus payload", len(encoded), i2np.TransportHeaderLen)
	}
	decoded, err := decodeNTCP2I2NP(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.Type != message.Header.Type || decoded.Header.ID != message.Header.ID ||
		decoded.Header.Expiration != message.Header.Expiration/1000*1000 ||
		string(decoded.Payload) != string(message.Payload) {
		t.Fatalf("NTCP2 transport I2NP round trip = %#v, want %#v", decoded, message)
	}
}

func TestNTCP2InboundRouterInfoPolicyRejectsStaleFutureAndRotationDowngrade(t *testing.T) {
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	managerStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{
		Database:      netdb.NewDatabase(ivnp.Hash{}, 16),
		StaticPrivate: managerStatic.Bytes(),
		StaticIV:      make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	staticOne := make([]byte, 32)
	staticTwo := make([]byte, 32)
	staticThree := make([]byte, 32)
	if _, err = rand.Read(staticOne); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(staticTwo); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(staticThree); err != nil {
		t.Fatal(err)
	}
	publish := func(static []byte, at uint64) netdb.RouterInfo {
		t.Helper()
		if err := owner.ReplaceAddresses([]PublishedAddress{{Transport: "NTCP2", Options: []MappingOption{
			{Key: "s", Value: ivnp.EncodeI2PBase64(static)},
			{Key: "v", Value: "2"},
		}}}); err != nil {
			t.Fatal(err)
		}
		info, err := owner.info.Publish(at)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}

	stale := publish(staticOne, now-netdb.RouterInfoMaxAgeMillis-1)
	if manager.admitInboundPeer(stale, staticOne, now) {
		t.Fatal("accepted RouterInfo older than NTCP2 maximum age")
	}
	first := publish(staticOne, now-1)
	if !manager.admitInboundPeer(first, staticOne, now) {
		t.Fatal("rejected current RouterInfo")
	}
	current := publish(staticTwo, now)
	if !manager.admitInboundPeer(current, staticTwo, now) {
		t.Fatal("rejected newer RouterInfo")
	}
	if manager.admitInboundPeer(first, staticOne, now) {
		t.Fatal("accepted archived RouterInfo with a rotated static key")
	}
	future := publish(staticThree, now+netdb.RouterInfoMaxFutureMillis+1)
	if manager.admitInboundPeer(future, staticThree, now) {
		t.Fatal("accepted RouterInfo beyond maximum future skew")
	}
	stored, ok := manager.database.Routers().Get(current.Hash())
	if !ok || stored.Info.Published != current.Published {
		t.Fatalf("RouterInfo downgrade changed netdb entry: %#v, %t", stored, ok)
	}
}

func newNTCP2TestLocal(t *testing.T, endpoint string) (*LocalRouterInfo, []byte, []byte) {
	t.Helper()
	local, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, RouterVersion: "0.9.66"})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "NTCP2",
		Cost:      3,
		Options: []MappingOption{
			{Key: "host", Value: host},
			{Key: "i", Value: ivnp.EncodeI2PBase64(iv)},
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
	return owner, static.Bytes(), iv
}

func TestNTCP2ManagerReleasesResponderOnPostConstructionFailure(t *testing.T) {
	local, staticPrivate, staticIV := newNTCP2TestLocal(t, "127.0.0.1:1")
	localHash := local.Hash()
	initiator, err := ntcp2.NewInitiator(ecdhPublic(staticPrivate))
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.ReleaseSensitive()
	request, err := initiator.BuildSessionRequest(make([]byte, ntcp2.SessionRequestCiphertextLen), localHash[:], staticIV, nil, ntcp2.SessionRequestOptions{
		NetworkID: 2, Version: 2, Timestamp: 1,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	responder, options, err := ntcp2.ParseSessionRequest(request, staticPrivate, localHash[:], staticIV, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{StaticPrivate: staticPrivate, StaticIV: staticIV})
	if err != nil {
		t.Fatal(err)
	}
	manager.bindings = TransportBindings{LocalInfo: local, Clock: WallClock{}}
	manager.readSessionRequest = func(io.Reader, []byte, []byte, []byte, uint8, bool) (*ntcp2.Responder, ntcp2.SessionRequestOptions, error) {
		return responder, options, nil
	}
	server, client := net.Pipe()
	defer client.Close()
	manager.acceptOne(server)
	if _, err = responder.BuildSessionCreated(make([]byte, ntcp2.SessionRequestCiphertextLen), localHash[:], nil, ntcp2.SessionCreatedOptions{}); !errors.Is(err, ntcp2.ErrHandshake) {
		t.Fatalf("responder remained usable after manager timestamp rejection: %v", err)
	}
}
