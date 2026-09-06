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

	dataplanentcp2 "gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	"gosuda.org/ivnp/foundation"
)

func TestNTCP2ManagerAuthenticatesAndRoutesI2NP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	alice, aliceStatic, aliceIV := newNTCP2TestLocal(t, "127.0.0.1:1")
	bob, bobStatic, bobIV := newNTCP2TestLocal(t, listener.Addr().String())
	aliceDB := newTransportTestPeers()
	bobDB := newTransportTestPeers()
	bobInfo := bob.Snapshot()
	if err = aliceDB.AdmitRouterInfo(bobInfo, uint64(time.Now().UnixMilli())); err != nil {
		t.Fatalf("admit Bob RouterInfo: %v", err)
	}

	aliceManager, err := NewNTCP2Manager(NTCP2ManagerConfig{Peers: aliceDB, StaticPrivate: aliceStatic, StaticIV: aliceIV})
	if err != nil {
		t.Fatal(err)
	}
	bobManager, err := NewNTCP2Manager(NTCP2ManagerConfig{Peers: bobDB, StaticPrivate: bobStatic, StaticIV: bobIV})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan foundation.I2NPMessage, 1)
	rejected := make(chan struct{}, 1)
	bindingsAlice := TransportBindings{
		LocalInfo: alice,
		Clock:     WallClock{},
		HandleI2NP: func(foundation.I2NPMessage, uint64, bool) error {
			return nil
		},
	}
	bindingsBob := TransportBindings{
		NTCP2:     listener,
		LocalInfo: bob,
		Clock:     WallClock{},
		HandleI2NP: func(message foundation.I2NPMessage, _ uint64, _ bool) error {
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
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 9, Expiration: now},
		Payload: make([]byte, 12),
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err = aliceManager.EnsureSession(sendCtx, bob.Hash()); err != nil {
		t.Fatalf("authenticate NTCP2 session: %v", err)
	}
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
	if current := aliceManager.session(bob.Hash()); current != session {
		t.Fatal("message-level handler rejection closed the authenticated NTCP2 session")
	}
	message.Header.ID = 10
	if err = aliceManager.Send(sendCtx, bob.Hash(), message); err != nil {
		t.Fatalf("Send after message-level rejection: %v", err)
	}
	wantHeader := message.Header
	expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		t.Fatal("test expiration is not encodable")
	}
	wantHeader.Expiration = foundation.I2NPDecodeTransportExpiration(expiration)
	select {
	case got := <-received:
		if got.Header != wantHeader {
			t.Fatalf("received I2NP header = %#v, want %#v", got.Header, wantHeader)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native NTCP2 peer did not receive I2NP after a message-level rejection")
	}
	if _, ok := bobDB.RouterInfo(alice.Hash()); !ok {
		t.Fatal("authenticated Alice RouterInfo was not admitted")
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
	info, err := foundation.NetworkDatabaseParseRouterInfo(wire)
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
	static, err := foundation.DecodeI2PBase64([]byte("9Lm8rFllOrFjaqhW-GJO0cKc-AoGA6ySWwa26Dool0c="))
	if err != nil {
		t.Fatal(err)
	}
	iv, err := foundation.DecodeI2PBase64([]byte("eSToe7Gh5ZM45xq~qP3LoQ=="))
	if err != nil {
		t.Fatal(err)
	}
	if selected.host != "11.89.0.2" || selected.port != 28442 ||
		!bytes.Equal(selected.static[:], static) || !bytes.Equal(selected.iv[:], iv) {
		t.Fatalf("native i2pd NTCP2 address = %#v", selected)
	}
}

func TestNTCP2I2NPUsesTransportHeader(t *testing.T) {
	message := foundation.I2NPMessage{
		Header: foundation.I2NPHeader{
			Type:       foundation.I2NPDatabaseLookup,
			ID:         0x01020304,
			Expiration: 1_700_000_000_999,
		},
		Payload: []byte{1, 2, 3},
	}
	encoded, err := marshalNTCP2I2NP(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != foundation.I2NPTransportHeaderLen+len(message.Payload) {
		t.Fatalf("NTCP2 I2NP length = %d, want %d-byte transport header plus payload", len(encoded), foundation.I2NPTransportHeaderLen)
	}
	decoded, err := decodeNTCP2I2NP(encoded)
	if err != nil {
		t.Fatal(err)
	}
	expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		t.Fatal("test expiration is not encodable")
	}
	if decoded.Header.Type != message.Header.Type || decoded.Header.ID != message.Header.ID ||
		decoded.Header.Expiration != foundation.I2NPDecodeTransportExpiration(expiration) ||
		string(decoded.Payload) != string(message.Payload) {
		t.Fatalf("NTCP2 transport I2NP round trip = %#v, want %#v", decoded, message)
	}
}

func TestNTCP2InboundRouterInfoPolicyRejectsStaleFutureAndRotationDowngrade(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTransportTestLocal(transportTestLocalConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	managerStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{Peers: newTransportTestPeers(), StaticPrivate: managerStatic.Bytes(),
		StaticIV: make([]byte, 16)})
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
	publish := func(static []byte, at uint64) foundation.NetworkDatabaseRouterInfo {
		t.Helper()
		if err := owner.ReplaceAddresses([]transportTestAddress{{Transport: "NTCP2", Options: []transportTestOption{
			{Key: "s", Value: foundation.EncodeI2PBase64(static)},
			{Key: "v", Value: "2"},
		}}}); err != nil {
			t.Fatal(err)
		}
		info, err := owner.PublishAt(at)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}

	stale := publish(staticOne, now-uint64(90*time.Minute/time.Millisecond)-1)
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
	future := publish(staticThree, now+uint64(2*time.Minute/time.Millisecond)+1)
	if manager.admitInboundPeer(future, staticThree, now) {
		t.Fatal("accepted RouterInfo beyond maximum future skew")
	}
	stored, ok := manager.peers.RouterInfo(current.Hash())
	if !ok || stored.Published != current.Published {
		t.Fatalf("RouterInfo downgrade changed netdb entry: %#v, %t", stored, ok)
	}
}

type ntcp2PreferenceListener struct{ address net.Addr }

func (l ntcp2PreferenceListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l ntcp2PreferenceListener) Close() error              { return nil }
func (l ntcp2PreferenceListener) Addr() net.Addr            { return l.address }

func TestNTCP2AddressSelectionDistinguishesPreferenceAndRequirement(t *testing.T) {
	tests := []struct {
		name     string
		listener net.Listener
		want     ntcp2AddressMode
	}{
		{"outbound only", nil, ntcp2AddressPreferIPv4},
		{"IPv4", ntcp2PreferenceListener{address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}, ntcp2AddressRequireIPv4},
		{"dual stack wildcard", ntcp2PreferenceListener{address: &net.TCPAddr{IP: net.IPv6unspecified}}, ntcp2AddressPreferIPv4},
		{"specific IPv6", ntcp2PreferenceListener{address: &net.TCPAddr{IP: net.ParseIP("2001:db8::1")}}, ntcp2AddressAny},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ntcp2AddressSelection(test.listener); got != test.want {
				t.Fatalf("address selection = %d, want %d", got, test.want)
			}
		})
	}
}

func TestSelectNTCP2AddressIPv4PreferenceFallsBackToIPv6(t *testing.T) {
	owner, _, _ := newNTCP2TestLocal(t, "[2001:db8::1]:12345")
	info := owner.Snapshot()
	selected, err := selectNTCP2AddressForNetwork(info, ntcp2AddressPreferIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if selected.host != "2001:db8::1" || selected.port != 12345 {
		t.Fatalf("IPv6 fallback = %s:%d", selected.host, selected.port)
	}
	if _, err = selectNTCP2AddressForNetwork(info, ntcp2AddressRequireIPv4); !errors.Is(err, ErrNTCP2Peer) {
		t.Fatalf("strict IPv4 selection error = %v, want %v", err, ErrNTCP2Peer)
	}
}

func TestSelectNTCP2AddressIPv4PreferenceSkipsEarlierIPv6(t *testing.T) {
	owner, _, _ := newNTCP2TestLocalWithEndpoints(t, "[2001:db8::1]:12345", "192.0.2.1:23456")
	selected, err := selectNTCP2AddressForNetwork(owner.Snapshot(), ntcp2AddressPreferIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if selected.host != "192.0.2.1" || selected.port != 23456 {
		t.Fatalf("preferred address = %s:%d, want 192.0.2.1:23456", selected.host, selected.port)
	}
}

func newNTCP2TestLocal(t *testing.T, endpoint string) (*transportTestLocal, []byte, []byte) {
	t.Helper()
	return newNTCP2TestLocalWithEndpoints(t, endpoint)
}

func newNTCP2TestLocalWithEndpoints(t *testing.T, endpoints ...string) (*transportTestLocal, []byte, []byte) {
	t.Helper()
	local, err := foundation.GenerateLocalAddress()
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
	owner, err := newTransportTestLocal(transportTestLocalConfig{Local: local, RouterVersion: "0.9.66"})
	if err != nil {
		t.Fatal(err)
	}
	addresses := make([]transportTestAddress, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host, port, splitErr := net.SplitHostPort(endpoint)
		if splitErr != nil {
			t.Fatal(splitErr)
		}
		addresses = append(addresses, transportTestAddress{
			Transport: "NTCP2",
			Cost:      3,
			Options: []transportTestOption{
				{Key: "host", Value: host},
				{Key: "i", Value: foundation.EncodeI2PBase64(iv)},
				{Key: "port", Value: port},
				{Key: "s", Value: foundation.EncodeI2PBase64(static.PublicKey().Bytes())},
				{Key: "v", Value: "2"},
			},
		})
	}
	if err = owner.ReplaceAddresses(addresses); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(transportTestReachable)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	return owner, static.Bytes(), iv
}

func testECDHPublic(t *testing.T, private []byte) []byte {
	t.Helper()
	public, err := ecdhPublic(private)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func TestNTCP2ManagerReleasesResponderOnPostConstructionFailure(t *testing.T) {
	local, staticPrivate, staticIV := newNTCP2TestLocal(t, "127.0.0.1:1")
	localHash := local.Hash()
	initiator, err := dataplanentcp2.NewInitiator(testECDHPublic(t, staticPrivate))
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.ReleaseSensitive()
	request, err := initiator.BuildSessionRequest(make([]byte, dataplanentcp2.SessionRequestCiphertextLen), localHash[:], staticIV, nil, dataplanentcp2.SessionRequestOptions{
		NetworkID: 2, Version: 2, Timestamp: 1,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	responder, options, err := dataplanentcp2.ParseSessionRequest(request, staticPrivate, localHash[:], staticIV, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewNTCP2Manager(NTCP2ManagerConfig{StaticPrivate: staticPrivate, StaticIV: staticIV})
	if err != nil {
		t.Fatal(err)
	}
	manager.bindings = TransportBindings{LocalInfo: local, Clock: WallClock{}}
	manager.readSessionRequest = func(io.Reader, []byte, []byte, []byte, uint8, bool) (*dataplanentcp2.Responder, dataplanentcp2.SessionRequestOptions, error) {
		return responder, options, nil
	}
	server, client := net.Pipe()
	defer client.Close()
	manager.acceptOne(server)
	if _, err = responder.BuildSessionCreated(make([]byte, dataplanentcp2.SessionRequestCiphertextLen), localHash[:], nil, dataplanentcp2.SessionCreatedOptions{}); !errors.Is(err, dataplanentcp2.ErrHandshake) {
		t.Fatalf("responder remained usable after manager timestamp rejection: %v", err)
	}
}
