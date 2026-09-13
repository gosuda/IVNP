package overlaybridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

func testDescriptor() overlay.FabricDescriptor {
	return overlay.FabricDescriptor{
		ID: overlay.FabricID(sha256.Sum256([]byte("test-fabric"))), NetworkID: 77, MaxPeers: 8,
	}
}

func testRealmID() overlay.RealmID {
	return overlay.RealmID(sha256.Sum256([]byte("test-realm")))
}

func freeTCP(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func realmSpec(fabrics []string, admission overlay.AdmissionMode, psk []byte) RealmSpec {
	return RealmSpec{
		ID: testRealmID(), Admission: admission, PSK: psk,
		Discovery: overlay.DiscoveryLocalOnly, Privacy: overlay.PrivacyExplicitDirect,
		Routing: overlay.RoutingOverlayDirect, Publication: overlay.PublicationNone,
		Prefix:  overlay.PrefixPolicy{Mode: overlay.PrefixDisabled},
		Fabrics: fabrics, AcknowledgeOpen: true, AcknowledgeExposure: true,
	}
}

func fabricRuntimeForTest(desc overlay.FabricDescriptor) *fabricRuntime {
	return &fabricRuntime{
		carrier: &fabricCarrier{fabric: desc.ID, netID: desc.NetworkID, maxPeers: desc.MaxPeers},
		peers:   make(map[foundation.Hash]overlay.RouteCandidate),
		router:  overlay.RouterID(sha256.Sum256([]byte("test-router"))),
	}
}

func testScope() overlay.ChannelScope {
	return overlay.ChannelScope{
		Fabric: testDescriptor().ID, NetworkID: 77, Realm: testRealmID(),
		Endpoint: overlay.EndpointID{9}, Port: 47001, Selector: 1,
		Protocol: overlay.EndpointProtocolIVNPStream, Class: overlay.RouteDirect,
		Exposure: overlay.PrivacyExplicitDirect, PolicyGen: 3,
	}
}

func TestFrameRoundTrip(t *testing.T) {
	scope := testScope()
	key := bytes.Repeat([]byte{7}, 32)
	exporter := bytes.Repeat([]byte{3}, 32)
	credential := []byte("membership-doc")
	frame, err := encodeFrame(scope, credential, key, exporter)
	if err != nil {
		t.Fatal(err)
	}
	gotScope, gotCred, mac, raw, err := readFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if gotScope != scope {
		t.Fatalf("scope %+v != %+v", gotScope, scope)
	}
	if !bytes.Equal(gotCred, credential) {
		t.Fatal("credential mismatch")
	}
	if subtle.ConstantTimeCompare(mac, admissionMAC(key, exporter, raw)) != 1 {
		t.Fatal("MAC does not cover the exact received body")
	}
}

func TestFrameNoKey(t *testing.T) {
	frame, err := encodeFrame(testScope(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, mac, _, err := readFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(mac, make([]byte, 32)) != 1 {
		t.Fatal("no-key frame carried a nonzero MAC")
	}
}

func TestReadFrameRejectsCorruption(t *testing.T) {
	frame, err := encodeFrame(testScope(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := readFrame(bytes.NewReader(frame[:10])); err == nil {
		t.Fatal("truncated frame accepted")
	}
	bad := append([]byte(nil), frame...)
	bad[2] ^= 0xff // magic byte
	if _, _, _, _, err := readFrame(bytes.NewReader(bad)); err == nil {
		t.Fatal("bad magic accepted")
	}
}

func TestDecodeScopeRejectsZeroFields(t *testing.T) {
	var buf bytes.Buffer
	encodeScope(testScope(), &buf)
	raw := buf.Bytes()
	raw[32] = 0 // NetworkID
	if _, err := decodeScope(raw); err == nil {
		t.Fatal("zero network id accepted")
	}
}

func TestAdmissionMACDetectsMutation(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	exporter := bytes.Repeat([]byte{3}, 32)
	frame, err := encodeFrame(testScope(), []byte("cred"), key, exporter)
	if err != nil {
		t.Fatal(err)
	}
	_, _, mac, raw, err := readFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), raw...)
	mutated[len(mutated)-1] ^= 1 // credential body byte
	if subtle.ConstantTimeCompare(mac, admissionMAC(key, exporter, mutated)) == 1 {
		t.Fatal("MAC survived a mutated body")
	}
}

func TestStaticSecretsLeaseCopiesAndWipes(t *testing.T) {
	realm := testRealmID()
	secrets := &staticSecrets{keys: map[overlay.RealmID][]byte{realm: []byte("realm-key")}}
	lease, err := secrets.Lease(t.Context(), realm, overlay.KeyPurposeNetworkAdmission)
	if err != nil {
		t.Fatal(err)
	}
	key := lease.Key()
	key[0] ^= 0xff // mutating the lease must not corrupt the stored key
	if secrets.keys[realm][0] == key[0] {
		t.Fatal("lease did not hand out an owned copy")
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(key, make([]byte, len(key))) != 1 {
		t.Fatal("release did not wipe the leased key")
	}
	if _, err := secrets.Lease(t.Context(), realm, overlay.KeyPurpose(99)); err == nil {
		t.Fatal("a non-admission purpose was leased")
	}
	if _, err := secrets.Lease(t.Context(), overlay.RealmID{1}, overlay.KeyPurposeNetworkAdmission); err == nil {
		t.Fatal("an unconfigured realm was leased")
	}
}

func TestInsertPeerDerivesFromDestination(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	identity, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	runtime := fabricRuntimeForTest(testDescriptor())
	peer := StaticPeer{Destination: identity.Bytes(), Contact: "ivnp-tls@127.0.0.1:47001"}
	if err := runtime.insertPeer(peer); err != nil {
		t.Fatal(err)
	}
	endpoint, err := overlay.EndpointIDFromDestination(identity.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	candidate, ok := runtime.peers[foundation.Hash(endpoint)]
	if !ok {
		t.Fatal("peer not keyed by its endpoint hash")
	}
	pub := dest.SigningPublic()
	if !bytes.Equal(candidate.ContactKey[:], pub) {
		t.Fatal("contact key is not the destination's signing public key")
	}
}

func TestInsertPeerValidation(t *testing.T) {
	runtime := fabricRuntimeForTest(testDescriptor())
	endpoint := overlay.EndpointID{1}
	var key [32]byte
	key[0] = 1

	if err := runtime.insertPeer(StaticPeer{Contact: "ivnp-tls@127.0.0.1:1"}); err == nil {
		t.Fatal("peer without identity was accepted")
	}
	if err := runtime.insertPeer(StaticPeer{
		EndpointID: endpoint, ContactKey: key, Contact: "ntcp2@127.0.0.1:1",
	}); err == nil {
		t.Fatal("peer on a non-ivnp-tls transport was accepted")
	}
}

func TestInsertPeerBound(t *testing.T) {
	desc := testDescriptor()
	desc.MaxPeers = 1
	runtime := fabricRuntimeForTest(desc)
	var key [32]byte
	key[0] = 1
	if err := runtime.insertPeer(StaticPeer{
		EndpointID: overlay.EndpointID{1}, ContactKey: key, Contact: "ivnp-tls@127.0.0.1:1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.insertPeer(StaticPeer{
		EndpointID: overlay.EndpointID{2}, ContactKey: key, Contact: "ivnp-tls@127.0.0.1:2",
	}); err == nil {
		t.Fatal("membership beyond the descriptor bound was accepted")
	}
}

func TestLookupPeerStampsRealm(t *testing.T) {
	runtime := fabricRuntimeForTest(testDescriptor())
	var key [32]byte
	key[0] = 1
	endpoint := overlay.EndpointID{1}
	if err := runtime.insertPeer(StaticPeer{
		EndpointID: endpoint, ContactKey: key, Contact: "ivnp-tls@127.0.0.1:1",
	}); err != nil {
		t.Fatal(err)
	}
	realm := overlay.RealmID{42}
	candidates, err := runtime.LookupPeer(t.Context(), overlay.PeerRef{
		Realm: realm, Locator: overlay.Locator{Kind: overlay.LocatorDestinationHash, Hash: foundation.Hash(endpoint)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Realm != realm {
		t.Fatalf("candidate realm not stamped: %+v", candidates)
	}
}

// TestFabricDialListenLoopback runs two bridges on one fabric over real TCP:
// TLS 1.3 with the destination's pinned Ed25519 key, exporter-bound admission,
// scope echo, and service routing.
func TestFabricDialListenLoopback(t *testing.T) {
	desc := testDescriptor()
	listenAddr := freeTCP(t)

	bridgeA, err := Open(t.Context(), Spec{
		Fabrics: []FabricSpec{{Name: "f", Descriptor: desc, IdentityRef: "a", Listeners: []string{listenAddr}}},
		Realm:   realmSpec([]string{"f"}, overlay.AdmissionOpen, nil),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridgeA.Close()

	destA, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destA.ReleaseSensitive()
	identityA, err := destA.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonicalA := identityA.Bytes()
	endpointA, err := overlay.EndpointIDFromDestination(canonicalA)
	if err != nil {
		t.Fatal(err)
	}
	svcA, err := bridgeA.OpenService(overlay.ServiceSpec{
		Destination: canonicalA, Port: 47001,
		Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Publication: overlay.PublicationNone,
		Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
	}, destA)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := svcA.Listen(overlay.ListenPolicy{
		Protocols: []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Classes:   []overlay.RouteClass{overlay.RouteDirect},
		Privacy:   overlay.PrivacyExplicitDirect, Queue: 8,
	})
	if err != nil {
		t.Fatal(err)
	}

	var keyA [32]byte
	copy(keyA[:], destA.SigningPublic())
	bridgeB, err := Open(t.Context(), Spec{
		Fabrics: []FabricSpec{{
			Name: "f", Descriptor: desc, IdentityRef: "b",
			Peers: []StaticPeer{{
				EndpointID: endpointA, ContactKey: keyA, Contact: "ivnp-tls@" + listenAddr,
			}},
		}},
		Realm: realmSpec([]string{"f"}, overlay.AdmissionOpen, nil),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridgeB.Close()

	svcB, err := bridgeB.OpenService(overlay.ServiceSpec{
		Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Publication: overlay.PublicationNone,
		Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := svcB.Dial(ctx, overlay.ServiceTarget{
		Endpoint: overlay.EndpointRef{ID: endpointA}, Port: 47001,
	}, overlay.DialPolicy{
		Fabrics:           []overlay.FabricID{desc.ID},
		RouteClasses:      []overlay.RouteClass{overlay.RouteDirect},
		EndpointProtocols: []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Privacy:           overlay.PrivacyExplicitDirect,
		Fallback:          overlay.ProtocolIVNPOnly, Failover: overlay.FailoverReconnect,
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(inbound, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q", buf)
	}
	if _, err := inbound.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("read %q", buf)
	}
}

// TestFabricPSKAdmission covers both directions: the right realm key admits
// the channel, the wrong key is rejected at admission verification.
func TestFabricPSKAdmission(t *testing.T) {
	desc := testDescriptor()
	psk := bytes.Repeat([]byte{5}, 32)

	dial := func(t *testing.T, pskB []byte) error {
		listenAddr := freeTCP(t)
		bridgeA, err := Open(t.Context(), Spec{
			Fabrics: []FabricSpec{{Name: "f", Descriptor: desc, IdentityRef: "a", Listeners: []string{listenAddr}}},
			Realm:   realmSpec([]string{"f"}, overlay.AdmissionPSK, psk),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer bridgeA.Close()

		destA, err := foundation.GenerateLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		defer destA.ReleaseSensitive()
		identityA, err := destA.Identity()
		if err != nil {
			t.Fatal(err)
		}
		endpointA, err := overlay.EndpointIDFromDestination(identityA.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		svcA, err := bridgeA.OpenService(overlay.ServiceSpec{
			Destination: identityA.Bytes(), Port: 47001,
			Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
			Publication: overlay.PublicationNone,
			Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
		}, destA)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := svcA.Listen(overlay.ListenPolicy{
			Protocols: []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
			Classes:   []overlay.RouteClass{overlay.RouteDirect},
			Privacy:   overlay.PrivacyExplicitDirect, Queue: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := listener.Accept(context.Background())
			if err == nil {
				_ = conn.Close()
			}
		}()

		var keyA [32]byte
		copy(keyA[:], destA.SigningPublic())
		bridgeB, err := Open(t.Context(), Spec{
			Fabrics: []FabricSpec{{
				Name: "f", Descriptor: desc, IdentityRef: "b",
				Peers: []StaticPeer{{
					EndpointID: endpointA, ContactKey: keyA, Contact: "ivnp-tls@" + listenAddr,
				}},
			}},
			Realm: realmSpec([]string{"f"}, overlay.AdmissionPSK, pskB),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer bridgeB.Close()

		svcB, err := bridgeB.OpenService(overlay.ServiceSpec{
			Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
			Publication: overlay.PublicationNone,
			Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		conn, err := svcB.Dial(ctx, overlay.ServiceTarget{
			Endpoint: overlay.EndpointRef{ID: endpointA}, Port: 47001,
		}, overlay.DialPolicy{
			Fabrics:           []overlay.FabricID{desc.ID},
			RouteClasses:      []overlay.RouteClass{overlay.RouteDirect},
			EndpointProtocols: []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
			Privacy:           overlay.PrivacyExplicitDirect,
			Fallback:          overlay.ProtocolIVNPOnly, Failover: overlay.FailoverReconnect,
		})
		if err != nil {
			return err
		}
		// Close error is not the admission verdict: the accept side may
		// already have closed, making close_notify a write on a dead socket.
		_ = conn.Close()
		return nil
	}

	if err := dial(t, psk); err != nil {
		t.Fatalf("matching PSK dial failed: %v", err)
	}
	if err := dial(t, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("wrong PSK was admitted")
	}
}
