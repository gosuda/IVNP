package overlaybridge

import (
	"runtime"
	"sort"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/overlay"
)

// mappingOf round-trips presence entries through the wire format the way the
// core's verifySignedPresence does before a record may carry them.
func mappingOf(t *testing.T, entries []foundation.MappingEntry) foundation.Mapping {
	t.Helper()
	sorted := append([]foundation.MappingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return string(sorted[i].Key) < string(sorted[j].Key)
	})
	n, err := foundation.MappingEncodedLen(sorted)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, n)
	if _, err := foundation.MarshalMappingTo(buf, sorted); err != nil {
		t.Fatal(err)
	}
	m, consumed, err := foundation.ParseMapping(buf)
	if err != nil || consumed != n {
		t.Fatalf("mapping parse = %v, %d", err, consumed)
	}
	return m
}

// SignPresence fills the owner-side fields from the fabric's real contact
// surface and the destination's verified Ed25519 key, so the embedded path
// can satisfy DualPresence without a third-party binding provider.
func TestBridgeBindingSignsPresence(t *testing.T) {
	desc := testDescriptor()
	listenAddr := freeTCP(t)
	bridgeA, err := Open(t.Context(), Spec{
		Fabrics: []FabricSpec{{
			Name: "f", Descriptor: desc, IdentityRef: "a",
			Listeners: []string{listenAddr}, Advertise: []string{"ivnp-tls@9.9.9.9:47001"},
		}},
		Realm: realmSpec([]string{"f"}, overlay.AdmissionOpen, nil),
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
	svcA, err := bridgeA.OpenService(overlay.ServiceSpec{
		Destination: canonicalA, Port: 47001,
		Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Publication: overlay.PublicationNone,
		Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
	}, destA)
	if err != nil {
		t.Fatal(err)
	}
	defer svcA.Close()

	binding := &bridgeBinding{bridge: bridgeA}
	entries, err := binding.SignPresence(t.Context(), overlay.DualPresence{
		RealmID: testRealmID(), Incarnation: 7, Sequence: 3, Port: 47001,
	}, canonicalA)
	if err != nil {
		t.Fatal(err)
	}
	presence, err := overlay.ParseDualPresence(mappingOf(t, entries), desc)
	if err != nil {
		t.Fatal(err)
	}
	if presence.FabricID != desc.ID || presence.NetworkID != desc.NetworkID {
		t.Fatalf("presence fabric = %+v/%d, want %+v/%d", presence.FabricID, presence.NetworkID, desc.ID, desc.NetworkID)
	}
	if presence.RealmID != testRealmID() || presence.Port != 47001 || presence.Incarnation != 7 || presence.Sequence != 3 {
		t.Fatalf("presence scope = %+v", presence)
	}
	pub := destA.SigningPublic()
	if !equalBytes(presence.ContactKey[:], pub) {
		t.Fatal("presence contact key is not the destination's signing key")
	}
	if !presence.HasCapability(overlay.CapDirect) {
		t.Fatal("presence lacks the direct capability despite a public endpoint")
	}
	if len(presence.Endpoints) != 1 || presence.Endpoints[0].String() != "ivnp-tls@9.9.9.9:47001" {
		t.Fatalf("presence endpoints = %v", presence.Endpoints)
	}

	// An endpoint the carrier never registered cannot claim presence.
	destB, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destB.ReleaseSensitive()
	identityB, err := destB.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.SignPresence(t.Context(), overlay.DualPresence{
		RealmID: testRealmID(), Incarnation: 7, Sequence: 3, Port: 47001,
	}, identityB.Bytes()); err == nil {
		t.Fatal("presence signed for an unregistered endpoint")
	}
}

// A listener on a non-public address never invents reachability: the
// projection carries no endpoints and no direct capability.
func TestBridgeBindingOmitsNonPublicEndpoints(t *testing.T) {
	desc := testDescriptor()
	bridgeA, err := Open(t.Context(), Spec{
		Fabrics: []FabricSpec{{
			Name: "f", Descriptor: desc, IdentityRef: "a", Listeners: []string{freeTCP(t)},
		}},
		Realm: realmSpec([]string{"f"}, overlay.AdmissionOpen, nil),
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
	svcA, err := bridgeA.OpenService(overlay.ServiceSpec{
		Destination: identityA.Bytes(), Port: 47001,
		Protocols:   []overlay.EndpointProtocol{overlay.EndpointProtocolIVNPStream},
		Publication: overlay.PublicationNone,
		Privacy:     overlay.PrivacyExplicitDirect, Routing: overlay.RoutingOverlayDirect,
	}, destA)
	if err != nil {
		t.Fatal(err)
	}
	defer svcA.Close()

	binding := &bridgeBinding{bridge: bridgeA}
	entries, err := binding.SignPresence(t.Context(), overlay.DualPresence{
		RealmID: testRealmID(), Incarnation: 1, Sequence: 1, Port: 47001,
	}, identityA.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	presence, err := overlay.ParseDualPresence(mappingOf(t, entries), desc)
	if err != nil {
		t.Fatal(err)
	}
	if len(presence.Endpoints) != 0 || presence.HasCapability(overlay.CapDirect) {
		t.Fatalf("presence invents reachability: %v caps %v", presence.Endpoints, presence.Capabilities)
	}
}

// Closing a service must drop its inbound routes and TLS contact key.
func TestServiceCloseUntracksContactKey(t *testing.T) {
	desc := testDescriptor()
	bridgeA, err := Open(t.Context(), Spec{
		Fabrics: []FabricSpec{{Name: "f", Descriptor: desc, IdentityRef: "a", Listeners: []string{freeTCP(t)}}},
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
	carrier := bridgeA.mux.fabrics[desc.ID]
	if carrier == nil || !carrier.hasCert(endpointA) {
		t.Fatal("service key was not registered")
	}
	if err := svcA.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for carrier.hasCert(endpointA) {
		if time.Now().After(deadline) {
			t.Fatal("closed service left its contact key registered")
		}
		runtime.Gosched()
	}
	if len(bridgeA.mux.services) != 0 {
		t.Fatal("closed service left inbound routes")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
