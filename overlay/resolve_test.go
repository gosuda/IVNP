package overlay

import (
	"context"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func canonicalDest(t *testing.T, dest *foundation.LocalDestination) []byte {
	t.Helper()
	identity, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Bytes()
}

type stubNetDB struct {
	records map[foundation.Hash]DestinationRecord
	routers map[foundation.Hash]RouterRecord
	err     error
}

func (s *stubNetDB) LookupRouter(ctx context.Context, h foundation.Hash) (RouterRecord, error) {
	record, ok := s.routers[h]
	if !ok {
		return RouterRecord{}, CodeUnreachable.Wrap("no router record")
	}
	return record, nil
}

func (s *stubNetDB) LookupDestination(ctx context.Context, h foundation.Hash) (DestinationRecord, error) {
	if s.err != nil {
		return DestinationRecord{}, s.err
	}
	record, ok := s.records[h]
	if !ok {
		return DestinationRecord{}, CodeUnreachable.Wrap("no destination record")
	}
	return record, nil
}

func (s *stubNetDB) PublishOwnedRouter(ctx context.Context, r RouterRecord) (PublicationObservation, error) {
	return PublicationObservation{}, nil
}

func (s *stubNetDB) PublishOwnedDestination(ctx context.Context, r DestinationRecord) (PublicationObservation, error) {
	return PublicationObservation{}, nil
}

// stubFabric supplies runtimes; the native runtime exposes the stub netdb.
type stubFabric struct {
	native PublicNetDBBackend
	local  map[foundation.Hash]RouteCandidate
	driver PublicationDriver
	err    error
}

func (s *stubFabric) OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	if cfg.Kind == ContextNativeI2P {
		return &stubRuntime{netdb: s.native, driver: s.driver}, nil
	}
	return &stubRuntime{local: s.local}, nil
}

type stubRuntime struct {
	netdb  PublicNetDBBackend
	local  map[foundation.Hash]RouteCandidate
	driver PublicationDriver
}

func (r *stubRuntime) RouterID() RouterID { return RouterID{1} }

func (r *stubRuntime) LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	c, ok := r.local[ref.Locator.Hash]
	if !ok {
		return nil, CodeUnreachable.Wrap("no local candidate")
	}
	return []RouteCandidate{c}, nil
}

func (r *stubRuntime) NetDB() (PublicNetDBBackend, error) {
	if r.netdb == nil {
		return nil, CodeUnsupportedCapability.Wrap("no netdb")
	}
	return r.netdb, nil
}

func (r *stubRuntime) PublicationDriver(EndpointRef) PublicationDriver { return r.driver }

func (r *stubRuntime) Ready(ctx context.Context) (Connectivity, error) {
	return Connectivity{Connected: true, PublicLookup: r.netdb != nil}, nil
}

func (r *stubRuntime) Close() error { return nil }

func dualHost(t *testing.T, fabric FabricProvider) (*Host, *Realm, *NetworkContext, *NetworkContext) {
	t.Helper()
	host := testHost(t, TopologyPublicDualStack)
	if fabric != nil {
		if err := host.RegisterProvider(fabric); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID:                  PublicFastRealmID,
		Contexts:            []ContextID{native.id, fast.id},
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryHedged,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOpportunistic,
		Publication:         PublicationLS2,
		Prefix:              PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, realm, native, fast
}

func testPolicy(fabrics ...FabricID) DialPolicy {
	return DialPolicy{
		Fabrics:           fabrics,
		RouteClasses:      []RouteClass{RouteDirect, RouteRouted, RouteNativeI2P},
		EndpointProtocols: []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream},
		Privacy:           PrivacyExplicitDirect,
		Fallback:          ProtocolIVNPPreferred,
		Failover:          FailoverReconnect,
	}
}

func TestResolvePublicPresence(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()

	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	record := signedLS2(t, dest, entries)
	endpoint := EndpointID(dest.Hash())
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: record, Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})

	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone,
		Privacy:     PrivacyExplicitDirect,
		Routing:     RoutingOpportunistic,
		Protocols:   []EndpointProtocol{EndpointProtocolIVNPStream},
		Port:        47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonicalDest(t, dest)}, Port: 47001}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := svc.realm.resolveCandidates(context.Background(), target, eff)
	if err != nil {
		t.Fatal(err)
	}
	var direct, native int
	for _, c := range candidates {
		switch c.Class {
		case RouteDirect:
			direct++
			if c.Contact == nil || c.Contact.Address != presence.Endpoints[0].Address {
				t.Fatalf("direct contact mismatch: %+v", c)
			}
		case RouteNativeI2P:
			native++
		}
	}
	if direct != 1 || native != 1 {
		t.Fatalf("candidates: direct=%d native=%d", direct, native)
	}
	_ = host
}

func TestResolveLocalOnly(t *testing.T) {
	local := make(map[foundation.Hash]RouteCandidate)
	host := testHost(t, TopologyIsolated)
	if err := host.RegisterProvider(&stubFabric{local: local}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	privateFabric := FabricConfig{
		Kind:        ContextIVNP,
		Descriptor:  privateDescriptor(),
		IdentityRef: "ivnp-router",
		StateDir:    "state-ivnp",
	}
	fast, err := host.OpenFabric(ctx, privateFabric)
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID:              PublicFastRealmID,
		Contexts:        []ContextID{fast.id},
		Admission:       AdmissionOpen,
		AcknowledgeOpen: true,
		Discovery:       DiscoveryLocalOnly,
		Privacy:         PrivacyPrivateConfined,
		Routing:         RoutingOverlayDirect,
		Publication:     PublicationNone,
		Prefix:          PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	endpoint := EndpointID(dest.Hash())
	local[dest.Hash()] = RouteCandidate{
		Endpoint: endpoint, Fabric: privateDescriptor().ID, NetworkID: 88,
		Realm: PublicFastRealmID, Class: RouteDirect, Carrier: "mem",
		ContactKey: testChannelKey,
		NotAfter:   time.Now().Add(time.Hour).Unix(), Exposure: PrivacyPrivateConfined,
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyPrivateConfined,
		Routing:   RoutingOverlayDirect,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonicalDest(t, dest)}, Port: 1}
	policy := testPolicy(privateDescriptor().ID)
	policy.RouteClasses = []RouteClass{RouteDirect}
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	found, err := svc.realm.resolveCandidates(ctx, target, eff)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Carrier != "mem" {
		t.Fatalf("local candidates: %+v", found)
	}
}

func TestDialCommitsWinner(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	endpoint := EndpointID(dest.Hash())
	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	scope := ChannelScope{
		Fabric: PublicFastFabricID, NetworkID: 77, Realm: PublicFastRealmID,
		Endpoint: endpoint, Port: 47001, Protocol: EndpointProtocolIVNPStream,
		Class: RouteDirect, Exposure: PrivacyExplicitDirect,
	}
	transport := &stubTransport{
		carrier: presence.Endpoints[0].Transport,
		caps:    TransportCapabilities{Exporter: true, DirectBinding: true},
		binding: scope, key: presence.ContactKey,
	}
	if err := host.RegisterProvider(transport); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonicalDest(t, dest)}, Port: 47001},
		policy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info := conn.RouteInfo()
	if info.Class != RouteDirect || info.Fabric != PublicFastFabricID || info.Endpoint != endpoint {
		t.Fatalf("route info: %+v", info)
	}
	if conn.FailoverStatus() != ConnActiveIVNP {
		t.Fatalf("state %v", conn.FailoverStatus())
	}
}
