package overlay

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// TestLocalContactShortPublicKey: a wrong-length key must error, not panic.
func TestLocalContactShortPublicKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnvelope()
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	record, err := MarshalLocalContact(priv, entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLocalContact(record, make([]byte, 8)); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("short key: %v", err)
	}
}

// TestPresenceSecondWithoutFirst: x-ivnp.e1 without x-ivnp.e0 is invalid.
func TestPresenceSecondWithoutFirst(t *testing.T) {
	p := testPresence()
	p.Endpoints = append(p.Endpoints,
		Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("1.0.0.4:4433")})
	entries, err := p.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	var hashed []foundation.MappingEntry
	for _, e := range entries {
		if string(e.Key) == "x-ivnp.e0" || string(e.Key) == "x-ivnp.h" {
			continue
		}
		hashed = append(hashed, e)
	}
	digest, err := presenceDigest(hashed)
	if err != nil {
		t.Fatal(err)
	}
	hashed = append(hashed, foundation.MappingEntry{Key: []byte("x-ivnp.h"), Value: []byte(encode32(digest))})
	m := marshalMapping(t, sortEntries(hashed))
	if _, err := ParseDualPresence(m, testDescriptor()); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("e1 without e0: %v", err)
	}
}

// TestCleartextPresencePrivateEndpoint: a signed presence may not project a
// non-public address into a cleartext record.
func TestCleartextPresencePrivateEndpoint(t *testing.T) {
	for _, text := range []string{
		"tls13@127.0.0.1:9443", "tls13@10.1.2.3:9443", "tls13@[::1]:9443",
		"tls13@[fd00::1]:9443", "tls13@169.254.9.9:9443",
	} {
		p := testPresence()
		ep, err := ParseEndpoint(text)
		if err != nil {
			t.Fatal(err)
		}
		p.Endpoints[0] = ep
		entries, err := p.presenceEntries()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := presenceDigest(entries)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ivnp.h"), Value: []byte(encode32(digest))})
		m := marshalMapping(t, sortEntries(entries))
		if _, err := ParseDualPresence(m, testDescriptor()); !errors.Is(err, CodeEndpointBindingInvalid) {
			t.Fatalf("%s admitted: %v", text, err)
		}
	}
}

// TestPublicPrimaryIgnoresContextOrder: the public strategy must reach the
// native netDB regardless of bound-context slice order.
func TestPublicPrimaryIgnoresContextOrder(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, nil), Provenance: ProvenancePublicNative},
	}}
	host := testHost(t, TopologyPublicDualStack)
	if err := host.RegisterProvider(&stubFabric{native: netdb}); err != nil {
		t.Fatal(err)
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
	// native first in the slice: the order that used to misroute the strategy.
	realm, err := host.OpenRealm(RealmConfig{
		ID:                  PublicFastRealmID,
		Contexts:            []ContextID{native.id, fast.id},
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryPublicPrimary,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOpportunistic,
		Publication:         PublicationNone,
		Prefix:              PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyI2PCompatible,
		Routing:   RoutingNativeI2P,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}}
	policy := testPolicy(NativeI2PFabricID)
	policy.Privacy = PrivacyI2PCompatible
	policy.RouteClasses = []RouteClass{RouteNativeI2P}
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	found, err := realm.resolveCandidates(ctx, target, eff)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Class != RouteNativeI2P {
		t.Fatalf("public primary candidates: %+v", found)
	}
}

// TestConfinedRealmRejectsPublicContext: private_confined may not bind a
// descriptor-marked public IVNP context.
func TestConfinedRealmRejectsPublicContext(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.OpenRealm(RealmConfig{
		ID:              RealmID{7},
		Contexts:        []ContextID{fast.id},
		Admission:       AdmissionOpen,
		AcknowledgeOpen: true,
		Discovery:       DiscoveryLocalOnly,
		Privacy:         PrivacyPrivateConfined,
		Routing:         RoutingOverlayRouted,
		Publication:     PublicationNone,
		Prefix:          PrefixPolicy{Mode: PrefixDisabled},
	})
	if !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("confined realm bound to public fabric: %v", err)
	}
}

// TestConfinedAdmissionFiltersPublicFabric: private_confined drops candidates
// on the public fabric even when the caller lists it.
func TestConfinedAdmissionFiltersPublicFabric(t *testing.T) {
	local := make(map[foundation.Hash]RouteCandidate)
	host := testHost(t, TopologyIsolated)
	if err := host.RegisterProvider(&stubFabric{local: local}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fast, err := host.OpenFabric(ctx, FabricConfig{
		Kind: ContextIVNP, Descriptor: privateDescriptor(),
		IdentityRef: "ivnp-router", StateDir: "state-ivnp",
	})
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: RealmID{8}, Contexts: []ContextID{fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{9}}, Port: 1}
	policy := testPolicy(privateDescriptor().ID, PublicFastFabricID)
	policy.RouteClasses = []RouteClass{RouteDirect}
	policy.Privacy = PrivacyPrivateConfined
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.8:4433")}
	in := []RouteCandidate{
		{Endpoint: target.Endpoint.ID, Fabric: privateDescriptor().ID, NetworkID: 88, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: time.Now().Add(time.Hour).Unix()},
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: time.Now().Add(time.Hour).Unix()},
	}
	out, err := realm.admitCandidates(ctx, target, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Fabric != privateDescriptor().ID {
		t.Fatalf("confined admission kept public fabric: %+v", out)
	}
}

// TestCallerPrivacyConstrainsDial: a caller's i2p_compatible requirement must
// drop direct candidates even in an explicit_direct realm.
func TestCallerPrivacyConstrainsDial(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.Privacy = PrivacyI2PCompatible
	policy.RouteClasses = []RouteClass{RouteNativeI2P}
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{5}}}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.5:4433")}
	in := []RouteCandidate{
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: time.Now().Add(time.Hour).Unix()},
		{Endpoint: target.Endpoint.ID, Fabric: NativeI2PFabricID, NetworkID: WireNetworkIDPublicI2P, Realm: realm.cfg.ID,
			Class: RouteNativeI2P, NotAfter: time.Now().Add(time.Hour).Unix()},
	}
	out, err := realm.admitCandidates(context.Background(), target, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Class != RouteNativeI2P {
		t.Fatalf("caller privacy dropped native or kept direct: %+v", out)
	}
}

// TestServicePrivacyConstrainsDial: a service declared i2p_compatible may not
// be direct-dialed.
func TestServicePrivacyConstrainsDial(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyI2PCompatible,
		Routing: RoutingNativeI2P, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{6}}}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.6:4433")}
	in := []RouteCandidate{
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: time.Now().Add(time.Hour).Unix()},
	}
	out, err := realm.admitCandidates(context.Background(), target, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("service privacy admitted direct: %+v", out)
	}
}

// gatedFabric blocks inside OpenContext until released, so the test controls
// the check-then-insert window deterministically.
type gatedFabric struct {
	entered chan struct{}
	release chan struct{}
}

func (s *gatedFabric) OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error) {
	s.entered <- struct{}{}
	<-s.release
	return &stubRuntime{}, nil
}

// TestOpenFabricAtomicAdmission: concurrent opens must admit exactly one
// native context even while a provider call is in flight.
func TestOpenFabricAtomicAdmission(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	gate := &gatedFabric{entered: make(chan struct{}, 4), release: make(chan struct{})}
	if err := host.RegisterProvider(gate); err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := nativeFabric()
			cfg.IdentityRef = fmt.Sprintf("native-%d", i)
			cfg.StateDir = fmt.Sprintf("state-%d", i)
			if _, err := host.OpenFabric(context.Background(), cfg); err == nil {
				admitted.Add(1)
			}
		}(i)
	}
	// The first opener is inside the provider with its slot already reserved;
	// the rest are still queued on the admission lock.
	<-gate.entered
	close(gate.release)
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("admitted %d native contexts", admitted.Load())
	}
}

// TestConnFSMConcurrentAccess exercises state reads against transitions under
// the race detector.
func TestConnFSMConcurrentAccess(t *testing.T) {
	fsm := newConnFSM()
	if err := fsm.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := fsm.ContactFound(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				fsm.State()
				fsm.Commit(RouteDirect)
				fsm.Revoke()
				fsm.Drained()
			}
		}()
	}
	wg.Wait()
	if fsm.State() != ConnClosed {
		t.Fatalf("state %v", fsm.State())
	}
}

// gatedTransport blocks inside Setup until the test releases it, so a losing
// setup can be held in flight deterministically. speculative reports the
// provider's safe-to-race capability.
type gatedTransport struct {
	carrier     string
	key         [32]byte
	speculative bool
	entered     chan struct{}
	hold        chan struct{}
	done        chan struct{}
	once        sync.Once
	err         error
	ch          *trackedChannel
	// mutate tampers with the returned channel's binding, simulating a
	// carrier that reports a scope other than the one the core requested.
	mutate func(*ChannelScope)
}

func (s *gatedTransport) Carrier() string { return s.carrier }
func (s *gatedTransport) Capabilities() TransportCapabilities {
	return TransportCapabilities{Exporter: true, DirectBinding: true, Speculative: s.speculative}
}
func (s *gatedTransport) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.hold != nil {
		<-s.hold
	}
	if s.err != nil {
		return nil, s.err
	}
	binding := scope
	if s.mutate != nil {
		s.mutate(&binding)
	}
	s.ch.binding = binding
	s.ch.key = s.key
	if s.done != nil {
		s.once.Do(func() { close(s.done) })
	}
	return s.ch, nil
}

type trackedChannel struct {
	stubChannel
	closeOnce sync.Once
	closedCh  chan struct{}
}

func newTrackedChannel() *trackedChannel {
	return &trackedChannel{closedCh: make(chan struct{})}
}

func (c *trackedChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return nil
}

// TestDialClosesLateLoserChannel: a setup that completes after the winner
// commits must still have its channel closed.
func TestDialClosesLateLoserChannel(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence()
	presence.Endpoints = append(presence.Endpoints,
		Endpoint{Transport: "tslow", Address: netip.MustParseAddrPort("1.0.0.7:4433")})
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	winner := newTrackedChannel()
	loser := newTrackedChannel()
	winnerHold := make(chan struct{})
	loserEntered := make(chan struct{}, 1)
	loserHold := make(chan struct{})
	loserDone := make(chan struct{})
	if err := host.RegisterProvider(&gatedTransport{carrier: "tls13", key: presence.ContactKey, hold: winnerHold, ch: winner, speculative: true}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&gatedTransport{carrier: "tslow", key: presence.ContactKey, entered: loserEntered, hold: loserHold, done: loserDone, ch: loser, speculative: true}); err != nil {
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
	policy.HedgeDelay = time.Millisecond
	type dialResult struct {
		conn *Connection
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := svc.Dial(context.Background(),
			ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001},
			policy)
		resultCh <- dialResult{conn, err}
	}()
	// Both setups are in flight before the winner completes.
	<-loserEntered
	close(winnerHold)
	res := <-resultCh
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.conn.Close()
	// The loser completes late; the drain path must close its channel.
	close(loserHold)
	<-loserDone
	select {
	case <-loser.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("losing setup channel never closed")
	}
}

// TestApplyPolicyFullValidation: policy replacement re-runs OpenRealm
// validation and rebinds contexts; the realm id is immutable.
func TestApplyPolicyFullValidation(t *testing.T) {
	_, realm, native, fast := dualHost(t, nil)
	cfg := realm.cfg
	changed := cfg
	changed.ID = RealmID{9}
	ctx := context.Background()
	if err := realm.ApplyPolicy(ctx, changed, 0); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("id change: %v", err)
	}
	bad := cfg
	bad.Discovery = DiscoveryMode(99)
	if err := realm.ApplyPolicy(ctx, bad, 0); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("bad enum: %v", err)
	}
	if err := realm.ApplyPolicy(ctx, cfg, 77); !errors.Is(err, CodeRevisionConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	unbound := cfg
	unbound.Contexts = []ContextID{native.id, ContextID(999)}
	if err := realm.ApplyPolicy(ctx, unbound, 0); !errors.Is(err, CodeContextScopeMismatch) {
		t.Fatalf("unknown context: %v", err)
	}
	reversed := cfg
	reversed.Contexts = []ContextID{fast.id, native.id}
	if err := realm.ApplyPolicy(ctx, reversed, 0); err != nil {
		t.Fatalf("valid apply: %v", err)
	}
	if realm.PolicyGen() != 1 {
		t.Fatalf("generation %d", realm.PolicyGen())
	}
	realm.mu.Lock()
	bound := realm.bound
	realm.mu.Unlock()
	if len(bound) != 2 || bound[0].id != fast.id || bound[1].id != native.id {
		t.Fatalf("rebind did not apply: %+v", bound)
	}
}

// TestServiceDialAfterClose and connection deregistration.
func TestServiceLifecycleConns(t *testing.T) {
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
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	if err := host.RegisterProvider(&stubTransport{
		carrier: presence.Endpoints[0].Transport,
		caps:    TransportCapabilities{Exporter: true, DirectBinding: true},
		key:     presence.ContactKey,
	}); err != nil {
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
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001}
	conn, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	n := len(svc.conns)
	svc.mu.Unlock()
	if n != 1 {
		t.Fatalf("service tracks %d conns", n)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	n = len(svc.conns)
	svc.mu.Unlock()
	if n != 0 {
		t.Fatalf("closed conn still registered")
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID)); !errors.Is(err, CodeClosed) {
		t.Fatalf("dial on closed service: %v", err)
	}
}

var errStubPathLost = errors.New("path lost")

// flakyChannel fails reads on demand to drive the path-loss transition.
type flakyChannel struct {
	stubChannel
	fail atomic.Bool
}

func (c *flakyChannel) Read(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errStubPathLost
	}
	return 0, nil
}

type chanTransport struct {
	carrier string
	ch      Channel
}

func (s *chanTransport) Carrier() string { return s.carrier }
func (s *chanTransport) Capabilities() TransportCapabilities {
	return TransportCapabilities{Exporter: true, DirectBinding: true}
}
func (s *chanTransport) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	if tracked, ok := s.ch.(*flakyChannel); ok {
		tracked.binding = scope
	}
	return s.ch, nil
}

func dialFlaky(t *testing.T) (*Service, *flakyChannel, ServiceTarget) {
	t.Helper()
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.ReleaseSensitive)
	presence := testPresence()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	flaky := &flakyChannel{stubChannel: stubChannel{key: presence.ContactKey}}
	if err := host.RegisterProvider(&chanTransport{carrier: "tls13", ch: flaky}); err != nil {
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
	return svc, flaky, ServiceTarget{
		Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)},
		Port:     47001,
	}
}

// TestReconnectAfterDeliveryRequiresContract: once data may have been
// delivered, reconnect without a negotiated resumption contract fails with
// reconnect_required.
func TestReconnectAfterDeliveryRequiresContract(t *testing.T) {
	svc, flaky, target := dialFlaky(t)
	conn, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	flaky.fail.Store(true)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected path failure")
	}
	if conn.FailoverStatus() != ConnPathLost {
		t.Fatalf("state %v", conn.FailoverStatus())
	}
	if _, err := conn.Reconnect(context.Background()); !errors.Is(err, CodeReconnectRequired) {
		t.Fatalf("reconnect after delivery: %v", err)
	}
}

// TestReconnectFreshBeforeDelivery: no data may have been delivered, so a
// fresh bounded setup is permitted.
func TestReconnectFreshBeforeDelivery(t *testing.T) {
	svc, flaky, target := dialFlaky(t)
	conn, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	flaky.fail.Store(true)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected path failure")
	}
	if conn.FailoverStatus() != ConnPathLost {
		t.Fatalf("state %v", conn.FailoverStatus())
	}
	next, err := conn.Reconnect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next == conn {
		t.Fatal("reconnect returned the failed connection")
	}
}

// TestSingleflightDeduplicates: concurrent identical resolutions share one
// lookup execution.
type countingRuntime struct {
	localRuntime
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (r *countingRuntime) LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	r.calls.Add(1)
	r.entered <- struct{}{}
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.localRuntime.LookupPeer(ctx, ref)
}

type fixedFabric struct{ rt ContextRuntime }

func (f *fixedFabric) OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error) {
	return f.rt, nil
}

func TestSingleflightDeduplicates(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	endpoint := EndpointID(dest.Hash())
	rt := &countingRuntime{entered: make(chan struct{}, 4), release: make(chan struct{})}
	rt.peers = make(map[foundation.Hash]RouteCandidate)
	rt.peers[dest.Hash()] = RouteCandidate{
		Endpoint: endpoint, Fabric: privateDescriptor().ID, NetworkID: 88, Realm: RealmID{3},
		Class: RouteDirect, Carrier: "mem", ContactKey: testChannelKey,
		NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	host := testHost(t, TopologyIsolated)
	if err := host.RegisterProvider(&fixedFabric{rt: rt}); err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(context.Background(), FabricConfig{
		Kind: ContextIVNP, Descriptor: privateDescriptor(),
		IdentityRef: "ivnp-router", StateDir: "state-ivnp",
	})
	if err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: RealmID{3}, Contexts: []ContextID{fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonicalDest(t, dest)}, Port: 1}
	policy := testPolicy(privateDescriptor().ID)
	policy.RouteClasses = []RouteClass{RouteDirect}
	policy.Privacy = PrivacyPrivateConfined
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	var leaderErr error
	leaderDone := make(chan struct{})
	go func() {
		_, leaderErr = realm.resolveCandidates(context.Background(), target, eff)
		close(leaderDone)
	}()
	// The leader is inside the provider with its singleflight call registered
	// in the inflight map; it stays registered until release closes, so a
	// joiner sees the in-flight call no matter when it is scheduled.
	<-rt.entered
	ctxJoin, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	joinErrs := make([]error, 3)
	for i := range joinErrs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, joinErrs[i] = realm.resolveCandidates(ctxJoin, target, eff)
		}(i)
	}
	cancel()
	wg.Wait()
	close(rt.release)
	<-leaderDone
	if leaderErr != nil {
		t.Fatalf("leader resolve: %v", leaderErr)
	}
	for i, err := range joinErrs {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("joiner %d should have deduplicated and waited: %v", i, err)
		}
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("singleflight ran %d lookups", rt.calls.Load())
	}
}

// signedELS2 builds a verifiable Encrypted LeaseSet2 record and returns the
// raw bytes plus the blinded DHT hash.
func signedELS2(t *testing.T) ([]byte, foundation.Hash) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var rec []byte
	rec = binary.BigEndian.AppendUint16(rec, uint16(foundation.SigningEdDSASHA512Ed25519))
	rec = append(rec, pub...)
	rec = binary.BigEndian.AppendUint32(rec, uint32(time.Now().Unix()))
	rec = binary.BigEndian.AppendUint16(rec, 600)
	rec = binary.BigEndian.AppendUint16(rec, 0)
	rec = binary.BigEndian.AppendUint16(rec, foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	rec = append(rec, make([]byte, foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)...)
	sig := ed25519.Sign(priv, append([]byte{5}, rec...))
	rec = append(rec, sig...)
	set, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, set.Hash()
}

// TestEncryptedRecordHonestErrors: an ELS2 without local access material
// fails with lookup_capability_required; with a key reference it reports the
// unwired decryption path honestly.
func TestEncryptedRecordHonestErrors(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	raw, blinded := signedELS2(t)
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		blinded:     {Raw: raw, Encrypted: true, Provenance: ProvenancePublicNative},
		dest.Hash(): {Raw: raw, Encrypted: true, Provenance: ProvenancePublicNative},
	}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}}
	_, err = realm.resolveCandidates(context.Background(), target, eff)
	if !errors.Is(err, CodeLookupCapabilityRequired) {
		t.Fatalf("encrypted record without key ref: %v", err)
	}
	target.Endpoint.Encrypted = &EncryptedLookupRef{KeyRef: "client-key", BlindedHash: blinded}
	_, err = realm.resolveCandidates(context.Background(), target, eff)
	if !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("encrypted record with key ref: %v", err)
	}
}

// TestExpiredPresenceNotAdmitted: an expired presence is skipped before the
// rollback floor is consulted; the verified native record still stands.
func TestExpiredPresenceNotAdmitted(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence()
	presence.NotAfter = time.Now().Add(-time.Hour).Unix()
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	found, err := realm.resolveCandidates(context.Background(), target, eff)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range found {
		if c.Class == RouteDirect {
			t.Fatalf("expired presence produced direct candidate: %+v", c)
		}
	}
	if len(realm.floors.floors) != 0 {
		t.Fatalf("expired presence advanced a floor")
	}
}

// TestPrefixCapEnforced: MaxPerPrefix bounds same-prefix contact candidates.
func TestPrefixCapEnforced(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	realm.cfg.Prefix = PrefixPolicy{Mode: PrefixBestEffort, IPv4Prefix: 24, IPv6Prefix: 48, MaxPerPrefix: 1}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{4}}}
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	a := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("8.8.4.1:4433")}
	b := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("8.8.4.2:4433")}
	c := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("1.1.1.1:4433")}
	in := []RouteCandidate{
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &a, NotAfter: time.Now().Add(time.Hour).Unix()},
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &b, NotAfter: time.Now().Add(time.Hour).Unix()},
		{Endpoint: target.Endpoint.ID, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.cfg.ID,
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &c, NotAfter: time.Now().Add(time.Hour).Unix()},
	}
	out, err := realm.admitCandidates(context.Background(), target, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("prefix cap kept %d candidates", len(out))
	}
}

// TestFloorPersistence: exported floors restore into a fresh tracker and
// never regress an existing position.
func TestFloorPersistence(t *testing.T) {
	src := NewFloorTracker()
	key := FloorKey{Endpoint: EndpointID{1}, Fabric: PublicFastFabricID, Realm: PublicFastRealmID, Port: 47001, Format: 1}
	expiry := time.Now().Add(time.Hour).Unix()
	if err := src.Admit(key, 2, 9, [32]byte{3}, expiry); err != nil {
		t.Fatal(err)
	}
	dst := NewFloorTracker()
	dst.Import(src.Export())
	if got := dst.Check(key, 2, 9, [32]byte{3}); got != FloorReplay {
		t.Fatalf("restored floor verdict %v", got)
	}
	dst.Import([]FloorEntry{{Key: key, Incarnation: 1, Sequence: 1, Digest: [32]byte{9}, NotAfter: expiry}})
	if got := dst.Check(key, 2, 9, [32]byte{3}); got != FloorReplay {
		t.Fatalf("import lowered floor, verdict %v", got)
	}
}

// TestWatchEventsClosedOnHostClose: watcher channels close with the host.
func TestWatchEventsClosedOnHostClose(t *testing.T) {
	host, err := NewHost(HostConfig{Topology: TopologyIsolated})
	if err != nil {
		t.Fatal(err)
	}
	ch := host.WatchEvents()
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("watcher channel still open")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher channel never closed")
	}
}

// TestPublishPassesOptionsToDriver: the driver receives verified option
// entries, not a fabricated record.
type captureDriver struct {
	options  []foundation.MappingEntry
	obs      PublicationObservation
	readBack DestinationRecord
}

func (d *captureDriver) Store(ctx context.Context, options []foundation.MappingEntry) (PublicationObservation, error) {
	d.options = append([]foundation.MappingEntry(nil), options...)
	return d.obs, nil
}

func (d *captureDriver) ReadBack(ctx context.Context) (DestinationRecord, error) {
	if d.readBack.Raw == nil {
		return DestinationRecord{}, CodeUnreachable.Wrap("no record")
	}
	return d.readBack, nil
}

func TestPublishPassesOptionsToDriver(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	driver := &captureDriver{obs: PublicationObservation{Accepted: true}}
	_, realm, _, _ := dualHost(t, &stubFabric{driver: driver})
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := []foundation.MappingEntry{{Key: []byte("unrelated"), Value: []byte("v")}}
	pub, err := svc.Publish(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.options) != 1 || string(driver.options[0].Key) != "unrelated" {
		t.Fatalf("driver received %+v", driver.options)
	}
	if pub.State() != PublicationAcknowledged {
		t.Fatalf("state %v", pub.State())
	}
}

// TestPublishRequiresOwnedDestination: an LS2-publishing service without an
// owned destination is rejected at open.
func TestPublishRequiresOwnedDestination(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	_, err := realm.OpenService(ServiceSpec{
		Publication: PublicationLS2, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("publication without destination: %v", err)
	}
}
