package overlay

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

// TestSingleflightSeparatesScopes: the dedup key covers the service port and
// the blinded locator material, so concurrent resolutions under different
// scopes never inherit each other's result.
func TestSingleflightSeparatesScopes(t *testing.T) {
	rt := &countingRuntime{entered: make(chan struct{}, 4), release: make(chan struct{})}
	rt.peers = make(map[foundation.Hash]RouteCandidate)
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
	realm := openAdmissionRealm(t, host, fast, RealmID{3}, AdmissionOpen)
	svc := confinedService(t, realm)

	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	endpoint := EndpointID(dest.Hash())
	candidate := RouteCandidate{
		Endpoint: endpoint, Fabric: privateDescriptor().ID, NetworkID: 88,
		Realm: RealmID{3}, Class: RouteDirect, Carrier: "mem",
		ContactKey: testChannelKey,
		NotAfter:   time.Now().Add(time.Hour).Unix(), Exposure: PrivacyPrivateConfined,
	}
	rt.peers[dest.Hash()] = candidate
	blinded := foundation.Hash{0xbb}
	rt.peers[blinded] = candidate

	policy := confinedPolicy()
	policy.normalize()
	eff, err := realm.effectiveDialPolicy(svc.spec, policy)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(target ServiceTarget) <-chan error {
		done := make(chan error, 1)
		go func() {
			_, err := realm.resolveCandidates(context.Background(), target, eff)
			done <- err
		}()
		return done
	}
	canonical := canonicalDest(t, dest)

	done1 := resolve(ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonical}, Port: 1})
	<-rt.entered
	done2 := resolve(ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonical}, Port: 2})
	select {
	case <-rt.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("different-port resolution joined the leader's singleflight")
	}
	done3 := resolve(ServiceTarget{Endpoint: EndpointRef{
		ID:        endpoint,
		Encrypted: &EncryptedLookupRef{BlindedHash: blinded, KeyRef: "k"},
	}, Port: 1})
	select {
	case <-rt.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("encrypted-locator resolution joined the leader's singleflight")
	}
	close(rt.release)
	for _, done := range []<-chan error{done1, done2, done3} {
		if err := <-done; err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if got := rt.calls.Load(); got != 3 {
		t.Fatalf("singleflight ran %d lookups", got)
	}
}

var errStubSetupFailed = errors.New("setup failed")

// TestNonSpeculativeRunsSequentially: a carrier that does not declare
// Speculative is never launched while another setup is in flight; it runs
// only after the in-flight attempt fails.
func TestNonSpeculativeRunsSequentially(t *testing.T) {
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
	firstHold := make(chan struct{})
	secondEntered := make(chan struct{}, 1)
	second := newTrackedChannel()
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tls13", key: presence.ContactKey, hold: firstHold,
		err: errStubSetupFailed, ch: newTrackedChannel(), speculative: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tslow", key: presence.ContactKey, entered: secondEntered, ch: second,
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
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.HedgeDelay = 5 * time.Millisecond
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
	// The hedge fires while the first attempt is in flight; the
	// non-speculative carrier must stay parked.
	select {
	case <-secondEntered:
		t.Fatal("non-speculative provider raced with the in-flight attempt")
	case <-time.After(50 * time.Millisecond):
	}
	close(firstHold)
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("non-speculative provider never ran after the first attempt failed")
	}
	res := <-resultCh
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.conn.Close()
}

// protoTransport completes setup only when the bound scope declares the
// protocol it can negotiate.
type protoTransport struct {
	carrier string
	accept  EndpointProtocol
	key     [32]byte
}

func (s *protoTransport) Carrier() string { return s.carrier }
func (s *protoTransport) Capabilities() TransportCapabilities {
	return TransportCapabilities{DirectBinding: true}
}
func (s *protoTransport) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	if scope.Protocol != s.accept {
		return nil, CodeEndpointBindingInvalid.Wrap("peer cannot negotiate the bound protocol")
	}
	return &stubChannel{binding: scope, key: s.key}, nil
}

// fixedSessions reports one fixed negotiated protocol.
type fixedSessions struct{ p EndpointProtocol }

func (s fixedSessions) Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error) {
	return fixedSession{p: s.p}, nil
}

type fixedSession struct{ p EndpointProtocol }

func (s fixedSession) Protocol() EndpointProtocol      { return s.p }
func (s fixedSession) Resume() (ResumeContract, error) { return ResumeContract{}, nil }
func (s fixedSession) Close() error                    { return nil }

// TestDialIVNPPreferredFallsBack: ivnp_preferred retries a candidate under
// every allowed protocol; a legacy-only peer commits with a legacy-bound
// channel while ivnp_only refuses the fallback, and a session negotiating
// outside the bound scope fails visibly.
func TestDialIVNPPreferredFallsBack(t *testing.T) {
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
	if err := host.RegisterProvider(&protoTransport{
		carrier: "tls13", accept: EndpointProtocolLegacyStream, key: presence.ContactKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(fixedSessions{p: EndpointProtocolLegacyStream}); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing:   RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream},
		Port:      47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ServiceTarget{
		Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)},
		Port:     47001,
	}
	conn, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	if info := conn.RouteInfo(); info.Protocol != EndpointProtocolLegacyStream {
		t.Fatalf("negotiated protocol %v", info.Protocol)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	only := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	only.EndpointProtocols = []EndpointProtocol{EndpointProtocolIVNPStream}
	if _, err := svc.Dial(context.Background(), target, only); err == nil {
		t.Fatal("ivnp_only dial succeeded on a legacy-only peer")
	}

	// A session negotiating a protocol outside the bound scope is rejected.
	if err := host.RegisterProvider(fixedSessions{p: EndpointProtocolIVNPStream}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Dial(context.Background(), target, testPolicy(PublicFastFabricID, NativeI2PFabricID)); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("session protocol outside the bound scope: %v", err)
	}
}

// auditCapture records audit events for assertions.
type auditCapture struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *auditCapture) Emit(ctx context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *auditCapture) saw(kind string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// dualAuditHost is dualHost with an audit sink wired into the host.
func dualAuditHost(t *testing.T, fabric FabricProvider, audit AuditSink) (*Host, *Realm) {
	t.Helper()
	host, err := NewHost(HostConfig{Topology: TopologyPublicDualStack, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
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
	return host, realm
}

// TestContactEnvelopeHints: a verified x-ov.* envelope supplies the peer's
// member slot as a pending hint and advances its format-2 floor; rolled-back
// and equivocating envelopes lose their hints.
func TestContactEnvelopeHints(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	env := testEnvelope()
	// In open mode the member label is the record's own identity hash.
	env.MemberID = MemberID(dest.Hash())
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	_, realm := dualAuditHost(t, &stubFabric{native: netdb}, nil)
	watch := realm.WatchEvents()
	ref := PeerRef{
		Realm:   PublicFastRealmID,
		Locator: Locator{Kind: LocatorDestinationHash, Hash: dest.Hash()},
	}
	peer, err := realm.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.RecordVerified || !peer.Ref.HasMember || peer.Ref.Member != MemberID(dest.Hash()) {
		t.Fatalf("envelope hints dropped: %+v", peer)
	}
	if peer.Membership != MembershipPending {
		t.Fatalf("membership %v", peer.Membership)
	}

	older := testEnvelope()
	older.MemberID = MemberID(dest.Hash())
	older.Sequence = 6
	olderEntries, err := older.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	netdb.records[dest.Hash()] = DestinationRecord{Raw: signedLS2(t, dest, olderEntries), Provenance: ProvenancePublicNative}
	peer, err = realm.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Ref.HasMember {
		t.Fatal("rolled-back envelope supplied a member hint")
	}

	forge := testEnvelope()
	forge.MemberID = MemberID(dest.Hash())
	forge.ChannelKey = [32]byte{8, 8, 8}
	forgeEntries, err := forge.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	netdb.records[dest.Hash()] = DestinationRecord{Raw: signedLS2(t, dest, forgeEntries), Provenance: ProvenancePublicNative}
	peer, err = realm.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Ref.HasMember {
		t.Fatal("equivocating envelope supplied a member hint")
	}
	select {
	case ev := <-watch:
		if ev.Kind != EventEquivocation {
			t.Fatalf("event %v", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("equivocation produced no event")
	}
}

// TestMalformedExtensionsAudited: malformed x-ov.*/x-ivnp.* extensions under
// a verified native signature emit an audit signal; the verified native
// candidate still stands.
func TestMalformedExtensionsAudited(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	ivnpEntries, err := testPresence().MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	for i := range ivnpEntries {
		if string(ivnpEntries[i].Key) == "x-ivnp.s" {
			ivnpEntries[i].Value = []byte("4")
		}
	}
	envEntries, err := testEnvelope().MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	for i := range envEntries {
		if string(envEntries[i].Key) == "x-ov.h" {
			envEntries[i].Value = []byte(encode32([32]byte{0xee}))
		}
	}
	all := sortEntries(append(ivnpEntries, envEntries...))
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, all), Provenance: ProvenancePublicNative},
	}}
	audit := &auditCapture{}
	_, realm := dualAuditHost(t, &stubFabric{native: netdb}, audit)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
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
	candidates, err := realm.resolveCandidates(context.Background(), ServiceTarget{
		Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)},
		Port:     47001,
	}, eff)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Class != RouteNativeI2P {
		t.Fatalf("candidates after malformed extensions: %+v", candidates)
	}
	if !audit.saw("presence_invalid") {
		t.Fatal("malformed x-ivnp.* produced no audit event")
	}
	if !audit.saw("contact_extension_invalid") {
		t.Fatal("malformed x-ov.* produced no audit event")
	}
}

// TestEmergencyReserveBounded: the emergency exception is finite — once the
// per-hour budget is spent, further emergency updates rate-limit, and expired
// reservations refill the budget.
func TestEmergencyReserveBounded(t *testing.T) {
	a := &publicationArbiter{}
	for i := 0; i < maxEmergencyReserves; i++ {
		if _, _, err := a.Reserve(true); err != nil {
			t.Fatalf("emergency %d: %v", i, err)
		}
	}
	if _, _, err := a.Reserve(true); !errors.Is(err, CodeRateLimited) {
		t.Fatalf("unbounded emergency reserve: %v", err)
	}
	a.mu.Lock()
	a.emergencies = []time.Time{time.Now().Add(-2 * emergencyWindow)}
	a.mu.Unlock()
	if _, _, err := a.Reserve(true); err != nil {
		t.Fatalf("expired emergency window did not refill: %v", err)
	}
}

// stubInbound delivers queued inbound items and counts provider calls;
// progress announces each call so tests wait without sleeping.
type stubInbound struct {
	carrier  string
	calls    atomic.Int32
	items    chan inboundItem
	progress chan int32
}

func (s *stubInbound) Carrier() string { return s.carrier }
func (s *stubInbound) Capabilities() TransportCapabilities {
	return TransportCapabilities{DirectBinding: true}
}
func (s *stubInbound) Setup(ctx context.Context, c RouteCandidate, scope ChannelScope, admission *AdmissionRequest) (Channel, error) {
	return nil, CodeUnsupportedCapability.Wrap("inbound only")
}
func (s *stubInbound) Accept(ctx context.Context, svc *Service) (Channel, ChannelScope, error) {
	n := s.calls.Add(1)
	select {
	case s.progress <- n:
	default:
	}
	select {
	case it := <-s.items:
		return it.channel, it.scope, it.err
	case <-ctx.Done():
		return nil, ChannelScope{}, ctx.Err()
	}
}

// waitProviderCalls blocks until the provider has been asked for the nth
// inbound channel.
func waitProviderCalls(t *testing.T, in *stubInbound, want int32) {
	t.Helper()
	for {
		select {
		case n := <-in.progress:
			if n >= want {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("provider calls %d < %d", in.calls.Load(), want)
		}
	}
}

// inboundScope builds a scope the way an external InboundProvider does:
// every field is sourced from the service's public accessors, never from
// in-package internals.
func inboundScope(svc *Service) ChannelScope {
	return ChannelScope{
		Fabric: privateDescriptor().ID, NetworkID: 88, Realm: svc.RealmID(),
		Endpoint: svc.Endpoint().ID, Port: svc.Port(), Protocol: EndpointProtocolIVNPStream,
		Class: RouteDirect, Exposure: PrivacyPrivateConfined,
		PolicyGen: svc.PolicyGen(),
	}
}

func listenableService(t *testing.T, realm *Realm) *Service {
	t.Helper()
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationNone,
		Privacy: PrivacyPrivateConfined, Routing: RoutingOverlayDirect,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// TestListenerQueueBound: the pending queue holds at most Queue channels plus
// one in provider handoff; excess inbound work is backpressured, and Close
// rejects every buffered channel.
func TestListenerQueueBound(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 8), progress: make(chan int32, 8)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{20}, AdmissionOpen)
	svc := listenableService(t, realm)
	l, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
		Queue:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := inboundScope(svc)
	channels := make([]*trackedChannel, 3)
	for i := range channels {
		channels[i] = newTrackedChannel()
		channels[i].binding = scope
		channels[i].key = testChannelKey
		in.items <- inboundItem{channel: channels[i], scope: scope}
	}
	waitProviderCalls(t, in, 2)
	// A second call is in the provider's handoff while the queue is full:
	// the pump provably cannot ask for a third until Accept consumes one.
	if len(l.queue) != 1 || in.calls.Load() != 2 {
		t.Fatalf("queue %d calls %d beyond the bound", len(l.queue), in.calls.Load())
	}
	conn, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conn.Session == nil {
		t.Fatal("inbound connection carries no session")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitProviderCalls(t, in, 3)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 3; i++ {
		select {
		case <-channels[i].closedCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("queued channel %d not closed on listener close", i)
		}
	}
}

// TestInboundSessionBound: an accepted inbound connection carries a verified
// session whose protocol matches the bound scope; a channel outside the
// listen policy is rejected before delivery, and a missing session provider
// fails visibly.
func TestInboundSessionBound(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 8)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{21}, AdmissionOpen)
	svc := listenableService(t, realm)
	l, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
		Queue:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := inboundScope(svc)

	rejected := newTrackedChannel()
	badScope := base
	badScope.Protocol = EndpointProtocolLegacyStream
	rejected.binding = badScope
	rejected.key = testChannelKey
	in.items <- inboundItem{channel: rejected, scope: badScope}

	good := newTrackedChannel()
	good.binding = base
	good.key = testChannelKey
	in.items <- inboundItem{channel: good, scope: base}

	conn, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conn.Session == nil || conn.Session.Protocol() != EndpointProtocolIVNPStream {
		t.Fatal("inbound connection lacks the bound session")
	}
	if info := conn.RouteInfo(); info.Class != RouteDirect || info.Port != 47001 {
		t.Fatalf("route info: %+v", info)
	}
	select {
	case <-rejected.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("policy-rejected channel was not closed")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Without a session provider the listener fails visibly rather than
	// exposing a channel without a bound protocol.
	host2, fast2 := isolatedHost(t)
	in2 := &stubInbound{carrier: "mem", items: make(chan inboundItem, 4)}
	if err := host2.RegisterProvider(in2); err != nil {
		t.Fatal(err)
	}
	realm2 := openAdmissionRealm(t, host2, fast2, RealmID{22}, AdmissionOpen)
	svc2 := listenableService(t, realm2)
	l2, err := svc2.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
		Queue:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := newTrackedChannel()
	scope := inboundScope(svc2)
	ch.binding = scope
	ch.key = testChannelKey
	in2.items <- inboundItem{channel: ch, scope: scope}
	if _, err := l2.Accept(context.Background()); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("missing session provider: %v", err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestListenerRefreshesRealmPolicy: a policy replacement applies to inbound
// admission on the next delivered channel — a fresh PolicyGen stamp does not
// revive listen-time filters. Newly forbidden channels are rejected and
// closed, connections committed under the old generation are drained, and a
// class the replacement re-admits is accepted under its own generation.
func TestListenerRefreshesRealmPolicy(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 8)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	realm, err := host.OpenRealm(RealmConfig{
		ID: RealmID{23}, Contexts: []ContextID{fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := listenableService(t, realm)
	l, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect, RouteNativeI2P},
		Privacy:   PrivacyPrivateConfined,
		Queue:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := newTrackedChannel()
	first.binding = inboundScope(svc)
	first.key = testChannelKey
	in.items <- inboundItem{channel: first, scope: first.binding}
	conn, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// RoutingNativeI2P removes RouteDirect from the realm's routing mode;
	// private_confined independently forbids the native class, so the
	// listener has no admissible class at all under generation two.
	cfg := RealmConfig{
		ID: RealmID{23}, Contexts: []ContextID{fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingNativeI2P, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	}
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("connection committed under the superseded policy was not drained")
	}
	_ = conn.Close()

	// A channel delivered after the replacement carries the current
	// generation; the stale listen-time class set must not admit it. Accept
	// runs in the background: the forbidden channel is closed and skipped,
	// and the call stays pending for the next delivery.
	stale := newTrackedChannel()
	staleScope := inboundScope(svc)
	stale.binding = staleScope
	stale.key = testChannelKey
	in.items <- inboundItem{channel: stale, scope: staleScope}
	type acceptResult struct {
		conn *Connection
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := l.Accept(context.Background())
		acceptCh <- acceptResult{conn, err}
	}()
	select {
	case <-stale.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("forbidden inbound channel was not rejected after policy replacement")
	}

	// Restoring direct routing re-admits the class under generation three.
	cfg.Routing = RoutingOverlayDirect
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	second := newTrackedChannel()
	second.binding = inboundScope(svc)
	second.key = testChannelKey
	in.items <- inboundItem{channel: second, scope: second.binding}
	var res acceptResult
	select {
	case res = <-acceptCh:
	case <-time.After(2 * time.Second):
		t.Fatal("admissible inbound channel was not accepted after policy replacement")
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	conn = res.conn
	if conn.RouteInfo().Class != RouteDirect {
		t.Fatalf("route info: %+v", conn.RouteInfo())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestNonSpeculativeInFlightNeverRaced: a non-speculative carrier runs alone
// in both directions — the hedge delay must not launch a speculative
// competitor while a non-speculative setup is in flight, because canceling
// that handshake cannot prove nothing was sent on the wire.
func TestNonSpeculativeInFlightNeverRaced(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	presence := testPresence()
	presence.Endpoints = append(presence.Endpoints,
		Endpoint{Transport: "tspec", Address: netip.MustParseAddrPort("1.0.0.9:4433")})
	entries, err := presence.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	host, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	firstHold := make(chan struct{})
	secondEntered := make(chan struct{}, 1)
	second := newTrackedChannel()
	// The first carrier cannot be raced safely; the second can.
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tls13", key: presence.ContactKey, hold: firstHold,
		err: errStubSetupFailed, ch: newTrackedChannel(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tspec", key: presence.ContactKey, entered: secondEntered,
		ch: second, speculative: true,
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
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.HedgeDelay = 5 * time.Millisecond
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
	// The hedge fires while the non-speculative setup is in flight; the
	// speculative carrier must stay parked until it finishes.
	select {
	case <-secondEntered:
		t.Fatal("speculative attempt raced a non-speculative in-flight handshake")
	case <-time.After(50 * time.Millisecond):
	}
	close(firstHold)
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("speculative attempt never ran after the first attempt failed")
	}
	res := <-resultCh
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.conn.Close()
}

// TestPresenceVerifiedAtService: Presence re-verifies the provider-signed
// projection against a bound fabric and the service scope, exactly like
// Publish.
func TestPresenceVerifiedAtService(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	host, realm, _, _ := dualHost(t, nil)
	entries, err := testPresence().MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(testSigningBinding()); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Presence(context.Background(), DualPresence{FabricID: PublicFastFabricID, NetworkID: 77})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("presence entries %d", len(got))
	}

	foreign := testPresence()
	foreign.FabricID = FabricID{0x77}
	foreignEntries, err := foreign.MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&stubBinding{entries: foreignEntries}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Presence(context.Background(), DualPresence{
		FabricID: PublicFastFabricID, NetworkID: 77, Emergency: true,
	}); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("foreign projection admitted: %v", err)
	}
}

// TestEndpointPublicScope: cleartext records reject every non-public address
// class including CGNAT shared space.
func TestEndpointPublicScope(t *testing.T) {
	for _, text := range []string{
		"tls13@10.1.2.3:443", "tls13@127.0.0.1:443", "tls13@169.254.1.1:443",
		"tls13@100.64.1.2:443", "tls13@100.127.255.254:443",
		"tls13@224.0.0.1:443", "tls13@203.0.113.255:443",
		"tls13@[fd00::1]:443", "tls13@[fe80::1]:443", "tls13@[::1]:443",
	} {
		ep, err := ParseEndpoint(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if ep.Public() {
			t.Fatalf("%s reported public", text)
		}
	}
	for _, text := range []string{"tls13@9.9.9.9:443", "tls13@100.63.255.1:443"} {
		ep, err := ParseEndpoint(text)
		if err != nil {
			t.Fatal(err)
		}
		if !ep.Public() {
			t.Fatalf("%s reported non-public", text)
		}
	}
}

// TestStateDirAlias: state-directory identity is compared after path
// cleaning, so "./state-ivnp" aliases "state-ivnp".
func TestStateDirAlias(t *testing.T) {
	host := testHost(t, TopologyPublicDualStack)
	ctx := context.Background()
	if _, err := host.OpenFabric(ctx, ivnpFabric()); err != nil {
		t.Fatal(err)
	}
	dup := ivnpFabric()
	dup.IdentityRef = "ivnp-router-2"
	dup.StateDir = "./state-ivnp"
	dup.Descriptor.ID = FabricID{0x55}
	if _, err := host.OpenFabric(ctx, dup); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("state dir alias admitted: %v", err)
	}
}

// TestDialHedgeRacesNativeWithMultipleIVNP: with several IVNP candidates the
// native setup is still the hedge — the first native attempt occupies launch
// position two, so the I2P path races the blocked fast path at HedgeDelay
// instead of an IVNP candidate hedging another IVNP candidate.
func TestDialHedgeRacesNativeWithMultipleIVNP(t *testing.T) {
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
	firstHold := make(chan struct{})
	secondEntered := make(chan struct{}, 1)
	nativeEntered := make(chan struct{}, 1)
	// The blocked fast path must declare itself race-safe: a non-speculative
	// in-flight setup cannot be hedged against at all.
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tls13", key: presence.ContactKey, hold: firstHold, ch: newTrackedChannel(),
		speculative: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tslow", key: presence.ContactKey, entered: secondEntered,
		hold: make(chan struct{}), ch: newTrackedChannel(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "i2p-tunnel", entered: nativeEntered, ch: newTrackedChannel(), speculative: true,
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
	policy := testPolicy(PublicFastFabricID, NativeI2PFabricID)
	policy.HedgeDelay = 10 * time.Millisecond
	resultCh := make(chan error, 1)
	go func() {
		conn, err := svc.Dial(context.Background(),
			ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001},
			policy)
		if err == nil {
			err = conn.Close()
		}
		resultCh <- err
	}()
	// The hedge delay expires while the first IVNP setup is still blocked:
	// the native setup must launch before the second IVNP candidate ever
	// gets a slot.
	select {
	case <-nativeEntered:
	case <-secondEntered:
		t.Fatal("second IVNP candidate hedged ahead of the native setup")
	case <-time.After(2 * time.Second):
		t.Fatal("native hedge never launched")
	}
	select {
	case <-secondEntered:
		t.Fatal("second IVNP candidate raced ahead of the native hedge")
	default:
	}
	close(firstHold)
	if err := <-resultCh; err != nil {
		t.Fatalf("dial: %v", err)
	}
}

// TestRouterInfoFreshness: a verified RouterInfo is usable only within the
// netDB freshness convention — older than ninety minutes or more than two
// minutes in the future is rejected like a stale lease set.
func TestRouterInfoFreshness(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	now := uint64(time.Now().UnixMilli())
	cases := []struct {
		name      string
		published uint64
		want      error
	}{
		{"stale record", now - routerInfoMaxAgeMillis - 60000, CodeRecordStale},
		{"future record", now + routerInfoMaxFutureMillis + 60000, CodeRecordStale},
		{"fresh record", now, nil},
		{"boundary future skew", now + routerInfoMaxFutureMillis, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := signedRI(t, dest, tc.published, nil)
			netdb := &stubNetDB{routers: map[foundation.Hash]RouterRecord{
				dest.Hash(): {Raw: raw, Provenance: ProvenancePublicNative},
			}}
			_, realm := dualAuditHost(t, &stubFabric{native: netdb}, nil)
			peer, err := realm.ResolvePeer(context.Background(), PeerRef{
				Realm:   PublicFastRealmID,
				Locator: Locator{Kind: LocatorRouterHash, Hash: dest.Hash()},
			})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("resolve error = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("fresh record rejected: %v", err)
			}
			if !peer.RecordVerified || peer.Provenance != ProvenancePublicNative {
				t.Fatalf("fresh record not verified: %+v", peer)
			}
		})
	}
}

// TestApplyPolicyDrainsSuperseded: a connection admitted under the replaced
// policy generation is drained when its route class leaves the new routing
// mode; teardown emits a policy_drain audit event.
func TestApplyPolicyDrainsSuperseded(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	audit := &auditCapture{}
	// No fabric provider: both contexts use the built-in local discovery
	// table so the test can seed the candidate directly.
	host, realm, _, fast := dualHost(t, nil)
	if err := host.RegisterProvider(audit); err != nil {
		t.Fatal(err)
	}
	endpoint := EndpointID{0x51}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.8:4433")}
	if err := fast.InsertCandidate(foundation.Hash(endpoint), RouteCandidate{
		Endpoint: endpoint, Fabric: PublicFastFabricID, NetworkID: 77,
		Realm: PublicFastRealmID, Class: RouteDirect, Carrier: "tls13",
		ContactKey: testChannelKey, Contact: &contact,
		NotAfter: time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	ch := newTrackedChannel()
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "tls13", key: testChannelKey, ch: ch,
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
	conn, err := svc.Dial(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001},
		testPolicy(PublicFastFabricID, NativeI2PFabricID))
	if err != nil {
		t.Fatal(err)
	}
	if conn.RouteInfo().Class != RouteDirect {
		t.Fatalf("route class %v", conn.RouteInfo().Class)
	}
	// The replacement policy forbids overlay routing entirely; the admitted
	// direct connection must be drained rather than persist silently.
	realm.mu.Lock()
	cfg := realm.cfg
	realm.mu.Unlock()
	cfg.Routing = RoutingNativeI2P
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("superseded-generation connection was not drained")
	}
	if !audit.saw("policy_drain") {
		t.Fatal("drain produced no audit event")
	}
}

// TestRealmWatchDetach: a realm watcher detaches its host subscription when
// the realm closes; abandoned watchers must not accumulate on the host.
func TestRealmWatchDetach(t *testing.T) {
	host, realm, _, _ := dualHost(t, nil)
	ch := realm.WatchEvents()
	host.mu.Lock()
	watchers := len(host.watchers)
	host.mu.Unlock()
	if watchers != 1 {
		t.Fatalf("host watchers %d, want 1", watchers)
	}
	if err := realm.Close(); err != nil {
		t.Fatal(err)
	}
	// The realm watcher defers unwatch before closing its output channel, so
	// a closed channel proves the host subscription was detached.
	for range ch {
	}
	host.mu.Lock()
	watchers = len(host.watchers)
	host.mu.Unlock()
	if watchers != 0 {
		t.Fatalf("realm watcher leaked on the host: %d subscriptions remain", watchers)
	}
}

// blockingRuntime defers Close until the gate opens, so a host close is
// observably in progress; entered signals that teardown has reached it.
type blockingFabric struct {
	entered chan struct{}
	gate    chan struct{}
}

func (s *blockingFabric) OpenContext(ctx context.Context, cfg FabricConfig) (ContextRuntime, error) {
	return &blockingRuntime{entered: s.entered, gate: s.gate}, nil
}

type blockingRuntime struct {
	stubRuntime
	entered chan struct{}
	gate    chan struct{}
}

func (r *blockingRuntime) Close() error {
	close(r.entered)
	<-r.gate
	return nil
}

// TestHostStoppingVsStopped: State distinguishes a close in progress from a
// finished close — HostStopping while teardown runs, HostStopped after.
func TestHostStoppingVsStopped(t *testing.T) {
	host, err := NewHost(HostConfig{Topology: TopologyIsolated})
	if err != nil {
		t.Fatal(err)
	}
	entered, gate := make(chan struct{}), make(chan struct{})
	if err := host.RegisterProvider(&blockingFabric{entered: entered, gate: gate}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenFabric(context.Background(), ivnpFabric()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- host.Close() }()
	<-entered
	if got := host.State(context.Background()); got != HostStopping {
		t.Fatalf("state during teardown = %v, want HostStopping", got)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := host.State(context.Background()); got != HostStopped {
		t.Fatalf("state after close = %v, want HostStopped", got)
	}
}

// TestSelectorPinnedInChannelScope: the target's endpoint-protocol selector is
// authenticated inside the channel binding; a carrier returning a channel
// bound to a different selector is rejected like any other scope mismatch.
func TestSelectorPinnedInChannelScope(t *testing.T) {
	host, fast := isolatedHost(t)
	realm := openAdmissionRealm(t, host, fast, RealmID{5}, AdmissionOpen)
	endpoint := EndpointID{0x52}
	seedDirectCandidate(t, fast, realm.realmID(), endpoint)
	if err := host.RegisterProvider(&gatedTransport{
		carrier: "mem", key: testChannelKey, ch: newTrackedChannel(),
		mutate: func(scope *ChannelScope) { scope.Selector = 99 },
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	target := ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001, Protocol: 6}
	if _, err := svc.Dial(context.Background(), target, confinedPolicy()); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("selector-substituted channel admitted: %v", err)
	}
}

// TestAuditReceivesCallerContext: security audit emission carries the
// caller's context — a sink observes the resolve caller's values, and a
// context-aware sink is not invoked under context.Background().
func TestAuditReceivesCallerContext(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	entries, err := testPresence().MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if string(entries[i].Key) == "x-ivnp.s" {
			entries[i].Value = []byte("4")
		}
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	sink := &ctxAudit{want: "lookup-1"}
	_, realm := dualAuditHost(t, &stubFabric{native: netdb}, sink)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
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
	ctx := context.WithValue(context.Background(), auditCtxKey{}, "lookup-1")
	if _, err := realm.resolveCandidates(ctx, ServiceTarget{
		Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)},
		Port:     47001,
	}, eff); err != nil {
		t.Fatal(err)
	}
	if !sink.matched() {
		t.Fatal("audit sink did not observe the caller's context")
	}
}

type auditCtxKey struct{}

// ctxAudit records whether an emitted event carried the caller's marker.
type ctxAudit struct {
	mu   sync.Mutex
	want string
	seen bool
}

func (a *ctxAudit) matched() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen
}

func (a *ctxAudit) Emit(ctx context.Context, event AuditEvent) error {
	if ctx.Value(auditCtxKey{}) == a.want {
		a.mu.Lock()
		a.seen = true
		a.mu.Unlock()
	}
	return nil
}

// TestCleartextPresenceRequiresExposureAck: a cleartext x-ivnp.* projection
// publishes a direct endpoint locator; it requires the realm's explicit
// exposure consent and the privacy class that owns the exposure.
func TestCleartextPresenceRequiresExposureAck(t *testing.T) {
	ctx := context.Background()
	host := testHost(t, TopologyPublicDualStack)
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	mkRealm := func(id byte, ack bool) *Realm {
		t.Helper()
		r, err := host.OpenRealm(RealmConfig{
			ID:        RealmID{id},
			Contexts:  []ContextID{native.id, fast.id},
			Admission: AdmissionOpen, AcknowledgeOpen: true,
			AcknowledgeExposure: ack,
			Discovery:           DiscoveryHedged,
			Privacy:             PrivacyExplicitDirect,
			Routing:             RoutingOpportunistic,
			Publication:         PublicationLS2,
			Prefix:              PrefixPolicy{Mode: PrefixDisabled},
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	spec := ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		DualPresence: true, Privacy: PrivacyExplicitDirect,
		Routing:   RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	}
	// No exposure acknowledgement: the direct locator must not publish.
	if _, err := mkRealm(1, false).OpenService(spec); !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("cleartext presence without exposure ack: %v", err)
	}
	// i2p_compatible forbids publishing a direct locator at all.
	bad := spec
	bad.Privacy, bad.Routing = PrivacyI2PCompatible, RoutingNativeI2P
	if _, err := mkRealm(2, true).OpenService(bad); !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("cleartext presence under i2p_compatible: %v", err)
	}
	// private_confined likewise.
	confined := spec
	confined.Privacy, confined.Routing = PrivacyPrivateConfined, RoutingOverlayRouted
	if _, err := mkRealm(3, true).OpenService(confined); !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("cleartext presence under private_confined: %v", err)
	}
	// Consent plus explicit_direct admits the projection.
	if _, err := mkRealm(4, true).OpenService(spec); err != nil {
		t.Fatalf("consented cleartext presence rejected: %v", err)
	}
	// An encrypted projection under a confidential service stays allowed:
	// the consent rule binds only cleartext records.
	encRealm, err := host.OpenRealm(RealmConfig{
		ID:        RealmID{5},
		Contexts:  []ContextID{native.id, fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery:   DiscoveryHedged,
		Privacy:     PrivacyExplicitDirect,
		Routing:     RoutingOpportunistic,
		Publication: PublicationEncryptedLS2,
		Prefix:      PrefixPolicy{Mode: PrefixDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	dest2, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest2.ReleaseSensitive()
	if _, err := encRealm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest2), Publication: PublicationEncryptedLS2,
		DualPresence: true, Privacy: PrivacyPrivateConfined,
		Routing:   RoutingOverlayRouted,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	}); err != nil {
		t.Fatalf("encrypted presence under private_confined rejected: %v", err)
	}
}

// TestCrossRealmDestinationOwnership: one native identity admits exactly one
// writer host-wide — across realms, within one realm, and again only after
// the owning service closes.
func TestCrossRealmDestinationOwnership(t *testing.T) {
	ctx := context.Background()
	host := testHost(t, TopologyPublicDualStack)
	native, err := host.OpenFabric(ctx, nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	fast, err := host.OpenFabric(ctx, ivnpFabric())
	if err != nil {
		t.Fatal(err)
	}
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	mkRealm := func(id byte) *Realm {
		t.Helper()
		r, err := host.OpenRealm(RealmConfig{
			ID:        RealmID{id},
			Contexts:  []ContextID{native.id, fast.id},
			Admission: AdmissionOpen, AcknowledgeOpen: true,
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
		return r
	}
	spec := ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	}
	r1, r2 := mkRealm(1), mkRealm(2)
	svc, err := r1.OpenService(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.OpenService(spec); !errors.Is(err, CodeIdentityMismatch) {
		t.Fatalf("second realm writer admitted: %v", err)
	}
	if _, err := r1.OpenService(spec); !errors.Is(err, CodeIdentityMismatch) {
		t.Fatalf("same-realm duplicate writer admitted: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.OpenService(spec); err != nil {
		t.Fatalf("released destination not reusable: %v", err)
	}
}

// TestNilDestinationOutboundOnly: a service without an owned destination has
// no endpoint identity — it can dial but must not listen.
func TestNilDestinationOutboundOnly(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 4)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{23}, AdmissionOpen)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Endpoint().ID != (EndpointID{}) {
		t.Fatal("identity-less service carries an endpoint id")
	}
	if _, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
	}); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("identity-less service listened: %v", err)
	}
}

// TestOpenModeMemberBoundToRecord: in open mode the envelope's member label
// must equal the record's own identity hash; a chosen label drops the
// envelope without advancing its floor.
func TestOpenModeMemberBoundToRecord(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	env := testEnvelope()
	env.MemberID = MemberID{9, 9, 9}
	entries, err := env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative},
	}}
	_, realm := dualAuditHost(t, &stubFabric{native: netdb}, nil)
	ref := PeerRef{
		Realm:   PublicFastRealmID,
		Locator: Locator{Kind: LocatorDestinationHash, Hash: dest.Hash()},
	}
	peer, err := realm.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.RecordVerified {
		t.Fatal("verified native record dropped with its envelope")
	}
	if peer.Ref.HasMember {
		t.Fatal("attacker-chosen member label surfaced as a hint")
	}
	// The floor never advanced: the same sequence with the correct member
	// label is admitted, not treated as equivocation.
	env.MemberID = MemberID(dest.Hash())
	entries, err = env.MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	netdb.records[dest.Hash()] = DestinationRecord{Raw: signedLS2(t, dest, entries), Provenance: ProvenancePublicNative}
	peer, err = realm.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.Ref.HasMember || peer.Ref.Member != MemberID(dest.Hash()) {
		t.Fatalf("valid member hint dropped after rejected envelope: %+v", peer.Ref)
	}
}

// TestInboundScopeFabricAndGeneration: an inbound channel's claimed scope
// must name a realm-bound fabric and the current policy generation — the
// same scope discipline the outbound path enforces.
func TestInboundScopeFabricAndGeneration(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 8)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{24}, AdmissionOpen)
	svc := listenableService(t, realm)
	l, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
		Queue:     4,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A fabric the realm never bound is rejected and closed.
	foreign := inboundScope(svc)
	foreign.Fabric = FabricID{0x99}
	ch := newTrackedChannel()
	ch.binding = foreign
	ch.key = testChannelKey
	in.items <- inboundItem{channel: ch, scope: foreign}

	// A policy generation superseded by ApplyPolicy is rejected too.
	cfg := RealmConfig{
		ID: realm.realmID(), Contexts: []ContextID{fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryLocalOnly, Privacy: PrivacyPrivateConfined,
		Routing: RoutingOverlayDirect, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	}
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	stale := inboundScope(svc)
	stale.PolicyGen = 0
	ch2 := newTrackedChannel()
	ch2.binding = stale
	ch2.key = testChannelKey
	in.items <- inboundItem{channel: ch2, scope: stale}

	fresh := inboundScope(svc)
	fresh.PolicyGen = realm.PolicyGen()
	good := newTrackedChannel()
	good.binding = fresh
	good.key = testChannelKey
	in.items <- inboundItem{channel: good, scope: fresh}

	conn, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*trackedChannel{ch, ch2} {
		select {
		case <-c.closedCh:
		case <-time.After(2 * time.Second):
			t.Fatal("out-of-scope channel was not closed")
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestResolvePeerRealmIsolation: a realm resolving through a shared local
// store never observes another realm's candidates.
func TestResolvePeerRealmIsolation(t *testing.T) {
	host, fast := isolatedHost(t)
	realmA := openAdmissionRealm(t, host, fast, RealmID{30}, AdmissionOpen)
	realmB := openAdmissionRealm(t, host, fast, RealmID{31}, AdmissionOpen)
	endpoint := EndpointID(sha256Sum("foreign-endpoint"))
	seedDirectCandidate(t, fast, realmA.realmID(), endpoint)
	ref := PeerRef{
		Realm:   realmB.realmID(),
		Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash(endpoint)},
	}
	if _, err := realmB.ResolvePeer(context.Background(), ref); !errors.Is(err, CodeUnreachable) {
		t.Fatalf("foreign-realm candidate surfaced: %v", err)
	}
	ref.Realm = realmA.realmID()
	peer, err := realmA.ResolvePeer(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(peer.Candidates) != 1 || peer.Candidates[0].Realm != realmA.realmID() {
		t.Fatalf("own-realm candidate filtered out: %+v", peer.Candidates)
	}
}

// TestPublishRejectsForeignPresenceKeys: a binding provider that returns
// entries outside the x-ivnp.* namespace is smuggling unverified material
// into the signed record — publish must refuse.
func TestPublishRejectsForeignPresenceKeys(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	driver := &captureDriver{obs: PublicationObservation{Accepted: true}}
	host, realm, _, _ := dualHost(t, &stubFabric{driver: driver})
	entries, err := testPresence().MarshalEntries()
	if err != nil {
		t.Fatal(err)
	}
	poisoned := append(entries, foundation.MappingEntry{
		Key: []byte("x-ov.m"), Value: []byte(encode32([32]byte{1})),
	})
	if err := host.RegisterProvider(&stubBinding{entries: poisoned}); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(context.Background(), nil); !errors.Is(err, CodeEndpointBindingInvalid) {
		t.Fatalf("foreign entries in signed projection admitted: %v", err)
	}
	if driver.options != nil {
		t.Fatal("rejected projection reached the driver")
	}
}

// TestPublishRequiresNativeDriver: the publication driver comes only from the
// bound native context's runtime — a context without one fails visibly.
func TestPublishRequiresNativeDriver(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	_, realm, _, _ := dualHost(t, nil)
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(context.Background(), nil); !errors.Is(err, CodeUnsupportedCapability) {
		t.Fatalf("publish without a native driver: %v", err)
	}
}

// TestRefreshBindsReadBack: cleartext refresh requires the read-back record
// to hash to the owned endpoint; an encrypted record's blinded lookup key
// rotates daily, so refresh binds to the hash the driver reported at store
// time. A substituted record is rejected either way.
func TestRefreshBindsReadBack(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	driver := &captureDriver{
		obs:      PublicationObservation{Accepted: true},
		readBack: DestinationRecord{Raw: signedLS2(t, dest, nil), Provenance: ProvenancePublicNative},
	}
	_, realm, _, _ := dualHost(t, &stubFabric{driver: driver})
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := svc.Publish(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pub.State() != PublicationFresh {
		t.Fatalf("state %v", pub.State())
	}
	other, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer other.ReleaseSensitive()
	driver.readBack = DestinationRecord{Raw: signedLS2(t, other, nil), Provenance: ProvenancePublicNative}
	if err := pub.Refresh(context.Background()); !errors.Is(err, CodePublicationNotFresh) {
		t.Fatalf("substituted record refreshed: %v", err)
	}

	els2, blinded := signedELS2(t)
	els2Driver := &captureDriver{
		obs:      PublicationObservation{Accepted: true, RecordHash: blinded},
		readBack: DestinationRecord{Raw: els2, Encrypted: true, Provenance: ProvenancePublicNative},
	}
	_, encRealm, _, _ := dualHost(t, &stubFabric{driver: els2Driver})
	encSvc, err := encRealm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationEncryptedLS2,
		Privacy: PrivacyI2PCompatible, Routing: RoutingOverlayRouted,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	encPub, err := encSvc.Publish(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := encPub.Refresh(context.Background()); err != nil {
		t.Fatalf("encrypted refresh failed: %v", err)
	}
	if encPub.State() != PublicationFresh {
		t.Fatalf("state %v", encPub.State())
	}
	substituted, _ := signedELS2(t)
	els2Driver.readBack = DestinationRecord{Raw: substituted, Encrypted: true, Provenance: ProvenancePublicNative}
	if err := encPub.Refresh(context.Background()); !errors.Is(err, CodePublicationNotFresh) {
		t.Fatalf("substituted encrypted record refreshed: %v", err)
	}
}

// TestPolicyReplacementWithdrawsForbidden: a policy replacement that forbids
// the service's projection withdraws its publications, just as it drains
// connections the new policy no longer admits.
func TestPolicyReplacementWithdrawsForbidden(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	driver := &captureDriver{obs: PublicationObservation{Accepted: true}}
	host, realm, native, fast := dualHost(t, &stubFabric{driver: driver})
	if err := host.RegisterProvider(testSigningBinding()); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := svc.Publish(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := RealmConfig{
		ID: realm.realmID(), Contexts: []ContextID{native.id, fast.id},
		Admission: AdmissionOpen, AcknowledgeOpen: true,
		Discovery: DiscoveryHedged, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Publication: PublicationNone,
		Prefix: PrefixPolicy{Mode: PrefixDisabled},
	}
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	if pub.State() != PublicationWithdrawn {
		t.Fatalf("forbidden projection left %v", pub.State())
	}
}

// gatedSessions blocks inside Open until released, so a test controls where
// the winner's commit lands relative to policy replacement: at Open time the
// scope's policy generation was already verified but the connection is not
// yet registered with the service.
type gatedSessions struct {
	entered chan struct{}
	hold    chan struct{}
}

func (s *gatedSessions) Open(ctx context.Context, channel Channel, target ServiceTarget) (Session, error) {
	s.entered <- struct{}{}
	select {
	case <-s.hold:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return fixedSession{p: EndpointProtocolIVNPStream}, nil
}

type dialOutcome struct {
	conn *Connection
	err  error
}

// policyRacingDial drives a dial whose session binding is held in flight, so
// ApplyPolicy can replace the realm policy before the connection registers.
func policyRacingDial(t *testing.T, svc *Service, endpoint EndpointID, gate *gatedSessions) chan dialOutcome {
	t.Helper()
	done := make(chan dialOutcome, 1)
	go func() {
		conn, err := svc.Dial(context.Background(),
			ServiceTarget{Endpoint: EndpointRef{ID: endpoint}, Port: 47001},
			testPolicy(PublicFastFabricID, NativeI2PFabricID))
		done <- dialOutcome{conn: conn, err: err}
	}()
	<-gate.entered
	return done
}

func dialRaceService(t *testing.T) (*Realm, *Service, EndpointID, *gatedSessions, *trackedChannel) {
	t.Helper()
	host, realm, _, fast := dualHost(t, nil)
	endpoint := EndpointID{0x61}
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.9:4433")}
	if err := fast.InsertCandidate(foundation.Hash(endpoint), RouteCandidate{
		Endpoint: endpoint, Fabric: PublicFastFabricID, NetworkID: 77,
		Realm: PublicFastRealmID, Class: RouteDirect, Carrier: "tls13",
		ContactKey: testChannelKey, Contact: &contact,
		NotAfter: time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	ch := newTrackedChannel()
	if err := host.RegisterProvider(&gatedTransport{carrier: "tls13", key: testChannelKey, ch: ch}); err != nil {
		t.Fatal(err)
	}
	gate := &gatedSessions{entered: make(chan struct{}, 1), hold: make(chan struct{})}
	if err := host.RegisterProvider(gate); err != nil {
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
	return realm, svc, endpoint, gate, ch
}

func replaceRealmPolicy(t *testing.T, realm *Realm, mutate func(*RealmConfig)) {
	t.Helper()
	realm.mu.Lock()
	cfg := realm.cfg
	realm.mu.Unlock()
	mutate(&cfg)
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyRaceDrainsLateCommit: a setup authenticated under generation N
// can commit after ApplyPolicy advanced to N+1 and drainSuperseded already
// snapshotted the service's conns. Registration must re-evaluate the route
// under the current policy and close the connection instead of letting it
// escape the drain.
func TestPolicyRaceDrainsLateCommit(t *testing.T) {
	realm, svc, endpoint, gate, ch := dialRaceService(t)
	done := policyRacingDial(t, svc, endpoint, gate)
	replaceRealmPolicy(t, realm, func(cfg *RealmConfig) { cfg.Routing = RoutingNativeI2P })
	close(gate.hold)
	select {
	case res := <-done:
		if !errors.Is(res.err, CodeRevisionConflict) {
			t.Fatalf("late commit escaped drain: %v", res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not finish")
	}
	select {
	case <-ch.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("superseded-generation channel was not closed")
	}
}

// TestPolicyRaceKeepsAdmittedRoute: a completion that raced the generation
// advance but whose route the new policy still admits stays live — the drain
// semantics apply to forbidden routes, not to every older-generation channel.
func TestPolicyRaceKeepsAdmittedRoute(t *testing.T) {
	realm, svc, endpoint, gate, ch := dialRaceService(t)
	done := policyRacingDial(t, svc, endpoint, gate)
	replaceRealmPolicy(t, realm, func(cfg *RealmConfig) { cfg.Discovery = DiscoveryPublicFallback })
	close(gate.hold)
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("admitted route drained: %v", res.err)
		}
		defer res.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not finish")
	}
	select {
	case <-ch.closedCh:
		t.Fatal("still-admitted channel was closed")
	default:
	}
}

// TestRefreshRejectsStaleLS2Version: when the driver reports the stored
// record's ContentHash, a read-back that parses and verifies but carries an
// older version of the same endpoint's record is not freshness evidence.
func TestRefreshRejectsStaleLS2Version(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	stored := signedLS2(t, dest, nil)
	stale := signedLS2(t, dest, []foundation.MappingEntry{{Key: []byte("older"), Value: []byte("1")}})
	driver := &captureDriver{
		obs: PublicationObservation{
			Accepted:    true,
			ContentHash: foundation.Hash(sha256.Sum256(stored)),
		},
		readBack: DestinationRecord{Raw: stale, Provenance: ProvenancePublicNative},
	}
	_, realm, _, _ := dualHost(t, &stubFabric{driver: driver})
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := svc.Publish(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Refresh(context.Background()); !errors.Is(err, CodePublicationNotFresh) {
		t.Fatalf("stale record version refreshed: %v", err)
	}
	driver.readBack = DestinationRecord{Raw: stored, Provenance: ProvenancePublicNative}
	if err := pub.Refresh(context.Background()); err != nil {
		t.Fatalf("stored projection rejected: %v", err)
	}
	if pub.State() != PublicationFresh {
		t.Fatalf("state %v", pub.State())
	}
}

// TestDualPresenceRequiresPort: a dual-presence projection carries x-ivnp.p,
// so a service without a logical port is rejected at open rather than at
// publish time.
func TestDualPresenceRequiresPort(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	_, realm, _, _ := dualHost(t, nil)
	_, err = realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true,
	})
	if !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("dual presence without a port admitted: %v", err)
	}
}

// TestInboundRouteInfoContext: an accepted inbound channel reports the
// context that owns the fabric it arrived on, not a zero handle.
func TestInboundRouteInfoContext(t *testing.T) {
	host, fast := isolatedHost(t)
	in := &stubInbound{carrier: "mem", items: make(chan inboundItem, 4), progress: make(chan int32, 4)}
	if err := host.RegisterProvider(in); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{41}, AdmissionOpen)
	svc := listenableService(t, realm)
	l, err := svc.Listen(ListenPolicy{
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Classes:   []RouteClass{RouteDirect},
		Privacy:   PrivacyPrivateConfined,
		Queue:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	scope := inboundScope(svc)
	scope.PolicyGen = realm.PolicyGen()
	ch := newTrackedChannel()
	ch.binding = scope
	ch.key = testChannelKey
	in.items <- inboundItem{channel: ch, scope: scope}
	conn, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RouteInfo().Context; got != fast.id {
		t.Fatalf("inbound route context %v, want %v", got, fast.id)
	}
}

// TestResolvedPeerLeaseBoundsFreshness: reported freshness for a verified
// record is bounded by the earliest live lease — a record whose inbound path
// expires before its header does is not usable past that point.
func TestResolvedPeerLeaseBoundsFreshness(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	now := uint32(time.Now().Unix())
	leaseEnd := now + 30
	record := signedLS2At(t, dest, nil, now, 600, leaseEnd)
	endpoint := EndpointID(dest.Hash())
	netdb := &stubNetDB{records: map[foundation.Hash]DestinationRecord{
		dest.Hash(): {Raw: record, Provenance: ProvenancePublicNative},
	}}
	_, realm, _, _ := dualHost(t, &stubFabric{native: netdb})
	peer, err := realm.ResolvePeer(context.Background(), PeerRef{
		Realm:   PublicFastRealmID,
		Locator: Locator{Kind: LocatorDestinationHash, Hash: dest.Hash()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if peer.NotAfter != int64(leaseEnd) {
		t.Fatalf("NotAfter %d not bounded by live lease end %d", peer.NotAfter, leaseEnd)
	}
	// The native route candidate is bounded the same way.
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
		Port: 47001,
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
	candidates, err := realm.resolveCandidates(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: endpoint, Destination: canonicalDest(t, dest)}, Port: 1},
		eff)
	if err != nil {
		t.Fatal(err)
	}
	var native *RouteCandidate
	for i := range candidates {
		if candidates[i].Class == RouteNativeI2P {
			native = &candidates[i]
		}
	}
	if native == nil {
		t.Fatal("no native candidate")
	}
	if native.NotAfter != int64(leaseEnd) {
		t.Fatalf("candidate NotAfter %d not bounded by live lease end %d", native.NotAfter, leaseEnd)
	}
}

// TestPolicyChangeBetweenResolveAndSetup: a policy replacement landing while
// resolution is in flight makes the setup's stamped generation stale, so the
// completion cannot activate a route the superseded eligibility computed.
func TestPolicyChangeBetweenResolveAndSetup(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	rt := &countingRuntime{entered: make(chan struct{}, 4), release: make(chan struct{})}
	rt.peers = make(map[foundation.Hash]RouteCandidate)
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
	realm := openAdmissionRealm(t, host, fast, RealmID{32}, AdmissionOpen)
	contact := Endpoint{Transport: "mem", Address: netip.MustParseAddrPort("192.0.2.9:4433")}
	rt.peers[dest.Hash()] = RouteCandidate{
		Endpoint: EndpointID(dest.Hash()), Fabric: privateDescriptor().ID, NetworkID: 88,
		Realm: RealmID{32}, Class: RouteDirect, Carrier: "mem",
		ContactKey: testChannelKey, Contact: &contact,
		NotAfter: time.Now().Add(time.Hour).Unix(), Exposure: PrivacyPrivateConfined,
	}
	ch := newTrackedChannel()
	if err := host.RegisterProvider(&gatedTransport{carrier: "mem", key: testChannelKey, ch: ch}); err != nil {
		t.Fatal(err)
	}
	if err := host.RegisterProvider(stubSessions{}); err != nil {
		t.Fatal(err)
	}
	svc := confinedService(t, realm)
	done := make(chan error, 1)
	go func() {
		_, err := svc.Dial(context.Background(),
			ServiceTarget{Endpoint: EndpointRef{ID: EndpointID(dest.Hash()), Destination: canonicalDest(t, dest)}, Port: 47001},
			confinedPolicy())
		done <- err
	}()
	select {
	case <-rt.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("lookup never started")
	}
	// Replace the policy while the lookup is blocked; the setup that follows
	// stamps the pre-replacement generation and must be rejected as stale.
	realm.mu.Lock()
	cfg := realm.cfg
	realm.mu.Unlock()
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	close(rt.release)
	if err := <-done; !errors.Is(err, CodeRevisionConflict) {
		t.Fatalf("stale-generation completion admitted: %v", err)
	}
	select {
	case <-ch.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stale completion's channel was not closed")
	}
}

// TestProjectionForbiddenByPolicyReplacement: Publish and Presence re-apply
// the realm's current publication policy on every call — a policy that now
// forbids the projection fails the call, not only existing publications.
func TestProjectionForbiddenByPolicyReplacement(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	dest2, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest2.ReleaseSensitive()
	driver := &captureDriver{obs: PublicationObservation{Accepted: true}}
	host, realm, native, fast := dualHost(t, &stubFabric{driver: driver})
	if err := host.RegisterProvider(testSigningBinding()); err != nil {
		t.Fatal(err)
	}
	plain, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	dual, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest2), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47002,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Publish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	cfg := RealmConfig{
		ID:                  realm.realmID(),
		Contexts:            []ContextID{native.id, fast.id},
		Admission:           AdmissionOpen,
		AcknowledgeOpen:     true,
		AcknowledgeExposure: true,
		Discovery:           DiscoveryHedged,
		Privacy:             PrivacyExplicitDirect,
		Routing:             RoutingOpportunistic,
		Publication:         PublicationNone,
		Prefix:              PrefixPolicy{Mode: PrefixDisabled},
	}
	if err := realm.ApplyPolicy(context.Background(), cfg, realm.PolicyGen()); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Publish(context.Background(), nil); !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("publish under a forbidding policy: %v", err)
	}
	if _, err := dual.Presence(context.Background(), DualPresence{
		FabricID: PublicFastFabricID, NetworkID: 77,
	}); !errors.Is(err, CodePrivacyPolicyConflict) {
		t.Fatalf("presence under a forbidding policy: %v", err)
	}
}

// TestPublishContactScopeStamp: the x-ov.* write path binds the envelope to
// the service scope — realm, reserved position, logical port, and in open
// mode the endpoint's own member slot — before the record may carry it.
func TestPublishContactScopeStamp(t *testing.T) {
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
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	contact := ContactEnvelope{
		Admission: AdmissionOpen, ChannelKey: [32]byte{9},
		NotAfter: time.Now().Add(time.Hour).Unix(),
		Endpoints: []Endpoint{
			{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.8:443")},
		},
	}
	if _, err := svc.PublishContact(context.Background(), nil, contact); err != nil {
		t.Fatal(err)
	}
	m, err := mappingFromEntries(driver.options)
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseContactEnvelope(m, RecordLS2)
	if err != nil || env == nil {
		t.Fatalf("published envelope does not parse: %v", err)
	}
	if env.RealmID != realm.realmID() || env.Port != 47001 {
		t.Fatalf("envelope scope: realm %v port %d", env.RealmID, env.Port)
	}
	if env.MemberID != MemberID(svc.endpoint.ID) {
		t.Fatalf("open-realm member slot %v is not the endpoint identity", env.MemberID)
	}
	if env.Sequence != svc.PublicationCursor().Sequence {
		t.Fatalf("envelope position %d is not the reserved cursor %d", env.Sequence, svc.PublicationCursor().Sequence)
	}
}

// TestPublishContactRejected: caller-declared envelope fields that lie about
// scope or violate record rules are refused before a cursor position is
// consumed.
func TestPublishContactRejected(t *testing.T) {
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
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := ContactEnvelope{
		Admission: AdmissionOpen, ChannelKey: [32]byte{9},
		NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ContactEnvelope)
		want   error
	}{
		{"foreign member slot", func(c *ContactEnvelope) { c.MemberID = MemberID{0x99} }, CodeEndpointBindingInvalid},
		{"already expired", func(c *ContactEnvelope) { c.NotAfter = time.Now().Unix() - 1 }, CodeRecordStale},
		{"private endpoint in cleartext", func(c *ContactEnvelope) {
			c.Endpoints = []Endpoint{{Transport: "tls13", Address: netip.MustParseAddrPort("10.0.0.7:443")}}
		}, CodeEndpointBindingInvalid},
	} {
		env := valid
		tc.mutate(&env)
		if _, err := svc.PublishContact(context.Background(), nil, env); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	if got := svc.PublicationCursor().Sequence; got != 0 {
		t.Fatalf("rejected requests consumed cursor position %d", got)
	}
}

// TestPublishRenewalReusesPosition: a republication carrying byte-identical
// semantic extension content is a lease renewal — it reuses the durable
// position instead of consuming a new one, so the minimum semantic-update
// interval does not rate-limit it. A semantic change still reserves a fresh
// position and obeys the interval.
func TestPublishRenewalReusesPosition(t *testing.T) {
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
		Protocols: []EndpointProtocol{EndpointProtocolIVNPStream}, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	contact := ContactEnvelope{
		Admission: AdmissionOpen, ChannelKey: [32]byte{9},
		NotAfter: time.Now().Add(time.Hour).Unix(),
		Endpoints: []Endpoint{
			{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.8:443")},
		},
	}
	if _, err := svc.PublishContact(context.Background(), nil, contact); err != nil {
		t.Fatal(err)
	}
	seq := svc.PublicationCursor().Sequence
	if _, err := svc.PublishContact(context.Background(), nil, contact); err != nil {
		t.Fatalf("renewal rejected: %v", err)
	}
	if got := svc.PublicationCursor().Sequence; got != seq {
		t.Fatalf("renewal consumed position %d -> %d", seq, got)
	}
	// A semantic change consumes a fresh position and obeys the minimum
	// interval; inside it the reservation is refused.
	changed := contact
	changed.Endpoints = append(changed.Endpoints,
		Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("8.8.8.8:443")})
	if _, err := svc.PublishContact(context.Background(), nil, changed); !errors.Is(err, CodeRateLimited) {
		t.Fatalf("semantic change inside the minimum interval: %v", err)
	}
	if got := svc.PublicationCursor().Sequence; got != seq {
		t.Fatalf("rejected change consumed position %d -> %d", seq, got)
	}
}

// TestPresenceRenewalReusesPosition: the standalone projection path follows
// the same renewal rule — identical semantic content reuses the reserved
// position, while an emergency always reserves a fresh one.
func TestPresenceRenewalReusesPosition(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	_, realm, _, _ := dualHost(t, nil)
	if err := realm.host.RegisterProvider(testSigningBinding()); err != nil {
		t.Fatal(err)
	}
	svc, err := realm.OpenService(ServiceSpec{
		Destination: canonicalDest(t, dest), Publication: PublicationLS2,
		Privacy: PrivacyExplicitDirect, Routing: RoutingOpportunistic,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream},
		DualPresence: true, Port: 47001,
	})
	if err != nil {
		t.Fatal(err)
	}
	presence := DualPresence{FabricID: PublicFastFabricID, NetworkID: 77}
	first, err := svc.Presence(context.Background(), presence)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Presence(context.Background(), presence)
	if err != nil {
		t.Fatalf("renewal rejected: %v", err)
	}
	if svc.PublicationCursor().Sequence != 1 {
		t.Fatalf("renewal consumed position %d", svc.PublicationCursor().Sequence)
	}
	if len(first) != len(second) {
		t.Fatalf("renewed projection differs: %d vs %d entries", len(first), len(second))
	}
	for i := range first {
		if string(first[i].Key) != string(second[i].Key) || string(first[i].Value) != string(second[i].Value) {
			t.Fatalf("renewed entry %d differs", i)
		}
	}
	// A semantic change inside the interval is refused; an emergency always
	// reserves a fresh position even for identical content.
	changed := presence
	changed.Capabilities = []string{CapRouted}
	if _, err := svc.Presence(context.Background(), changed); !errors.Is(err, CodeRateLimited) {
		t.Fatalf("semantic change inside the minimum interval: %v", err)
	}
	presence.Emergency = true
	if _, err := svc.Presence(context.Background(), presence); err != nil {
		t.Fatalf("emergency presence rejected: %v", err)
	}
	if got := svc.PublicationCursor().Sequence; got != 2 {
		t.Fatalf("emergency did not reserve a fresh position: %d", got)
	}
}

// TestPublishContactRequiresPort: a port-less service cannot stamp the
// envelope's matchable port, so contact publication is refused outright.
func TestPublishContactRequiresPort(t *testing.T) {
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
	contact := ContactEnvelope{
		Admission: AdmissionOpen, ChannelKey: [32]byte{9},
		NotAfter: time.Now().Add(time.Hour).Unix(),
	}
	if _, err := svc.PublishContact(context.Background(), nil, contact); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("port-less contact publication: %v", err)
	}
}

// TestAdmissionRejectsUnpinnedCandidate: a non-native candidate without an
// owner-authorized contact key has no endpoint key binding to verify, and a
// candidate pairing a bound fabric with a foreign wire netId is inadmissible.
func TestAdmissionRejectsUnpinnedCandidate(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
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
	contact := Endpoint{Transport: "tls13", Address: netip.MustParseAddrPort("9.9.9.9:4433")}
	expiry := time.Now().Add(time.Hour).Unix()
	in := []RouteCandidate{
		// No contact key: nothing for the channel binding to pin.
		{Endpoint: EndpointID{5}, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.realmID(),
			Class: RouteDirect, Contact: &contact, NotAfter: expiry},
		// Foreign wire netId under a bound fabric id.
		{Endpoint: EndpointID{5}, Fabric: PublicFastFabricID, NetworkID: 88, Realm: realm.realmID(),
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: expiry},
		// Admissible.
		{Endpoint: EndpointID{5}, Fabric: PublicFastFabricID, NetworkID: 77, Realm: realm.realmID(),
			Class: RouteDirect, ContactKey: testChannelKey, Contact: &contact, NotAfter: expiry},
		// Native candidates carry no contact key; destination authentication
		// is inherent to the native tunnel.
		{Endpoint: EndpointID{5}, Fabric: NativeI2PFabricID, NetworkID: WireNetworkIDPublicI2P, Realm: realm.realmID(),
			Class: RouteNativeI2P, NotAfter: expiry},
	}
	out, err := realm.admitCandidates(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{5}}}, eff, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("admission kept %d candidates: %+v", len(out), out)
	}
}

// TestRealmClosedStopsServiceOps: once the realm closes, every service
// operation that could still mint evidence or listeners fails closed.
func TestRealmClosedStopsServiceOps(t *testing.T) {
	_, realm, _, _ := dualHost(t, nil)
	svc, err := realm.OpenService(ServiceSpec{
		Publication: PublicationNone, Privacy: PrivacyExplicitDirect,
		Routing: RoutingOpportunistic, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := realm.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveEndpoint(context.Background(),
		ServiceTarget{Endpoint: EndpointRef{ID: EndpointID{1}}}, testPolicy(PublicFastFabricID)); !errors.Is(err, CodeClosed) {
		t.Fatalf("resolve on closed realm: %v", err)
	}
	if _, err := svc.Listen(ListenPolicy{
		Privacy: PrivacyExplicitDirect, Protocols: []EndpointProtocol{EndpointProtocolIVNPStream},
	}); !errors.Is(err, CodeClosed) {
		t.Fatalf("listen on closed realm: %v", err)
	}
	if _, err := svc.Publish(context.Background(), nil); !errors.Is(err, CodeClosed) {
		t.Fatalf("publish on closed realm: %v", err)
	}
}

// TestResolvePeerForeignEndpointDropped: a local-store candidate keyed under
// a locator hash but naming a different endpoint is not returned as
// resolution evidence.
func TestResolvePeerForeignEndpointDropped(t *testing.T) {
	host, fast := isolatedHost(t)
	realm := openAdmissionRealm(t, host, fast, RealmID{33}, AdmissionOpen)
	key := foundation.Hash{0x51}
	contact := Endpoint{Transport: "mem", Address: netip.MustParseAddrPort("192.0.2.10:4433")}
	if err := fast.InsertCandidate(key, RouteCandidate{
		Endpoint: EndpointID{0x52}, Fabric: privateDescriptor().ID, NetworkID: 88,
		Realm: realm.realmID(), Class: RouteDirect, Carrier: "mem",
		ContactKey: testChannelKey,
		Contact:    &contact, NotAfter: time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	peer, err := realm.ResolvePeer(context.Background(), PeerRef{
		Realm:   realm.realmID(),
		Locator: Locator{Kind: LocatorDestinationHash, Hash: key},
	})
	if err == nil && len(peer.Candidates) != 0 {
		t.Fatalf("foreign-endpoint candidate returned: %+v", peer.Candidates)
	}
}

// stubBootstrap returns fixed candidate references for Discover.
type stubBootstrap struct{ refs []PeerRef }

func (s *stubBootstrap) Candidates(ctx context.Context, realm RealmID, limit int) ([]PeerRef, error) {
	return s.refs, nil
}

// TestDiscoverMemberDedup: bootstrap hints carrying the same member slot
// contribute one reference — member uniqueness is not relaxed by the
// discovery bound.
func TestDiscoverMemberDedup(t *testing.T) {
	host, fast := isolatedHost(t)
	refs := []PeerRef{
		{Realm: RealmID{34}, HasMember: true, Member: MemberID{1}, Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash{1}}},
		{Realm: RealmID{34}, HasMember: true, Member: MemberID{1}, Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash{2}}},
		{Realm: RealmID{34}, HasMember: true, Member: MemberID{2}, Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash{3}}},
		{Realm: RealmID{0xfe}, HasMember: true, Member: MemberID{9}, Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash{4}}},
	}
	if err := host.RegisterProvider(&stubBootstrap{refs: refs}); err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{34}, AdmissionOpen)
	res, err := realm.Discover(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("discover returned %d refs, want 2", len(res.Refs))
	}
}

// TestRIPortRejectedByParser: the LS2-only service port is malformed in a
// RouterInfo extension — the parser enforces it, not only the marshal path.
func TestRIPortRejectedByParser(t *testing.T) {
	entries, err := testEnvelope().MarshalEntries(RecordLS2)
	if err != nil {
		t.Fatal(err)
	}
	m := marshalMapping(t, entries)
	if _, err := ParseContactEnvelope(m, RecordRI); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("x-ov.p in an RI record parsed: %v", err)
	}
}

// failingAudit rejects every security event.
type failingAudit struct{}

var errAuditUnavailable = errors.New("audit sink unavailable")

func (failingAudit) Emit(ctx context.Context, event AuditEvent) error {
	return errAuditUnavailable
}

// TestAuditDropCounted: a best-effort audit sink may drop, but the drop is
// observable.
func TestAuditDropCounted(t *testing.T) {
	host, err := NewHost(HostConfig{Topology: TopologyIsolated, Audit: failingAudit{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	fast, err := host.OpenFabric(context.Background(), FabricConfig{
		Kind: ContextIVNP, Descriptor: privateDescriptor(),
		IdentityRef: "ivnp-router", StateDir: "state-ivnp",
	})
	if err != nil {
		t.Fatal(err)
	}
	realm := openAdmissionRealm(t, host, fast, RealmID{35}, AdmissionOpen)
	// A local-only miss transitions discovery to isolated and emits the
	// state-change event the sink rejects.
	_, _ = realm.ResolvePeer(context.Background(), PeerRef{
		Realm:   realm.realmID(),
		Locator: Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash{7}},
	})
	if host.AuditDropped() == 0 {
		t.Fatal("rejected audit event was not counted")
	}
}

// TestLocalTableDefaultBound: the native context carries no descriptor, so
// its built-in local table still needs a finite bound.
func TestLocalTableDefaultBound(t *testing.T) {
	host := testHost(t, TopologyNativeI2P)
	native, err := host.OpenFabric(context.Background(), nativeFabric())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < defaultLocalPeerTableBound; i++ {
		key := foundation.Hash{byte(i), byte(i >> 8), byte(i >> 16)}
		if err := native.InsertCandidate(key, RouteCandidate{Endpoint: EndpointID{1}}); err != nil {
			t.Fatalf("insert %d under default bound failed: %v", i, err)
		}
	}
	if err := native.InsertCandidate(foundation.Hash{0xff, 0xff, 0xff}, RouteCandidate{Endpoint: EndpointID{2}}); !errors.Is(err, CodeInvalidConfig) {
		t.Fatalf("insert past default bound: %v", err)
	}
}

// TestAdmissionAtLeast: the published admission requirement may tighten the
// realm's mode but never weaken it.
func TestAdmissionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		offered, required AdmissionMode
		want              bool
	}{
		{AdmissionOpen, AdmissionOpen, true},
		{AdmissionPSK, AdmissionOpen, true},
		{AdmissionCredentialPSK, AdmissionOpen, true},
		{AdmissionOpen, AdmissionPSK, false},
		{AdmissionOpen, AdmissionCredential, false},
		{AdmissionPSK, AdmissionCredential, false},
		{AdmissionCredential, AdmissionPSK, false},
		{AdmissionCredentialPSK, AdmissionPSK, true},
		{AdmissionCredentialPSK, AdmissionCredential, true},
		{AdmissionPSK, AdmissionCredentialPSK, false},
	} {
		if got := admissionAtLeast(tc.offered, tc.required); got != tc.want {
			t.Fatalf("admissionAtLeast(%v, %v) = %v", tc.offered, tc.required, got)
		}
	}
}
