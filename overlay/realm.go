package overlay

import (
	"context"
	"time"

	"gosuda.org/ivnp/foundation"
)

// MembershipState distinguishes record authenticity from membership proof.
type MembershipState uint8

const (
	// MembershipNone: no membership evidence was requested or found.
	MembershipNone MembershipState = iota + 1
	// MembershipPending: a credential digest or reference exists but the
	// credential itself is unverified.
	MembershipPending
	// MembershipVerified: a verified credential binds the member slot.
	MembershipVerified
)

// ResolvedPeer is evidence-rich resolution output; admission is a separate
// gate performed at connection setup.
type ResolvedPeer struct {
	Ref            PeerRef
	RecordVerified bool
	Membership     MembershipState
	NotAfter       int64
	Provenance     Provenance
	Candidates     []RouteCandidate
}

// ResolvePeer resolves an already identified peer under the realm's discovery
// strategy: local_only never issues a public netDB lookup, public_fallback
// queries the native path only after bounded local failure, and hedged races
// both under the discovery hedge delay. RecordVerified is set only when this
// layer verified a signed native record and checked its freshness;
// runtime-supplied candidates carry no such proof. Membership stays pending
// until admission verifies a credential.
func (r *Realm) ResolvePeer(ctx context.Context, ref PeerRef) (ResolvedPeer, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedPeer{}, err
	}
	if err := ref.Validate(); err != nil {
		return ResolvedPeer{}, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ResolvedPeer{}, CodeClosed.Wrap("realm closed")
	}
	bound := append([]*NetworkContext(nil), r.bound...)
	r.mu.Unlock()

	membership := MembershipNone
	if ref.HasMember {
		membership = MembershipPending
	}
	found := func(p ResolvedPeer) bool {
		return p.RecordVerified || len(p.Candidates) > 0
	}
	var local, public []attempt[ResolvedPeer]
	for _, nctx := range bound {
		nctx := nctx
		switch nctx.kind {
		case ContextIVNP:
			local = append(local, attempt[ResolvedPeer]{
				found: found,
				run: func(ctx context.Context) (ResolvedPeer, error) {
					candidates, err := nctx.lookup(ctx, ref)
					if err != nil {
						r.setDiscovery(ctx, DiscoveryLocalSuspect)
						return ResolvedPeer{}, err
					}
					// Local stores are shared across realms bound to one
					// context: the realm filter the dial path applies must
					// hold here too, stale candidates are unusable, and a
					// table entry keyed under this locator may not name a
					// different endpoint.
					realm := r.realmID()
					now := time.Now().Unix()
					want := locatorEndpoint(ref.Locator)
					kept := make([]RouteCandidate, 0, len(candidates))
					for _, c := range candidates {
						if c.Realm != realm {
							continue
						}
						if want != (EndpointID{}) && c.Endpoint != want {
							continue
						}
						if c.NotAfter != 0 && c.NotAfter <= now {
							continue
						}
						c.Provenance = ProvenanceLocal
						kept = append(kept, c)
					}
					if len(kept) == 0 {
						r.setDiscovery(ctx, DiscoveryLocalSuspect)
						return ResolvedPeer{}, nil
					}
					return ResolvedPeer{
						Ref: ref, Membership: membership,
						Provenance: ProvenanceLocal, Candidates: kept,
					}, nil
				},
			})
		case ContextNativeI2P:
			public = append(public, attempt[ResolvedPeer]{
				found: found,
				run: func(ctx context.Context) (ResolvedPeer, error) {
					release, err := r.acquirePublic()
					if err != nil {
						return ResolvedPeer{}, err
					}
					defer release()
					r.setDiscovery(ctx, DiscoveryPublicResolving)
					peer, err := r.resolveNativePeer(ctx, nctx, ref, membership)
					if err == nil {
						r.setDiscovery(ctx, DiscoveryContactRevalidated)
					}
					return peer, err
				},
			})
		}
	}
	var peer ResolvedPeer
	var err error
	switch r.discoveryMode() {
	case DiscoveryLocalOnly:
		if len(local) == 0 {
			return ResolvedPeer{}, CodeUnreachable.Wrap("local_only binds no ivnp context")
		}
		peer, err = runFirst(ctx, local)
		if err != nil {
			r.setDiscovery(ctx, DiscoveryIsolated)
		} else {
			r.setDiscovery(ctx, DiscoveryHealthy)
		}
	case DiscoveryPublicPrimary:
		if len(public) == 0 {
			return ResolvedPeer{}, CodePublicUnavailable.Wrap("public_primary requires a native context")
		}
		peer, err = runFirst(ctx, public)
		r.finishDiscovery(ctx, err)
	case DiscoveryPublicFallback:
		peer, err = runFirst(ctx, append(append([]attempt[ResolvedPeer](nil), local...), public...))
		r.finishDiscovery(ctx, err)
	case DiscoveryHedged:
		peer, err = runHedged(ctx, append(append([]attempt[ResolvedPeer](nil), local...), public...), DefaultDiscoveryHedgeDelay)
		r.finishDiscovery(ctx, err)
	default:
		return ResolvedPeer{}, CodeInvalidConfig.Wrap("unknown discovery mode")
	}
	return peer, err
}

// resolveNativePeer verifies a signed record from the narrow public netDB
// boundary. Encrypted records verify by signature but expose no contact data
// without local access material.
func (r *Realm) resolveNativePeer(ctx context.Context, nctx *NetworkContext, ref PeerRef, membership MembershipState) (ResolvedPeer, error) {
	backend, err := nctx.NativePublic()
	if err != nil {
		return ResolvedPeer{}, err
	}
	switch ref.Locator.Kind {
	case LocatorRouterHash:
		record, err := backend.LookupRouter(ctx, ref.Locator.Hash)
		if err != nil {
			return ResolvedPeer{}, err
		}
		ri, err := foundation.NetworkDatabaseParseRouterInfo(record.Raw)
		if err != nil {
			return ResolvedPeer{}, err
		}
		if ri.Hash() != ref.Locator.Hash {
			return ResolvedPeer{}, CodeIdentityMismatch.Wrap("router record does not match the locator")
		}
		valid, err := ri.Verify()
		if err != nil || !valid {
			return ResolvedPeer{}, CodeEndpointBindingInvalid.Wrap("router record signature invalid")
		}
		if err := routerInfoFresh(ri.Published, uint64(time.Now().UnixMilli())); err != nil {
			return ResolvedPeer{}, err
		}
		peer := ResolvedPeer{
			Ref: ref, RecordVerified: true, Membership: membership,
			NotAfter:   int64(ri.Published/1000) + int64(routerInfoMaxAgeMillis/1000),
			Provenance: publicProvenance(record.Provenance),
		}
		if env := r.contactHints(ctx, ri.Options, EndpointID(ref.Locator.Hash), true, peer.NotAfter); env != nil && env.RealmID == ref.Realm {
			// The envelope's member slot is a hint until admission verifies
			// the credential itself.
			ref.Member = env.MemberID
			ref.HasMember = true
			peer.Ref = ref
			peer.Membership = MembershipPending
		}
		return peer, nil
	case LocatorDestinationHash, LocatorDestination:
		record, err := backend.LookupDestination(ctx, ref.Locator.Hash)
		if err != nil {
			return ResolvedPeer{}, err
		}
		if record.Encrypted {
			return ResolvedPeer{}, r.encryptedRecordError(record.Raw,
				ServiceTarget{Endpoint: EndpointRef{Encrypted: ref.Locator.Encrypted}})
		}
		ls2, err := foundation.NetworkDatabaseParseLeaseSet2(record.Raw)
		if err != nil {
			return ResolvedPeer{}, err
		}
		if ls2.Hash() != ref.Locator.Hash {
			return ResolvedPeer{}, CodeIdentityMismatch.Wrap("record does not match the locator")
		}
		valid, err := ls2.Verify()
		if err != nil || !valid {
			return ResolvedPeer{}, CodeEndpointBindingInvalid.Wrap("record signature invalid")
		}
		now := time.Now().Unix()
		notAfter := int64(ls2.Header.Published) + int64(ls2.Header.Expires)
		if notAfter < now {
			return ResolvedPeer{}, CodeRecordStale.Wrap("record expired")
		}
		// Reported freshness is bounded by the earliest live lease: a record
		// whose inbound path expires first is not usable past it.
		if leaseEnd, live := minLiveLease(ls2, now); live && leaseEnd < notAfter {
			notAfter = leaseEnd
		}
		peer := ResolvedPeer{
			Ref: ref, RecordVerified: true, Membership: membership,
			NotAfter: notAfter, Provenance: publicProvenance(record.Provenance),
		}
		if env := r.contactHints(ctx, ls2.Options, EndpointID(ref.Locator.Hash), false, peer.NotAfter); env != nil && env.RealmID == ref.Realm {
			// The envelope's member slot is a hint until admission verifies
			// the credential itself.
			ref.Member = env.MemberID
			ref.HasMember = true
			peer.Ref = ref
			peer.Membership = MembershipPending
			if env.NotAfter < peer.NotAfter {
				peer.NotAfter = env.NotAfter
			}
		}
		return peer, nil
	case LocatorEncrypted:
		record, err := backend.LookupDestination(ctx, ref.Locator.Encrypted.BlindedHash)
		if err != nil {
			return ResolvedPeer{}, err
		}
		els2, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(record.Raw)
		if err != nil {
			return ResolvedPeer{}, err
		}
		if els2.Hash() != ref.Locator.Encrypted.BlindedHash {
			return ResolvedPeer{}, CodeIdentityMismatch.Wrap("encrypted record does not match the blinded locator")
		}
		valid, err := els2.Verify()
		if err != nil || !valid {
			return ResolvedPeer{}, CodeEndpointBindingInvalid.Wrap("encrypted record signature invalid")
		}
		// The outer signature verifies under the blinded key; inner contact
		// data stays opaque until ELS2 decryption is wired.
		return ResolvedPeer{
			Ref: ref, RecordVerified: true, Membership: membership,
			NotAfter:   int64(els2.Published) + int64(els2.Expires),
			Provenance: publicProvenance(record.Provenance),
		}, nil
	}
	return ResolvedPeer{}, CodeInvalidConfig.Wrap("unknown locator kind")
}

func publicProvenance(p Provenance) Provenance {
	if p == 0 {
		return ProvenancePublicNative
	}
	return p
}

// RouterInfo freshness bounds mirror the netDB admission convention: a record
// older than ninety minutes or published more than two minutes in the future
// is unusable.
const (
	routerInfoMaxAgeMillis    = uint64(90 * time.Minute / time.Millisecond)
	routerInfoMaxFutureMillis = uint64(2 * time.Minute / time.Millisecond)
)

// routerInfoFresh classifies a verified RouterInfo's published timestamp.
// RouterInfo.Published is milliseconds since epoch.
func routerInfoFresh(published, nowMillis uint64) error {
	if published > nowMillis {
		if published-nowMillis > routerInfoMaxFutureMillis {
			return CodeRecordStale.Wrap("router record is impossibly far in the future")
		}
		return nil
	}
	if nowMillis-published > routerInfoMaxAgeMillis {
		return CodeRecordStale.Wrap("router record is stale")
	}
	return nil
}

// DiscoveryCoverage reports how complete a Discover result can honestly be.
type DiscoveryCoverage uint8

const (
	// CoveragePartial: public netDB has no global attribute index and no
	// complete realm roster; every discovery result is partial.
	CoveragePartial DiscoveryCoverage = iota + 1
)

// DiscoveryResult is a bounded, non-exhaustive candidate set plus its honest
// coverage classification.
type DiscoveryResult struct {
	Refs     []PeerRef
	Coverage DiscoveryCoverage
}

// Discover returns a bounded, non-exhaustive candidate set. Coverage is always
// partial: public netDB has no global attribute index and no complete realm
// roster.
func (r *Realm) Discover(ctx context.Context, limit int) (DiscoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, err
	}
	if limit <= 0 {
		return DiscoveryResult{}, CodeInvalidConfig.Wrap("discover requires a finite limit")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return DiscoveryResult{}, CodeClosed.Wrap("realm closed")
	}
	r.mu.Unlock()
	bootstrap := r.host.bootstrapProvider()
	if bootstrap == nil {
		return DiscoveryResult{}, CodeUnsupportedCapability.Wrap("no bootstrap provider")
	}
	refs, err := bootstrap.Candidates(ctx, r.realmID(), limit)
	if err != nil {
		return DiscoveryResult{}, err
	}
	// Bootstrap hints are untrusted input: drop malformed or foreign-realm
	// references and hold the caller's bound regardless of what the provider
	// returned. References carrying a member claim deduplicate on it: one
	// member slot contributes at most one hint to the bounded set.
	realm := r.realmID()
	seen := make(map[MemberID]struct{})
	out := make([]PeerRef, 0, min(limit, len(refs)))
	for _, ref := range refs {
		if len(out) == limit {
			break
		}
		if ref.Validate() != nil || ref.Realm != realm {
			continue
		}
		if ref.HasMember {
			if _, dup := seen[ref.Member]; dup {
				continue
			}
			seen[ref.Member] = struct{}{}
		}
		out = append(out, ref)
	}
	return DiscoveryResult{Refs: out, Coverage: CoveragePartial}, nil
}

// ApplyPolicy publishes a new policy generation under the same validation as
// OpenRealm: enum checks, provider requirements, context rebinding, and
// admission/exposure rules all apply. The realm identity is immutable. Dial
// operations pin the generation they observed so stale completions cannot
// advance state. Connections admitted under the superseded generation whose
// committed route the new policy no longer permits are drained.
func (r *Realm) ApplyPolicy(ctx context.Context, cfg RealmConfig, expectedRevision uint64) error {
	r.mu.Lock()
	realmID := r.cfg.ID
	r.mu.Unlock()
	if cfg.ID != realmID {
		return CodeInvalidConfig.Wrap("policy replacement cannot change the realm id")
	}
	bound, err := r.host.checkRealmPlacement(cfg)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return CodeClosed.Wrap("realm closed")
	}
	if expectedRevision != r.policyGen.Load() {
		r.mu.Unlock()
		return CodeRevisionConflict.Wrap("policy revision mismatch")
	}
	r.cfg = cfg
	r.bound = bound
	r.policyGen.Add(1)
	services := make([]*Service, 0, len(r.all))
	for s := range r.all {
		services = append(services, s)
	}
	r.mu.Unlock()
	r.drainSuperseded(ctx, services, cfg, bound)
	return nil
}

// projectionPermitted evaluates the realm's current configuration against a
// service's owned projection. validateServiceSpec applies it at open;
// Publish, PublishContact, and Presence re-apply it on every call because
// ApplyPolicy may have replaced the configuration since.
func (r *Realm) projectionPermitted(spec ServiceSpec) error {
	r.mu.Lock()
	cfg := r.cfg
	bound := append([]*NetworkContext(nil), r.bound...)
	r.mu.Unlock()
	switch cfg.Publication {
	case PublicationNone, PublicationNativeRI:
		return CodePrivacyPolicyConflict.Wrap("realm forbids a public lease-set projection")
	case PublicationEncryptedLS2:
		if spec.Publication == PublicationLS2 {
			return CodePrivacyPolicyConflict.Wrap("encrypted-publication realm forbids a cleartext projection")
		}
	}
	if spec.DualPresence {
		if spec.Publication == PublicationLS2 && !cfg.AcknowledgeExposure {
			return CodePrivacyPolicyConflict.Wrap("cleartext presence publishes a direct locator without realm exposure acknowledgement")
		}
		if !contextKindBound(bound, ContextIVNP) {
			return CodeContextScopeMismatch.Wrap("dual presence requires a bound ivnp context")
		}
	}
	return nil
}

// routePolicy is the admissibility predicate a committed route must satisfy
// under one realm configuration: the route class stays in the routing mode,
// the fabric stays bound, and the privacy class still admits the path.
type routePolicy struct {
	classes map[RouteClass]struct{}
	fabrics map[FabricID]struct{}
	public  map[FabricID]struct{}
	privacy PrivacyClass
}

func routePolicyFor(cfg RealmConfig, bound []*NetworkContext) routePolicy {
	public := map[FabricID]struct{}{NativeI2PFabricID: {}}
	fabrics := make(map[FabricID]struct{}, len(bound))
	for _, nctx := range bound {
		fabrics[nctx.fabric.ID] = struct{}{}
		if nctx.kind == ContextNativeI2P || nctx.cfg.Descriptor.Public {
			public[nctx.fabric.ID] = struct{}{}
		}
	}
	return routePolicy{
		classes: routingClasses(cfg.Routing), fabrics: fabrics,
		public: public, privacy: cfg.Privacy,
	}
}

func (p routePolicy) admits(route RouteInfo) bool {
	_, classOK := p.classes[route.Class]
	_, fabricBound := p.fabrics[route.Fabric]
	return classOK && fabricBound &&
		privacyAdmits(p.privacy, RouteCandidate{Class: route.Class, Fabric: route.Fabric}, p.public)
}

// admitsRoute reports whether a committed route stays admissible under the
// realm's current policy — the same predicate drainSuperseded applies.
func (r *Realm) admitsRoute(route RouteInfo) bool {
	r.mu.Lock()
	p := routePolicyFor(r.cfg, r.bound)
	r.mu.Unlock()
	return p.admits(route)
}

// drainSuperseded closes connections whose committed route the replacement
// policy no longer admits: the route class left the realm's routing mode, the
// fabric is no longer bound, or the privacy class now forbids the path. Drains
// run after the generation advances; a completion that raced the advance is
// caught by the registration-time re-check in Service.registerConn.
func (r *Realm) drainSuperseded(ctx context.Context, services []*Service, cfg RealmConfig, bound []*NetworkContext) {
	policy := routePolicyFor(cfg, bound)
	for _, s := range services {
		s.withdrawForbiddenPubs(cfg)
		s.mu.Lock()
		conns := make([]*Connection, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		for _, c := range conns {
			route := c.RouteInfo()
			if policy.admits(route) {
				continue
			}
			r.host.emit(ctx, AuditEvent{Kind: "policy_drain", Realm: cfg.ID, Endpoint: route.Endpoint, At: time.Now().Unix()})
			_ = c.Close()
		}
	}
}

// withdrawForbiddenPubs retires the service's projections when the
// replacement policy no longer permits them: the realm's publication mode
// forbids the projection, or a cleartext presence lost the realm's exposure
// acknowledgement. Withdrawal stops renewal and local acceptance; remote
// deletion is never promised.
func (s *Service) withdrawForbiddenPubs(cfg RealmConfig) {
	owned := s.spec.Publication == PublicationLS2 ||
		s.spec.Publication == PublicationEncryptedLS2 || s.spec.DualPresence
	if !owned {
		return
	}
	forbidden := cfg.Publication == PublicationNone || cfg.Publication == PublicationNativeRI ||
		(cfg.Publication == PublicationEncryptedLS2 && s.spec.Publication == PublicationLS2) ||
		(s.spec.DualPresence && s.spec.Publication == PublicationLS2 &&
			(!cfg.AcknowledgeExposure || s.spec.Privacy != PrivacyExplicitDirect))
	if !forbidden {
		return
	}
	s.mu.Lock()
	pubs := make([]*Publication, 0, len(s.pubs))
	for p := range s.pubs {
		pubs = append(pubs, p)
	}
	s.mu.Unlock()
	for _, p := range pubs {
		p.Withdraw()
	}
}

// PolicyGen is the current policy generation.
func (r *Realm) PolicyGen() uint64 { return r.policyGen.Load() }

// Status reports the realm's multidimensional readiness. Every axis is
// computed from its own evidence; an isolated realm can be locally ready
// without any public evidence.
func (r *Realm) Status(ctx context.Context) Readiness {
	r.mu.Lock()
	bound := append([]*NetworkContext(nil), r.bound...)
	services := make([]*Service, 0, len(r.all))
	for s := range r.all {
		services = append(services, s)
	}
	cfg := r.cfg
	closed := r.closed
	r.mu.Unlock()
	var out Readiness
	if closed {
		return out
	}
	var ivnpConnected, nativeConnected, publicLookup bool
	for _, nctx := range bound {
		conn, err := nctx.ready(ctx)
		if err != nil {
			continue
		}
		out.LocalConnectivity = out.LocalConnectivity || conn.Connected
		switch nctx.kind {
		case ContextNativeI2P:
			nativeConnected = nativeConnected || conn.Connected
			publicLookup = publicLookup || conn.PublicLookup
		case ContextIVNP:
			ivnpConnected = ivnpConnected || conn.Connected
		}
	}
	out.PublicLookup = publicLookup
	out.FallbackReady = publicLookup && (ivnpConnected || nativeConnected)
	switch cfg.Routing {
	case RoutingNativeI2P:
		out.RoutePolicySatisfied = nativeConnected
	case RoutingOverlayDirect, RoutingOverlayRouted:
		out.RoutePolicySatisfied = ivnpConnected
	default:
		out.RoutePolicySatisfied = out.LocalConnectivity
	}
	// Every service requiring a public projection must hold a non-terminal
	// publication; a realm with no publishing services satisfies the axis.
	out.PublicationCurrent = true
	for _, s := range services {
		required, fresh := s.publicationFresh()
		if required && !fresh {
			out.PublicationCurrent = false
		}
		out.ServiceAccepting = out.ServiceAccepting || s.listenerOpen()
	}
	switch cfg.Admission {
	case AdmissionCredential, AdmissionCredentialPSK:
		// Membership freshness is the trust snapshot's validity, not a flag.
		state, err := r.trustSnapshot(ctx)
		out.MembershipFresh = err == nil && (state.NotAfter == 0 || state.NotAfter > time.Now().Unix())
	default:
		// open and psk realms carry no issuer-side membership to go stale.
		out.MembershipFresh = true
	}
	return out
}

// nativeFallbackReady reports whether a bound native context currently has a
// usable public path: connectivity plus lookup readiness.
func (r *Realm) nativeFallbackReady(ctx context.Context) bool {
	for _, nctx := range r.boundContexts() {
		if nctx.kind != ContextNativeI2P {
			continue
		}
		conn, err := nctx.ready(ctx)
		if err == nil && conn.Connected && conn.PublicLookup {
			return true
		}
	}
	return false
}

// WatchEvents subscribes to this realm's host lifecycle events. The stream is
// bounded and closes when the realm or the host closes; the underlying host
// subscription is detached on exit.
func (r *Realm) WatchEvents() <-chan HostEvent {
	out := make(chan HostEvent, 32)
	src := r.host.watchEvents()
	realm := r.realmID()
	go func() {
		defer close(out)
		defer r.host.unwatch(src)
		for {
			select {
			case ev, ok := <-src:
				if !ok {
					return
				}
				if ev.Realm != realm {
					continue
				}
				select {
				case out <- ev:
				case <-r.done:
					return
				default:
				}
			case <-r.done:
				return
			}
		}
	}()
	return out
}

// Enroll requests a credential lifecycle operation from the realm's
// enrollment provider. Enrollment tokens are audience-scoped to enrollment;
// the returned proof is validated against this realm.
func (r *Realm) Enroll(ctx context.Context, op EnrollmentOp) (IdentityProof, error) {
	if err := ctx.Err(); err != nil {
		return IdentityProof{}, err
	}
	if !op.Valid() {
		return IdentityProof{}, CodeInvalidConfig.Wrap("unknown enrollment operation")
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return IdentityProof{}, CodeClosed.Wrap("realm closed")
	}
	provider := r.host.enrollmentProvider()
	if provider == nil {
		return IdentityProof{}, CodeUnsupportedCapability.Wrap("no enrollment provider")
	}
	realm := r.realmID()
	proof, err := provider.Enroll(ctx, realm, op)
	if err != nil {
		return IdentityProof{}, err
	}
	if proof.Realm != realm {
		return IdentityProof{}, CodeRealmMismatch.Wrap("enrollment returned a foreign-realm credential")
	}
	return proof, nil
}
