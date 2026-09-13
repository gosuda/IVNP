package overlay

import (
	"cmp"
	"context"
	"errors"
	"time"

	"gosuda.org/ivnp/foundation"
)

// attempt is one bounded resolution source; found decides whether a clean
// result counts as having resolved anything.
type attempt[T any] struct {
	run   func(context.Context) (T, error)
	found func(T) bool
}

// lookupPlan separates local IVNP discovery from the native public path. The
// strategy selects by source, never by bound-context order.
type lookupPlan struct {
	local  []attempt[[]RouteCandidate]
	public []attempt[[]RouteCandidate]
}

func candidatesFound(found []RouteCandidate) bool { return len(found) > 0 }

// resolveCandidates implements dual-stack known-endpoint resolution: pin the
// EndpointID, singleflight the realm's discovery strategy over the same typed
// identity, then verify, floor, and filter candidates. Discovery never
// redirects the target.
func (r *Realm) resolveCandidates(ctx context.Context, target ServiceTarget, eff *effectivePolicy) ([]RouteCandidate, error) {
	if err := target.Endpoint.Validate(); err != nil {
		return nil, err
	}
	raw, err := r.lookupShared(ctx, target, eff.privacy, eff.discoveryHedge)
	if err != nil {
		return nil, err
	}
	return r.admitCandidates(ctx, target, eff, raw)
}

// lookupShared deduplicates concurrent resolutions of the same identity under
// one access-policy generation and privacy class.
func (r *Realm) lookupShared(ctx context.Context, target ServiceTarget, privacy PrivacyClass, delay time.Duration) ([]RouteCandidate, error) {
	key := sflightKey{endpoint: target.Endpoint.ID, port: target.Port, gen: r.PolicyGen(), privacy: privacy}
	if target.Endpoint.Encrypted != nil {
		key.blinded = target.Endpoint.Encrypted.BlindedHash
	}
	r.sfMu.Lock()
	if r.inflight == nil {
		r.inflight = make(map[sflightKey]*sflightCall)
	}
	if call, ok := r.inflight[key]; ok {
		r.sfMu.Unlock()
		select {
		case <-call.done:
			return call.res, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &sflightCall{done: make(chan struct{})}
	r.inflight[key] = call
	r.sfMu.Unlock()

	call.res, call.err = r.runDiscovery(ctx, target, delay)
	r.sfMu.Lock()
	delete(r.inflight, key)
	close(call.done)
	r.sfMu.Unlock()
	return call.res, call.err
}

// runDiscovery executes the realm's discovery strategy over the plan. Local
// attempts run before public attempts regardless of context order; a suspect
// local result records the transition rather than substituting an identity.
func (r *Realm) runDiscovery(ctx context.Context, target ServiceTarget, delay time.Duration) ([]RouteCandidate, error) {
	plan, err := r.planLookups(target)
	if err != nil {
		return nil, err
	}
	var found []RouteCandidate
	switch r.discoveryMode() {
	case DiscoveryLocalOnly:
		if len(plan.local) == 0 {
			return nil, CodeUnreachable.Wrap("local_only binds no ivnp context")
		}
		found, err = runFirst(ctx, plan.local)
		if err != nil {
			r.setDiscovery(ctx, DiscoveryIsolated)
		} else {
			r.setDiscovery(ctx, DiscoveryHealthy)
		}
	case DiscoveryPublicPrimary:
		if len(plan.public) == 0 {
			return nil, CodePublicUnavailable.Wrap("public_primary requires a native context")
		}
		found, err = runFirst(ctx, plan.public)
		r.finishDiscovery(ctx, err)
	case DiscoveryPublicFallback:
		found, err = runFirst(ctx, append(append([]attempt[[]RouteCandidate](nil), plan.local...), plan.public...))
		r.finishDiscovery(ctx, err)
	case DiscoveryHedged:
		found, err = runHedged(ctx, append(append([]attempt[[]RouteCandidate](nil), plan.local...), plan.public...), delay)
		r.finishDiscovery(ctx, err)
	default:
		return nil, CodeInvalidConfig.Wrap("unknown discovery mode")
	}
	return found, err
}

func (r *Realm) finishDiscovery(ctx context.Context, err error) {
	if err != nil {
		r.setDiscovery(ctx, DiscoveryDegraded)
	}
}

// planLookups builds source-separated attempts under the per-resolution query
// budget. A suspect or absent local result never substitutes another identity.
func (r *Realm) planLookups(target ServiceTarget) (lookupPlan, error) {
	r.mu.Lock()
	bound := append([]*NetworkContext(nil), r.bound...)
	r.mu.Unlock()
	var plan lookupPlan
	for _, nctx := range bound {
		nctx := nctx
		switch nctx.kind {
		case ContextIVNP:
			plan.local = append(plan.local, attempt[[]RouteCandidate]{
				found: candidatesFound,
				run: func(ctx context.Context) ([]RouteCandidate, error) {
					found, err := r.lookupLocal(ctx, nctx, target)
					if err != nil || len(found) == 0 {
						r.setDiscovery(ctx, DiscoveryLocalSuspect)
					} else {
						r.setDiscovery(ctx, DiscoveryHealthy)
					}
					return found, err
				},
			})
		case ContextNativeI2P:
			plan.public = append(plan.public, attempt[[]RouteCandidate]{
				found: candidatesFound,
				run: func(ctx context.Context) ([]RouteCandidate, error) {
					r.setDiscovery(ctx, DiscoveryPublicResolving)
					found, err := r.lookupPublic(ctx, nctx, target)
					if err == nil && len(found) > 0 {
						r.setDiscovery(ctx, DiscoveryContactRevalidated)
					}
					return found, err
				},
			})
		}
	}
	if len(plan.local)+len(plan.public) > maxQueryAttempts {
		return lookupPlan{}, CodeLookupBudgetExceeded.Wrap("resolution exceeds the per-target query budget")
	}
	return plan, nil
}

func (r *Realm) lookupLocal(ctx context.Context, nctx *NetworkContext, target ServiceTarget) ([]RouteCandidate, error) {
	// An encrypted endpoint locates by its blinded key on every path; the
	// unblinded destination hash is never the lookup key.
	locator := Locator{Kind: LocatorDestinationHash, Hash: foundation.Hash(target.Endpoint.ID)}
	if target.Endpoint.Encrypted != nil {
		locator = Locator{Kind: LocatorEncrypted, Encrypted: target.Endpoint.Encrypted}
	}
	ref := PeerRef{Realm: r.realmID(), Locator: locator}
	found, err := nctx.lookup(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := make([]RouteCandidate, 0, len(found)+4)
	for _, c := range found {
		c.Provenance = ProvenanceLocal
		out = append(out, c)
	}
	provider := r.host.routeProvider()
	if provider == nil {
		return out, nil
	}
	extra, err := provider.Candidates(ctx, target, r.realmID(), 8)
	if err != nil {
		r.host.emit(ctx, AuditEvent{Kind: "route_provider_failure", Realm: r.realmID(), Endpoint: target.Endpoint.ID, At: time.Now().Unix()})
		return out, nil
	}
	for _, c := range extra {
		c.Provenance = ProvenanceLocal
		out = append(out, c)
	}
	return out, nil
}

// lookupPublic resolves the same EndpointID through the native public netDB
// under the host/realm public-query budgets. The record's native signature and
// expected Destination hash are verified before its extension authorizes
// anything.
func (r *Realm) lookupPublic(ctx context.Context, nctx *NetworkContext, target ServiceTarget) ([]RouteCandidate, error) {
	release, err := r.acquirePublic()
	if err != nil {
		return nil, err
	}
	defer release()
	backend, err := nctx.NativePublic()
	if err != nil {
		switch r.discoveryMode() {
		case DiscoveryPublicFallback, DiscoveryHedged:
			return nil, CodeFallbackNotReady.Wrap("native public fallback path is unavailable")
		}
		return nil, err
	}
	// An encrypted endpoint's record lives under the blinded lookup key; the
	// unblinded destination hash never locates it.
	lookupKey := foundation.Hash(target.Endpoint.ID)
	if target.Endpoint.Encrypted != nil {
		lookupKey = target.Endpoint.Encrypted.BlindedHash
	}
	record, err := backend.LookupDestination(ctx, lookupKey)
	if err != nil {
		return nil, err
	}
	provenance := cmp.Or(record.Provenance, ProvenancePublicNative)
	if record.Encrypted {
		return nil, r.encryptedRecordError(record.Raw, target)
	}
	ls2, err := foundation.NetworkDatabaseParseLeaseSet2(record.Raw)
	if err != nil {
		return nil, err
	}
	if foundation.Hash(target.Endpoint.ID) != ls2.Hash() {
		return nil, CodeIdentityMismatch.Wrap("netdb record does not match the pinned endpoint")
	}
	valid, err := ls2.Verify()
	if err != nil || !valid {
		return nil, CodeEndpointBindingInvalid.Wrap("netdb record signature invalid")
	}
	now := time.Now().Unix()
	if int64(ls2.Header.Published)+int64(ls2.Header.Expires) < now {
		return nil, CodeRecordStale.Wrap("netdb record expired")
	}
	// recordBound is the verified authorization lifetime of this record: its
	// published expiry, further bounded by the earliest live lease when the
	// record carries one. Extension candidates never outlive it — an
	// extension's own NotAfter cannot extend the record that carries it.
	recordBound := int64(ls2.Header.Published) + int64(ls2.Header.Expires)
	var candidates []RouteCandidate
	if leaseEnd, live := minLiveLease(ls2, now); live {
		if leaseEnd < recordBound {
			recordBound = leaseEnd
		}
		candidates = append(candidates, RouteCandidate{
			Endpoint: target.Endpoint.ID, Fabric: nctx.fabric.ID,
			NetworkID: nctx.fabric.NetworkID, Realm: r.realmID(),
			Class: RouteNativeI2P, Carrier: "i2p-tunnel",
			NotAfter:   recordBound,
			Provenance: provenance, Exposure: PrivacyI2PCompatible,
		})
	}
	// The x-ov.* envelope's membership hints and format-2 floor advance on
	// every verified record, not only for targets it can authorize. Its
	// endpoints are native-fabric direct contacts for its declared port.
	if env := r.contactHints(ctx, ls2.Options, target.Endpoint.ID, false, recordBound); env != nil {
		candidates = r.contactCandidates(candidates, env, target, provenance, recordBound)
	}
	presence, err := r.parsePresence(ctx, ls2.Options, target.Endpoint.ID)
	if err != nil {
		return nil, err
	}
	if presence == nil {
		return candidates, nil
	}
	if presence.NotAfter <= now {
		// Expired extensions are unusable; the verified native record stands.
		return candidates, nil
	}
	// The presence's authorization expires with the record that carries it;
	// its own NotAfter can shorten, never extend, that bound.
	if presence.NotAfter > recordBound {
		presence.NotAfter = recordBound
	}
	key := FloorKey{Endpoint: target.Endpoint.ID, Fabric: presence.FabricID, Realm: presence.RealmID, Port: presence.Port, Format: 1}
	switch verdict := r.floors.Check(key, presence.Incarnation, presence.Sequence, presence.Digest()); verdict {
	case FloorRollback:
		// Stale extension is unusable; the verified native record stands.
		return candidates, nil
	case FloorEquivocation:
		r.host.emit(ctx, AuditEvent{Kind: "equivocation", Realm: presence.RealmID, Endpoint: target.Endpoint.ID, At: now})
		r.host.broadcast(HostEvent{Kind: EventEquivocation, Realm: presence.RealmID})
		return candidates, nil
	}
	if r.boundFabric(presence.FabricID) == nil {
		return candidates, nil
	}
	if err := r.floors.Admit(key, presence.Incarnation, presence.Sequence, presence.Digest(), presence.NotAfter); err != nil {
		// A raced admission — a concurrent verified record won the position —
		// drops only the extension. The verified native candidates stand.
		if errors.Is(err, CodeEquivocation) {
			r.host.emit(ctx, AuditEvent{Kind: "equivocation", Realm: presence.RealmID, Endpoint: target.Endpoint.ID, At: now})
			r.host.broadcast(HostEvent{Kind: EventEquivocation, Realm: presence.RealmID})
		}
		return candidates, nil
	}
	// The presence authorizes contacts only for its declared realm and only
	// for the service port it was published under; the floor still advanced.
	if presence.RealmID != r.realmID() {
		return candidates, nil
	}
	if presence.Port != target.Port {
		return candidates, nil
	}
	if presence.HasCapability(CapDirect) {
		for _, ep := range presence.Endpoints {
			contact := ep
			candidates = append(candidates, RouteCandidate{
				Endpoint: target.Endpoint.ID, Fabric: presence.FabricID,
				NetworkID: presence.NetworkID, Realm: presence.RealmID,
				Class: RouteDirect, Carrier: ep.Transport, Contact: &contact,
				ContactKey: presence.ContactKey, RouterHint: presence.RouterHint,
				Incarnation: presence.Incarnation, Sequence: presence.Sequence,
				NotAfter:   presence.NotAfter,
				Provenance: provenance, Exposure: PrivacyExplicitDirect,
			})
		}
	}
	if presence.HasCapability(CapRouted) {
		candidates = append(candidates, RouteCandidate{
			Endpoint: target.Endpoint.ID, Fabric: presence.FabricID,
			NetworkID: presence.NetworkID, Realm: presence.RealmID,
			Class: RouteRouted, Carrier: "routed", ContactKey: presence.ContactKey,
			RouterHint:  presence.RouterHint,
			Incarnation: presence.Incarnation, Sequence: presence.Sequence,
			NotAfter:   presence.NotAfter,
			Provenance: provenance, Exposure: PrivacyExplicitDirect,
		})
	}
	return candidates, nil
}

// encryptedRecordError classifies an Encrypted LS2 honestly: the signature is
// verifiable, but deriving an inner LeaseSet requires local access material and
// a decryption path this layer does not wire.
func (r *Realm) encryptedRecordError(raw []byte, target ServiceTarget) error {
	els2, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(raw)
	if err != nil {
		return err
	}
	valid, err := els2.Verify()
	if err != nil || !valid {
		return CodeEndpointBindingInvalid.Wrap("encrypted netdb record signature invalid")
	}
	if target.Endpoint.Encrypted == nil {
		return CodeLookupCapabilityRequired.Wrap("encrypted record requires local access material")
	}
	if els2.Hash() != target.Endpoint.Encrypted.BlindedHash {
		return CodeIdentityMismatch.Wrap("encrypted record does not match the blinded locator")
	}
	return CodeUnsupportedCapability.Wrap("encrypted ls2 decryption is not wired")
}

// parsePresence extracts the x-ivnp.* presence against each bound IVNP
// descriptor. Absence is ordinary; a malformed extension under a verified
// native signature is audited rather than silently treated as absent. A
// fabric mismatch is normal routing across descriptors and is not audited.
func (r *Realm) parsePresence(ctx context.Context, m foundation.Mapping, endpoint EndpointID) (*DualPresence, error) {
	r.mu.Lock()
	bound := append([]*NetworkContext(nil), r.bound...)
	r.mu.Unlock()
	for _, nctx := range bound {
		if nctx.kind != ContextIVNP {
			continue
		}
		presence, err := ParseDualPresence(m, nctx.fabric)
		if err != nil {
			if !errors.Is(err, CodeFabricMismatch) {
				r.host.emit(ctx, AuditEvent{
					Kind: "presence_invalid", Endpoint: endpoint, At: time.Now().Unix(),
				})
			}
			continue
		}
		if presence == nil {
			return nil, nil
		}
		return presence, nil
	}
	return nil, nil
}

// contactHints extracts the verified x-ov.* envelope from a signed native
// record and admits it through the format-2 rollback floor. recordBound is
// the enclosing record's verified lifetime; the floor entry expires with it.
// A malformed, expired, rolled-back, or equivocating envelope drops its
// hints; the verified native record stands. routerRecord applies the RI
// extension budget, under which the parser already rejects the LS2-only
// service port.
func (r *Realm) contactHints(ctx context.Context, m foundation.Mapping, endpoint EndpointID, routerRecord bool, recordBound int64) *ContactEnvelope {
	kind := RecordLS2
	if routerRecord {
		kind = RecordRI
	}
	env, err := ParseContactEnvelope(m, kind)
	if err != nil {
		r.host.emit(ctx, AuditEvent{
			Kind: "contact_extension_invalid", Endpoint: endpoint, At: time.Now().Unix(),
		})
		return nil
	}
	if env == nil {
		return nil
	}
	now := time.Now().Unix()
	if env.NotAfter <= now {
		return nil
	}
	// In open mode the member label must equal the record's own identity
	// hash; it is not a member slot an attacker may choose.
	if env.Admission == AdmissionOpen && env.MemberID != MemberID(endpoint) {
		r.host.emit(ctx, AuditEvent{Kind: "contact_extension_invalid", Endpoint: endpoint, At: now})
		return nil
	}
	key := FloorKey{Endpoint: endpoint, Fabric: NativeI2PFabricID, Realm: env.RealmID, Port: env.Port, Format: 2}
	switch r.floors.Check(key, env.Incarnation, env.Sequence, env.Digest()) {
	case FloorRollback:
		return nil
	case FloorEquivocation:
		r.host.emit(ctx, AuditEvent{Kind: "equivocation", Realm: env.RealmID, Endpoint: endpoint, At: now})
		r.host.broadcast(HostEvent{Kind: EventEquivocation, Realm: env.RealmID})
		return nil
	}
	// The floor entry's lifetime is the enclosing record's, not the
	// envelope's own clock.
	floorNotAfter := env.NotAfter
	if floorNotAfter > recordBound {
		floorNotAfter = recordBound
	}
	if err := r.floors.Admit(key, env.Incarnation, env.Sequence, env.Digest(), floorNotAfter); err != nil {
		if errors.Is(err, CodeEquivocation) {
			r.host.emit(ctx, AuditEvent{Kind: "equivocation", Realm: env.RealmID, Endpoint: endpoint, At: now})
			r.host.broadcast(HostEvent{Kind: EventEquivocation, Realm: env.RealmID})
		}
		return nil
	}
	return env
}

// contactCandidates projects an admitted x-ov.* envelope into direct route
// candidates scoped to this realm and the requested port. recordBound caps
// every candidate's freshness at the enclosing record's verified lifetime:
// the envelope's NotAfter can shorten, never extend, its carrier's bound.
// The envelope's member and credential digest remain hints until admission
// verifies the credential itself.
func (r *Realm) contactCandidates(candidates []RouteCandidate, env *ContactEnvelope, target ServiceTarget, provenance Provenance, recordBound int64) []RouteCandidate {
	if env.RealmID != r.realmID() || env.Port != target.Port {
		return candidates
	}
	notAfter := env.NotAfter
	if notAfter > recordBound {
		notAfter = recordBound
	}
	for _, ep := range env.Endpoints {
		contact := ep
		candidates = append(candidates, RouteCandidate{
			Endpoint: target.Endpoint.ID, Fabric: NativeI2PFabricID,
			NetworkID: WireNetworkIDPublicI2P, Realm: env.RealmID,
			Class: RouteDirect, Carrier: ep.Transport, Contact: &contact,
			ContactKey:       env.ChannelKey,
			CredentialDigest: env.CredentialDigest,
			Incarnation:      env.Incarnation, Sequence: env.Sequence,
			NotAfter:   notAfter,
			Provenance: provenance, Exposure: PrivacyExplicitDirect,
		})
	}
	return candidates
}

func (r *Realm) boundFabric(id FabricID) *NetworkContext {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, nctx := range r.bound {
		if nctx.fabric.ID == id {
			return nctx
		}
	}
	return nil
}

// minLiveLease returns the earliest expiration among the record's live
// leases. A record's usable path ends at its earliest live lease, so reported
// freshness must not outlive it.
func minLiveLease(ls2 foundation.NetworkDatabaseLeaseSet2, now int64) (int64, bool) {
	it := ls2.Leases()
	var minEnd int64
	for {
		lease, ok, err := it.Next()
		if err != nil {
			return 0, false
		}
		if !ok {
			break
		}
		if end := int64(lease.EndDate); end > now && (minEnd == 0 || end < minEnd) {
			minEnd = end
		}
	}
	return minEnd, minEnd != 0
}

// admitCandidates applies hard eligibility filters after verification:
// endpoint and realm match, freshness, caller/service/realm allow-lists, the
// strictest privacy class, and the per-prefix concentration cap.
func (r *Realm) admitCandidates(ctx context.Context, target ServiceTarget, eff *effectivePolicy, in []RouteCandidate) ([]RouteCandidate, error) {
	now := time.Now().Unix()
	realm := r.realmID()
	out := make([]RouteCandidate, 0, len(in))
	for _, c := range in {
		if c.Endpoint != target.Endpoint.ID {
			continue
		}
		if c.Realm != realm {
			continue
		}
		if c.NotAfter != 0 && c.NotAfter <= now {
			continue
		}
		if !eff.allowsFabric(c.Fabric) || !eff.allowsClass(c.Class) {
			continue
		}
		// The claimed fabric must be a context the realm bound, and its wire
		// network number must equal the bound descriptor's: a provider
		// candidate cannot pair a bound fabric with a foreign netId.
		if nctx := r.boundFabric(c.Fabric); nctx == nil || nctx.fabric.NetworkID != c.NetworkID {
			continue
		}
		// A direct or routed candidate must pin the owner-authorized contact
		// key the channel has to prove; without one there is no endpoint key
		// binding to verify. Native candidates carry none — destination
		// authentication is inherent to the native tunnel.
		if c.Class != RouteNativeI2P && c.ContactKey == ([32]byte{}) {
			continue
		}
		if !privacyAdmits(eff.privacy, c, eff.publicFabrics) {
			continue
		}
		out = append(out, c)
	}
	prefix := r.prefix()
	kept, dropped := capByPrefix(prefix, out)
	if dropped > 0 {
		r.host.emit(ctx, AuditEvent{
			Kind: "prefix_cap_applied", Realm: realm,
			Endpoint: target.Endpoint.ID, At: now,
		})
		// Best-effort proceeds with the capped set; strict treats observed
		// concentration beyond the bound as a diversity failure.
		if prefix.Mode == PrefixStrict {
			return nil, CodeInsufficientDiversity.Wrap("strict prefix policy rejected concentrated candidates")
		}
	}
	return kept, nil
}

func (r *Realm) prefix() PrefixPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Prefix
}

// privacyAdmits is a hard filter; no score can outweigh it. private_confined
// excludes every public fabric: native public I2P and any descriptor-marked
// public IVNP fabric bound to this realm.
func privacyAdmits(minimum PrivacyClass, c RouteCandidate, publicFabrics map[FabricID]struct{}) bool {
	switch minimum {
	case PrivacyI2PCompatible:
		return c.Class == RouteNativeI2P && c.Fabric == NativeI2PFabricID
	case PrivacyPrivateConfined:
		_, public := publicFabrics[c.Fabric]
		return c.Class != RouteNativeI2P && !public
	}
	return true
}

// capByPrefix limits admitted contact-bearing candidates to MaxPerPrefix per
// masked IP prefix. Candidates without a contact address cannot be evaluated
// against an IP prefix and are not concentration-counted here.
func capByPrefix(p PrefixPolicy, in []RouteCandidate) (kept []RouteCandidate, dropped int) {
	if p.Mode == PrefixDisabled || len(in) == 0 {
		return in, 0
	}
	kept = make([]RouteCandidate, 0, len(in))
	counts := make(map[[21]byte]int)
	for _, c := range in {
		key, ok := prefixKey(c, p)
		if !ok {
			kept = append(kept, c)
			continue
		}
		if counts[key] >= p.MaxPerPrefix {
			dropped++
			continue
		}
		counts[key]++
		kept = append(kept, c)
	}
	return kept, dropped
}

// prefixKey returns a fixed-size masked-prefix key for a contact address.
// IPv4-mapped IPv6 forms count under the IPv4 policy.
func prefixKey(c RouteCandidate, p PrefixPolicy) ([21]byte, bool) {
	if c.Contact == nil {
		return [21]byte{}, false
	}
	ip := c.Contact.Address.Addr().Unmap()
	var key [21]byte
	if ip.Is4() {
		v4 := ip.As4()
		key[0] = 4
		bits := p.IPv4Prefix
		masked := maskBytes(v4[:], bits)
		copy(key[1:5], masked)
		return key, true
	}
	v6 := ip.As16()
	key[0] = 6
	masked := maskBytes(v6[:], p.IPv6Prefix)
	copy(key[1:], masked)
	return key, true
}

func maskBytes(addr []byte, bits int) []byte {
	out := make([]byte, len(addr))
	copy(out, addr)
	for i := range out {
		rem := bits - i*8
		switch {
		case rem <= 0:
			out[i] = 0
		case rem < 8:
			out[i] &= 0xff << (8 - rem)
		}
	}
	return out
}

// runFirst executes attempts in order and returns the first success.
func runFirst[T any](ctx context.Context, attempts []attempt[T]) (T, error) {
	var zero T
	var last error
	for _, a := range attempts {
		found, err := a.run(ctx)
		if err == nil && a.found(found) {
			return found, nil
		}
		if err != nil {
			last = err
		}
	}
	if last == nil {
		last = CodeUnreachable.Wrap("no lookup produced a result")
	}
	return zero, last
}

// runHedged starts the primary attempt and launches the next after the hedge
// delay. The first valid result wins; stale later evidence cannot overwrite a
// higher admitted generation because floors apply at admission.
func runHedged[T any](ctx context.Context, attempts []attempt[T], delay time.Duration) (T, error) {
	var zero T
	if len(attempts) == 0 {
		return zero, CodeUnreachable.Wrap("no discovery sources")
	}
	type result struct {
		i     int
		found T
		err   error
	}
	results := make(chan result, len(attempts))
	inner, cancel := context.WithCancel(ctx)
	defer cancel()
	launch := func(i int) {
		go func() {
			found, err := attempts[i].run(inner)
			results <- result{i, found, err}
		}()
	}
	launch(0)
	launched := 1
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var last error
	for finished := 0; finished < len(attempts); {
		var hedge <-chan time.Time
		if launched < len(attempts) {
			hedge = timer.C
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case res := <-results:
			finished++
			if res.err == nil && attempts[res.i].found(res.found) {
				return res.found, nil
			}
			if res.err != nil {
				last = res.err
			}
			if launched < len(attempts) {
				launch(launched)
				launched++
			}
		case <-hedge:
			launch(launched)
			launched++
		}
	}
	if last == nil {
		last = CodeUnreachable.Wrap("no lookup produced a result")
	}
	return zero, errors.Join(CodeUnreachable.Wrap("all discovery sources failed"), last)
}
