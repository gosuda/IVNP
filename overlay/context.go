package overlay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/foundation"
)

// NetworkContext is one fabric instance: router identity, discovery state,
// routing, listeners, and replay/persistence namespaces. Its stores never merge
// with another context's.
type NetworkContext struct {
	host    *Host
	id      ContextID
	kind    ContextKind
	fabric  FabricDescriptor
	cfg     FabricConfig
	runtime ContextRuntime
	mu      sync.Mutex
	closed  bool
}

// Identity reports the context's scoped principals.
func (c *NetworkContext) Identity() (fabric FabricID, network WireNetworkID, router RouterID, id ContextID) {
	c.mu.Lock()
	runtime := c.runtime
	c.mu.Unlock()
	if runtime == nil {
		return c.fabric.ID, c.fabric.NetworkID, RouterID{}, c.id
	}
	return c.fabric.ID, c.fabric.NetworkID, runtime.RouterID(), c.id
}

// Status reports connectivity and provenance for this context alone.
func (c *NetworkContext) Status(ctx context.Context) (Connectivity, error) {
	c.mu.Lock()
	closed := c.closed
	runtime := c.runtime
	c.mu.Unlock()
	if closed {
		return Connectivity{}, CodeClosed.Wrap("context closed")
	}
	if runtime == nil {
		return Connectivity{}, nil
	}
	return runtime.Ready(ctx)
}

// NativePublic returns the narrow native netDB boundary; only a netId=2
// context has one.
func (c *NetworkContext) NativePublic() (PublicNetDBBackend, error) {
	if c.kind != ContextNativeI2P {
		return nil, CodeContextScopeMismatch.Wrap("native public operations require the netId=2 context")
	}
	c.mu.Lock()
	runtime := c.runtime
	c.mu.Unlock()
	if runtime == nil {
		return nil, CodeUnsupportedCapability.Wrap("context is still initializing")
	}
	return runtime.NetDB()
}

// InsertCandidate seeds the built-in local discovery table of an isolated
// realm. Contexts driven by a FabricProvider reject this; their tables are
// provider-owned.
func (c *NetworkContext) InsertCandidate(key foundation.Hash, candidate RouteCandidate) error {
	c.mu.Lock()
	runtime := c.runtime
	c.mu.Unlock()
	local, ok := runtime.(*localRuntime)
	if !ok {
		return CodeUnsupportedCapability.Wrap("context discovery table is provider-owned")
	}
	return local.InsertCandidate(key, candidate)
}

// ready reports connectivity; an initializing context reports no evidence.
func (c *NetworkContext) ready(ctx context.Context) (Connectivity, error) {
	c.mu.Lock()
	runtime := c.runtime
	c.mu.Unlock()
	if runtime == nil {
		return Connectivity{}, nil
	}
	return runtime.Ready(ctx)
}

func (c *NetworkContext) lookup(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	c.mu.Lock()
	runtime := c.runtime
	c.mu.Unlock()
	if runtime == nil {
		return nil, CodeClosed.Wrap("context is initializing")
	}
	return runtime.LookupPeer(ctx, ref)
}

func (c *NetworkContext) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	runtime := c.runtime
	c.mu.Unlock()
	var err error
	if runtime != nil {
		err = runtime.Close()
	}
	c.host.mu.Lock()
	delete(c.host.contexts, c.id)
	c.host.mu.Unlock()
	c.host.broadcast(HostEvent{Kind: EventContextClosed})
	return err
}

// Realm scopes membership, services, admission rules, and policy across its
// bound contexts.
type Realm struct {
	host      *Host
	cfg       RealmConfig
	bound     []*NetworkContext
	floors    *FloorTracker
	policyGen atomic.Uint64
	publicSem chan struct{}
	mu        sync.Mutex
	all       map[*Service]struct{}
	sfMu      sync.Mutex
	inflight  map[sflightKey]*sflightCall
	discMu    sync.Mutex
	discovery DiscoveryState
	done      chan struct{}
	closed    bool
}

// ID returns the realm namespace.
func (r *Realm) ID() RealmID { return r.realmID() }

// realmID is the mutex-guarded realm identity; cfg is replaced wholesale by
// ApplyPolicy and must never be read unlocked.
func (r *Realm) realmID() RealmID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.ID
}

func (r *Realm) admissionMode() AdmissionMode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Admission
}

func (r *Realm) discoveryMode() DiscoveryMode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Discovery
}

// hasContextKind reports whether a bound context of kind exists.
func (r *Realm) hasContextKind(kind ContextKind) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return contextKindBound(r.bound, kind)
}

func contextKindBound(bound []*NetworkContext, kind ContextKind) bool {
	for _, nctx := range bound {
		if nctx.kind == kind {
			return true
		}
	}
	return false
}

// boundContexts returns a snapshot of the bound contexts.
func (r *Realm) boundContexts() []*NetworkContext {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*NetworkContext(nil), r.bound...)
}

// Assurance reports the admission mode's identity-multiplication bound.
func (r *Realm) Assurance() SybilAssurance { return r.admissionMode().Assurance() }

// OpenService creates a service owning one endpoint identity.
func (r *Realm) OpenService(spec ServiceSpec) (*Service, error) {
	if err := r.validateServiceSpec(spec); err != nil {
		return nil, err
	}
	var endpoint EndpointRef
	if spec.Destination != nil {
		id, err := EndpointIDFromDestination(spec.Destination)
		if err != nil {
			return nil, err
		}
		endpoint = EndpointRef{ID: id, Destination: append([]byte(nil), spec.Destination...)}
		// One native identity admits exactly one writer host-wide; two realms
		// must never hold unfenced writers for the same public LS2 key.
		if err := r.host.claimEndpoint(endpoint.ID); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		if spec.Destination != nil {
			r.host.releaseEndpoint(endpoint.ID)
		}
		return nil, CodeClosed.Wrap("realm closed")
	}
	if r.all == nil {
		r.all = make(map[*Service]struct{})
	}
	svc := &Service{
		realm: r, spec: spec, endpoint: endpoint, done: make(chan struct{}),
		arbiter: &publicationArbiter{},
	}
	svc.arbiter.Restore(spec.PublicationFloor)
	r.all[svc] = struct{}{}
	return svc, nil
}

// validateServiceSpec applies realm/service policy interaction rules.
func (r *Realm) validateServiceSpec(spec ServiceSpec) error {
	r.mu.Lock()
	cfg := r.cfg
	r.mu.Unlock()
	if !spec.Privacy.valid() || !spec.Routing.valid() || !spec.Publication.valid() {
		return CodeInvalidConfig.Wrap("service carries an unknown enum value")
	}
	if len(spec.Protocols) == 0 {
		return CodeInvalidConfig.Wrap("service accepts no endpoint protocol")
	}
	if len(spec.Protocols) > 0 && !validProtocols(spec.Protocols) {
		return CodeInvalidConfig.Wrap("service carries an unknown endpoint protocol")
	}
	if spec.Privacy == PrivacyExplicitDirect && !cfg.AcknowledgeExposure {
		return CodePrivacyPolicyConflict.Wrap("direct exposure requires realm acknowledgement")
	}
	if privacyRestrictiveness(spec.Privacy) < privacyRestrictiveness(cfg.Privacy) {
		return CodePrivacyPolicyConflict.Wrap("service cannot relax the realm privacy class")
	}
	if spec.DualPresence {
		if spec.Publication != PublicationLS2 && spec.Publication != PublicationEncryptedLS2 {
			return CodeInvalidConfig.Wrap("dual presence requires an owned ls2 publication")
		}
		if spec.Port == 0 {
			return CodeInvalidConfig.Wrap("dual presence requires the service logical port")
		}
		if spec.Publication == PublicationLS2 {
			// A cleartext projection publishes a direct endpoint locator:
			// it requires the realm's explicit exposure consent and the
			// privacy class that owns it.
			if spec.Privacy != PrivacyExplicitDirect {
				return CodePrivacyPolicyConflict.Wrap("cleartext presence requires the explicit_direct privacy class")
			}
			if !cfg.AcknowledgeExposure {
				return CodePrivacyPolicyConflict.Wrap("cleartext presence publishes a direct locator without realm exposure acknowledgement")
			}
		}
	}
	if spec.Publication == PublicationNativeRI {
		return CodeInvalidConfig.Wrap("native_ri publication applies to routers, not service identities")
	}
	ownedPublication := spec.Publication == PublicationLS2 ||
		spec.Publication == PublicationEncryptedLS2 || spec.DualPresence
	if len(spec.Destination) == 0 && ownedPublication {
		return CodeInvalidConfig.Wrap("publication requires an owned destination identity")
	}
	if spec.Publication == PublicationEncryptedLS2 && spec.Privacy == PrivacyExplicitDirect {
		return CodePrivacyPolicyConflict.Wrap("explicit direct exposure conflicts with encrypted publication")
	}
	if ownedPublication {
		return r.projectionPermitted(spec)
	}
	return nil
}

func validProtocols(protocols []EndpointProtocol) bool {
	for _, p := range protocols {
		if p != EndpointProtocolLegacyStream && p != EndpointProtocolIVNPStream {
			return false
		}
	}
	return true
}

func (r *Realm) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	realmID := r.cfg.ID
	services := make([]*Service, 0, len(r.all))
	for s := range r.all {
		services = append(services, s)
	}
	r.mu.Unlock()
	close(r.done)
	var err error
	for _, s := range services {
		err = errors.Join(err, s.Close())
	}
	r.host.mu.Lock()
	delete(r.host.realms, realmID)
	r.host.mu.Unlock()
	r.host.broadcast(HostEvent{Kind: EventRealmClosed, Realm: realmID})
	return err
}

// publicationArbiter reserves (incarnation, sequence) durably before changed
// semantic contact data is issued. One writer per public record key.
type publicationArbiter struct {
	mu          sync.Mutex
	incarnation uint64
	sequence    uint64
	last        time.Time
	emergencies []time.Time
}

// The emergency escape is a bounded exception: at most four reservations per
// rolling hour bypass the minimum update interval, so the flag cannot become
// the ordinary update path.
const (
	maxEmergencyReserves = 4
	emergencyWindow      = time.Hour
)

// Reserve returns the next position for a semantic change. Counters never
// wrap; overflow requires explicit reprovisioning. Non-emergency semantic
// updates obey the minimum contact-update interval; emergency reservations
// consume a finite per-hour budget.
func (a *publicationArbiter) Reserve(emergency bool) (incarnation, sequence uint64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sequence == ^uint64(0) {
		return 0, 0, CodeRevisionConflict.Wrap("sequence exhausted; reprovision required")
	}
	now := time.Now()
	if emergency {
		cutoff := now.Add(-emergencyWindow)
		kept := a.emergencies[:0]
		for _, at := range a.emergencies {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		a.emergencies = kept
		if len(a.emergencies) >= maxEmergencyReserves {
			return 0, 0, CodeRateLimited.Wrap("emergency update budget exhausted")
		}
		a.emergencies = append(a.emergencies, now)
	} else if !a.last.IsZero() && now.Sub(a.last) < DefaultMinContactUpdate {
		return 0, 0, CodeRateLimited.Wrap("semantic contact update inside the minimum interval")
	}
	a.sequence++
	a.last = now
	return a.incarnation, a.sequence, nil
}

// Renew returns the reserved position for a lease renewal carrying unchanged
// contact fields.
func (a *publicationArbiter) Renew() (incarnation, sequence uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.incarnation, a.sequence
}

// Restore seeds the durable position recovered from a previous run. The floor
// is a minimum; the next reservation is strictly above it.
func (a *publicationArbiter) Restore(cursor PublicationCursor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cursor.Incarnation > a.incarnation ||
		(cursor.Incarnation == a.incarnation && cursor.Sequence > a.sequence) {
		a.incarnation, a.sequence = cursor.Incarnation, cursor.Sequence
	}
}

// Snapshot returns the current durable position for the operator to persist.
func (a *publicationArbiter) Snapshot() PublicationCursor {
	a.mu.Lock()
	defer a.mu.Unlock()
	return PublicationCursor{Incarnation: a.incarnation, Sequence: a.sequence}
}

// Service owns one endpoint identity and its authorized reachability
// projections.
type Service struct {
	realm     *Realm
	spec      ServiceSpec
	endpoint  EndpointRef
	arbiter   *publicationArbiter
	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	conns     map[*Connection]struct{}
	listeners map[*Listener]struct{}
	pubs      map[*Publication]struct{}
	// extFP/extFPSet fingerprint the last successfully published extension
	// content so lease renewal reuses the durable position; presenceFP does
	// the same for standalone Presence generation.
	extFP         [32]byte
	extFPSet      bool
	presenceFP    [32]byte
	presenceFPSet bool
}

// Endpoint returns the stable endpoint reference.
func (s *Service) Endpoint() EndpointRef { return s.endpoint }

// Done closes when the service closes; providers and bridges use it to
// release service-scoped registrations without polling.
func (s *Service) Done() <-chan struct{} { return s.done }

// RealmID returns the realm this service is scoped to.
func (s *Service) RealmID() RealmID { return s.realm.realmID() }

// PolicyGen returns the realm's current policy generation. An
// InboundProvider stamps ChannelScope.PolicyGen with the generation observed
// at delivery; a channel authenticated under a superseded generation is not
// admitted.
func (s *Service) PolicyGen() uint64 { return s.realm.PolicyGen() }

// Admission returns the realm's live admission mode. InboundProviders read it
// at delivery so a realm policy replacement cannot admit material issued
// under a superseded mode.
func (s *Service) Admission() AdmissionMode { return s.realm.admissionMode() }

// Port returns the service's declared logical port.
func (s *Service) Port() uint16 { return s.spec.Port }

// Presence builds the dual-presence projection for publication. Sequence
// reservation happens here; the enclosing native record is written by the
// single fenced publisher. presence.Emergency permits an update inside the
// minimum semantic-update interval for a bounded security/reachability
// emergency.
func (s *Service) Presence(ctx context.Context, presence DualPresence) ([]foundation.MappingEntry, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("service closed")
	}
	s.realm.mu.Lock()
	realmClosed := s.realm.closed
	s.realm.mu.Unlock()
	if realmClosed {
		return nil, CodeClosed.Wrap("realm closed")
	}
	if !s.spec.DualPresence {
		return nil, CodeUnsupportedCapability.Wrap("service did not authorize dual presence")
	}
	// The realm's current configuration is authoritative: ApplyPolicy may
	// have withdrawn the exposure acknowledgement or forbidden the
	// projection since the service opened.
	if err := s.realm.projectionPermitted(s.spec); err != nil {
		return nil, err
	}
	target := s.realm.boundFabric(presence.FabricID)
	if target == nil || target.kind != ContextIVNP || target.fabric.NetworkID != presence.NetworkID {
		return nil, CodeFabricMismatch.Wrap("presence does not match a bound ivnp context")
	}
	if s.spec.Port == 0 {
		return nil, CodeInvalidConfig.Wrap("presence requires the service logical port")
	}
	// Scope and provider checks precede position handling: a rejected request
	// must not consume a durable cursor position.
	binding := s.realm.host.bindingProvider()
	if binding == nil {
		return nil, CodeUnsupportedCapability.Wrap("no endpoint binding provider")
	}
	presence.RealmID = s.realm.realmID()
	presence.Port = s.spec.Port
	// Build at the current durable position first: a byte-identical semantic
	// projection is a lease renewal and reuses that position instead of
	// consuming a new one. An emergency update always reserves — its purpose
	// is a forced advance inside the minimum interval.
	incarnation, sequence := s.arbiter.Renew()
	entries, err := s.signAndVerifyPresence(ctx, binding, presence, incarnation, sequence)
	if err != nil {
		return nil, err
	}
	fp := extensionFingerprint(entries)
	if presence.Emergency || !s.unchangedPresence(fp) {
		incarnation, sequence, err = s.arbiter.Reserve(presence.Emergency)
		if err != nil {
			return nil, err
		}
		entries, err = s.signAndVerifyPresence(ctx, binding, presence, incarnation, sequence)
		if err != nil {
			return nil, err
		}
		fp = extensionFingerprint(entries)
	}
	s.notePresence(fp)
	return entries, nil
}

// signAndVerifyPresence produces the provider-signed projection at one
// durable position and re-verifies it like Publish's: it must carry only the
// projection's own keys, parse against a bound fabric, match the service's
// realm and port, carry that position, and satisfy the record's cleartext
// rules before it may be returned.
func (s *Service) signAndVerifyPresence(ctx context.Context, binding EndpointBindingProvider, presence DualPresence, incarnation, sequence uint64) ([]foundation.MappingEntry, error) {
	presence.Incarnation, presence.Sequence = incarnation, sequence
	entries, err := binding.SignPresence(ctx, presence, s.endpoint.Destination)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !isPresenceKey(e.Key) {
			return nil, CodeEndpointBindingInvalid.Wrap("signed presence carries foreign extension entries")
		}
	}
	parsed, err := s.verifySignedPresence(entries, s.spec.Publication == PublicationLS2)
	if err != nil {
		return nil, err
	}
	if err := s.checkPresenceScope(parsed, incarnation, sequence); err != nil {
		return nil, err
	}
	// The projection must name the fabric the caller asked for — not merely
	// any bound context — so a provider cannot silently retarget the record.
	if parsed.FabricID != presence.FabricID || parsed.NetworkID != presence.NetworkID {
		return nil, CodeEndpointBindingInvalid.Wrap("signed presence does not carry the requested fabric")
	}
	return entries, nil
}

// unchangedPresence reports whether the projected semantic content equals
// what the service last generated; identical content renews at the reserved
// position instead of consuming a new one.
func (s *Service) unchangedPresence(fp [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.presenceFPSet && s.presenceFP == fp
}

// notePresence records the semantic fingerprint of a generated projection.
func (s *Service) notePresence(fp [32]byte) {
	s.mu.Lock()
	s.presenceFP = fp
	s.presenceFPSet = true
	s.mu.Unlock()
}

// PublicationCursor returns the durable arbiter position for persistence.
func (s *Service) PublicationCursor() PublicationCursor {
	return s.arbiter.Snapshot()
}

// Dial runs the policy-constrained selection: resolve the pinned EndpointID,
// admit eligible candidates, race bounded setups, and commit one winner. A
// losing candidate never carries application data.
func (s *Service) Dial(ctx context.Context, target ServiceTarget, policy DialPolicy) (*Connection, error) {
	return s.dialWithResume(ctx, target, policy, nil)
}

// ResolveEndpoint resolves the pinned endpoint and returns the candidates
// that passed admission filters — evidence without a channel. It runs the
// same verification, floors, and policy gates as Dial.
func (s *Service) ResolveEndpoint(ctx context.Context, target ServiceTarget, policy DialPolicy) ([]RouteCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := target.Endpoint.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("service closed")
	}
	s.realm.mu.Lock()
	realmClosed := s.realm.closed
	s.realm.mu.Unlock()
	if realmClosed {
		return nil, CodeClosed.Wrap("realm closed")
	}
	policy.normalize()
	eff, err := s.realm.effectiveDialPolicy(s.spec, policy)
	if err != nil {
		return nil, err
	}
	return s.realm.resolveCandidates(ctx, target, eff)
}

// dialWithResume is Dial with an optional negotiated resumption contract; a
// non-nil contract is reconciled by the session provider on the successor's
// channel rather than relabeled.
func (s *Service) dialWithResume(ctx context.Context, target ServiceTarget, policy DialPolicy, resume *ResumeContract) (*Connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := target.Endpoint.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("service closed")
	}
	s.realm.mu.Lock()
	realmClosed := s.realm.closed
	s.realm.mu.Unlock()
	if realmClosed {
		return nil, CodeClosed.Wrap("realm closed")
	}
	policy.normalize()
	eff, err := s.realm.effectiveDialPolicy(s.spec, policy)
	if err != nil {
		return nil, err
	}
	return dial(ctx, s, target, policy, eff, resume)
}

// Connection is one committed route to an endpoint. Only the winning candidate
// is exposed for application I/O.
type Connection struct {
	Channel Channel
	Session Session
	route   RouteInfo
	fsm     *connFSM
	owner   *Service
	// dialTarget, dialPolicy, and eff support path-loss recovery on outbound
	// connections; inbound connections carry no dial context.
	dialTarget ServiceTarget
	dialPolicy DialPolicy
	eff        *effectivePolicy
	// policyGen is the realm policy generation the channel's scope was
	// authenticated under; registerConn uses it to close the drain race.
	policyGen uint64
	wrote     atomic.Bool
	mu        sync.Mutex
	closed    bool
}

// RouteInfo reports the actual committed path: network, carrier, endpoint
// protocol, exposure, and proof status. Unknown hops stay unknown.
type RouteInfo struct {
	Endpoint   EndpointID
	Port       uint16
	Context    ContextID
	Fabric     FabricID
	NetworkID  WireNetworkID
	Class      RouteClass
	Carrier    string
	Protocol   EndpointProtocol
	Exposure   PrivacyClass
	Provenance Provenance
	// FallbackReady is endpoint-level fallback readiness, separate from
	// network-level readiness.
	FallbackReady bool
}

func (c *Connection) Read(b []byte) (int, error) {
	n, err := c.Channel.Read(b)
	if err != nil {
		c.notePathLost(err)
	}
	return n, err
}

func (c *Connection) Write(b []byte) (int, error) {
	n, err := c.Channel.Write(b)
	if n > 0 {
		c.wrote.Store(true)
	}
	if err != nil {
		c.notePathLost(err)
	}
	return n, err
}

// notePathLost transitions the FSM on channel failure. A deadline timeout is
// caller-imposed, not evidence of path loss. Delivery is uncertain once
// application bytes may have reached the peer.
func (c *Connection) notePathLost(err error) {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return
	}
	_ = c.fsm.PathLost(c.wrote.Load())
}

// RouteInfo returns the committed route's properties.
func (c *Connection) RouteInfo() RouteInfo { return c.route }

// FailoverStatus reports the post-failure continuation state.
func (c *Connection) FailoverStatus() ConnState { return c.fsm.State() }

// Reconnect establishes a successor connection after path loss. With no
// possible prior delivery it runs a fresh bounded setup. With possible
// delivery it requires the negotiated resumption contract, and the successor
// session must be opened through a ResumableSessionProvider that reconciles
// replay/offset state under a strictly newer fence — an ordinary reconnect or
// new CID is never reported as a resume. Without a proven contract the call
// fails with reconnect_required and never replays in-flight data.
func (c *Connection) Reconnect(ctx context.Context) (*Connection, error) {
	c.mu.Lock()
	owner, closed := c.owner, c.closed
	c.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("connection closed")
	}
	if owner == nil || c.eff == nil {
		return nil, CodeReconnectRequired.Wrap("inbound connection has no dial context")
	}
	if c.fsm.State() != ConnPathLost {
		return nil, CodeContextScopeMismatch.Wrap("connection path is not lost")
	}
	if !c.fsm.deliveredPossible() {
		conn, err := owner.dialWithResume(ctx, c.dialTarget, c.dialPolicy, nil)
		if err != nil {
			return nil, err
		}
		_ = c.Close()
		return conn, nil
	}
	resumable := c.dialPolicy.Failover == FailoverNegotiatedResume && c.Session != nil
	var contract ResumeContract
	if resumable {
		var err error
		contract, err = c.Session.Resume()
		resumable = err == nil && contract.Supported
	}
	if !resumable {
		_ = c.fsm.BeginResume(false)
		return nil, CodeReconnectRequired.Wrap("possible delivery without a proven resumption contract")
	}
	if err := c.fsm.BeginResume(true); err != nil {
		return nil, err
	}
	conn, err := owner.dialWithResume(ctx, c.dialTarget, c.dialPolicy, &contract)
	if err != nil {
		_ = c.fsm.ResumeFailed()
		return nil, err
	}
	_ = c.fsm.ResumeCommitted(conn.route.Class)
	_ = c.Close()
	return conn, nil
}

// registerConn makes an authenticated connection visible to the owning
// service and closes the registration race against policy replacement: a
// channel whose scope was authenticated under a superseded generation can
// commit after drainSuperseded already snapshotted this service's conns. When
// the generation advanced, the committed route is re-evaluated under the
// current policy; a route it no longer admits is closed rather than escaping
// the drain.
func (s *Service) registerConn(conn *Connection) error {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[*Connection]struct{})
	}
	s.conns[conn] = struct{}{}
	closed := s.closed
	s.mu.Unlock()
	if closed {
		// The service closed while setup raced; the connection must not
		// outlive its owner.
		_ = conn.Close()
		return CodeClosed.Wrap("service closed during setup")
	}
	if conn.policyGen != s.realm.PolicyGen() && !s.realm.admitsRoute(conn.route) {
		_ = conn.Close()
		return CodeRevisionConflict.Wrap("committed route is not admitted under the current policy generation")
	}
	return nil
}

func (c *Connection) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.fsm.Revoke()
	err := c.Channel.Close()
	if c.Session != nil {
		err = errors.Join(err, c.Session.Close())
	}
	c.fsm.Drained()
	if c.owner != nil {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	}
	return err
}

var _ net.Conn = (*Connection)(nil)

func (c *Connection) LocalAddr() net.Addr {
	if c.owner != nil {
		return Addr{Endpoint: c.owner.Endpoint().ID, Port: c.owner.Port()}
	}
	if c.Channel != nil {
		return c.Channel.LocalAddr()
	}
	return Addr{}
}

func (c *Connection) RemoteAddr() net.Addr {
	if c.route.Endpoint != (EndpointID{}) {
		return Addr{Endpoint: c.route.Endpoint, Port: c.route.Port}
	}
	if c.Channel != nil {
		return c.Channel.RemoteAddr()
	}
	return Addr{}
}

func (c *Connection) SetDeadline(t time.Time) error {
	if c.Channel != nil {
		return c.Channel.SetDeadline(t)
	}
	return nil
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	if c.Channel != nil {
		return c.Channel.SetReadDeadline(t)
	}
	return nil
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	if c.Channel != nil {
		return c.Channel.SetWriteDeadline(t)
	}
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	conns := make([]*Connection, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	listeners := make([]*Listener, 0, len(s.listeners))
	for l := range s.listeners {
		listeners = append(listeners, l)
	}
	pubs := make([]*Publication, 0, len(s.pubs))
	for p := range s.pubs {
		pubs = append(pubs, p)
	}
	s.mu.Unlock()
	s.realm.mu.Lock()
	delete(s.realm.all, s)
	s.realm.mu.Unlock()
	if s.endpoint.ID != (EndpointID{}) {
		s.realm.host.releaseEndpoint(s.endpoint.ID)
	}
	// Closing a service stops renewal; it cannot promise immediate remote
	// deletion, so the projections are withdrawn rather than abandoned.
	for _, p := range pubs {
		p.Withdraw()
	}
	var err error
	for _, l := range listeners {
		err = errors.Join(err, l.Close())
	}
	for _, c := range conns {
		err = errors.Join(err, c.Close())
	}
	return err
}

// trackPublication records a publication for readiness reporting. It reports
// false when the service is already closed so the caller abandons the submit
// rather than publishing under a released identity.
func (s *Service) trackPublication(p *Publication) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.pubs == nil {
		s.pubs = make(map[*Publication]struct{})
	}
	s.pubs[p] = struct{}{}
	return true
}

// publicationFresh reports whether the service's required publication is
// current: a service that requires a public projection holds at least one
// non-terminal publication.
func (s *Service) publicationFresh() (required, fresh bool) {
	required = s.spec.Publication == PublicationLS2 || s.spec.Publication == PublicationEncryptedLS2
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.pubs {
		switch p.State() {
		case PublicationAcknowledged, PublicationReadBack, PublicationFresh:
			fresh = true
		}
	}
	return required, fresh
}

// listenerOpen reports whether the service has a live accept queue.
func (s *Service) listenerOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.listeners) > 0
}

// localRuntime is the built-in scoped context used when no FabricProvider is
// registered: an isolated in-memory discovery table. It never claims public
// reachability.
type localRuntime struct {
	cfg    FabricConfig
	router RouterID
	mu     sync.Mutex
	peers  map[foundation.Hash]RouteCandidate
	closed bool
}

func newLocalRuntime(cfg FabricConfig) *localRuntime {
	var router RouterID
	// A local context still needs a distinct router principal; derive it from
	// the identity reference so two contexts never collide.
	router = RouterID(sha256Sum("local-router/" + cfg.IdentityRef))
	return &localRuntime{cfg: cfg, router: router, peers: make(map[foundation.Hash]RouteCandidate)}
}

func (l *localRuntime) RouterID() RouterID { return l.router }

func (l *localRuntime) LookupPeer(ctx context.Context, ref PeerRef) ([]RouteCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, CodeClosed.Wrap("context closed")
	}
	key := ref.Locator.Hash
	if ref.Locator.Kind == LocatorEncrypted && ref.Locator.Encrypted != nil {
		key = ref.Locator.Encrypted.BlindedHash
	}
	candidate, ok := l.peers[key]
	if !ok {
		return nil, CodeUnreachable.Wrap("no local candidate for locator")
	}
	candidate.Provenance = ProvenanceLocal
	return []RouteCandidate{candidate}, nil
}

// defaultLocalPeerTableBound caps the built-in table when the descriptor
// carries no MaxPeers — the local store is never unbounded.
const defaultLocalPeerTableBound = 1024

// InsertCandidate adds a peer to the local table for testing and isolated
// realms. Public fabrics must source candidates through a FabricProvider. The
// table is bounded by the descriptor's MaxPeers, or a fixed default when the
// descriptor carries none.
func (l *localRuntime) InsertCandidate(key foundation.Hash, candidate RouteCandidate) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	bound := l.cfg.Descriptor.MaxPeers
	if bound <= 0 {
		bound = defaultLocalPeerTableBound
	}
	if _, exists := l.peers[key]; !exists && len(l.peers) >= bound {
		return CodeInvalidConfig.Wrap("local peer table is at its descriptor bound")
	}
	l.peers[key] = candidate
	return nil
}

func (l *localRuntime) NetDB() (PublicNetDBBackend, error) {
	return nil, CodeUnsupportedCapability.Wrap("no public netdb backend registered")
}

// Ready reports connectivity honestly: an in-memory table claims connectivity
// only while it holds at least one usable peer; an empty table is not a
// connected fabric.
func (l *localRuntime) Ready(ctx context.Context) (Connectivity, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Connectivity{Connected: !l.closed && len(l.peers) > 0, Peers: len(l.peers)}, nil
}

func (l *localRuntime) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}
