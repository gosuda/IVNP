// Package overlay implements the v3 unified dual-stack object model:
// Host -> Fabric/NetworkContext -> Realm -> Service, typed endpoint identity,
// owner-authorized contact projections, and policy-constrained route
// selection. Wire transports and public netDB access arrive through provider
// contracts; a missing provider fails visibly rather than being simulated.
package overlay

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Host owns resources, providers, scheduling, and context lifetimes. Close
// cancels and joins all children.
type Host struct {
	// openMu serializes OpenFabric so placement checks and context
	// registration stay atomic across provider calls.
	openMu    sync.Mutex
	mu        sync.Mutex
	topology  Topology
	providers providerSet
	contexts  map[ContextID]*NetworkContext
	realms    map[RealmID]*Realm
	// endpoints tracks each owned endpoint identity across all realms: one
	// native destination admits exactly one fenced writer per host.
	endpoints map[EndpointID]struct{}
	floors    *FloorTracker
	watchers  []chan HostEvent
	// auditDropped counts events the audit sink rejected; best-effort
	// telemetry may drop, but the drop must be observable.
	auditDropped atomic.Uint64
	publicSem    chan struct{}
	nextContext  ContextID
	closed       bool
	closeOnce    sync.Once
	closeDone    chan struct{}
	closeErr     error
	wasReady     bool
}

// HostConfig selects the deployment profile.
type HostConfig struct {
	Topology Topology
	// Audit receives security events; nil disables auditing.
	Audit AuditSink
}

// NewHost validates the profile and returns an empty host. Contexts and realms
// open explicitly afterward.
func NewHost(cfg HostConfig) (*Host, error) {
	if !cfg.Topology.valid() {
		return nil, CodeInvalidConfig.Wrap("unknown topology")
	}
	return &Host{
		topology:  cfg.Topology,
		contexts:  make(map[ContextID]*NetworkContext),
		realms:    make(map[RealmID]*Realm),
		endpoints: make(map[EndpointID]struct{}),
		floors:    NewFloorTracker(),
		publicSem: make(chan struct{}, maxHostPublicQueries),
		closeDone: make(chan struct{}),
		providers: providerSet{audit: cfg.Audit},
	}, nil
}

type providerSet struct {
	identity   IdentityProvider
	trust      TrustProvider
	verifier   CredentialVerifier
	secrets    SecretProvider
	bootstrap  BootstrapProvider
	fabric     FabricProvider
	binding    EndpointBindingProvider
	routes     RouteProvider
	sessions   SessionProvider
	transports []TransportProvider
	authorize  AuthorizationProvider
	enroll     EnrollmentProvider
	audit      AuditSink
}

// RegisterProvider installs an operator-owned provider. One object may fill
// several roles; unknown objects are rejected. Providers are never selected
// from untrusted contact data.
func (h *Host) RegisterProvider(p any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return CodeClosed.Wrap("host closed")
	}
	known := false
	if v, ok := p.(IdentityProvider); ok {
		h.providers.identity, known = v, true
	}
	if v, ok := p.(TrustProvider); ok {
		h.providers.trust, known = v, true
	}
	if v, ok := p.(CredentialVerifier); ok {
		h.providers.verifier, known = v, true
	}
	if v, ok := p.(SecretProvider); ok {
		h.providers.secrets, known = v, true
	}
	if v, ok := p.(BootstrapProvider); ok {
		h.providers.bootstrap, known = v, true
	}
	if v, ok := p.(FabricProvider); ok {
		h.providers.fabric, known = v, true
	}
	if v, ok := p.(EndpointBindingProvider); ok {
		h.providers.binding, known = v, true
	}
	if v, ok := p.(RouteProvider); ok {
		h.providers.routes, known = v, true
	}
	if v, ok := p.(SessionProvider); ok {
		h.providers.sessions, known = v, true
	}
	if v, ok := p.(TransportProvider); ok {
		h.providers.transports = append(h.providers.transports, v)
		known = true
	}
	if v, ok := p.(AuthorizationProvider); ok {
		h.providers.authorize, known = v, true
	}
	if v, ok := p.(EnrollmentProvider); ok {
		h.providers.enroll, known = v, true
	}
	if v, ok := p.(AuditSink); ok {
		h.providers.audit, known = v, true
	}
	if !known {
		return CodeInvalidConfig.Wrap("object implements no provider contract")
	}
	return nil
}

// OpenFabric creates one NetworkContext. A native context fixes netId 2; an
// IVNP context requires its pinned descriptor. Identity references and state
// directories are never shared across contexts. Placement is decided under
// openMu before the provider runs, and the context becomes visible to realm
// binding only after the provider succeeds: a realm can never bind a context
// whose initialization later failed.
func (h *Host) OpenFabric(ctx context.Context, cfg FabricConfig) (*NetworkContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	h.openMu.Lock()
	defer h.openMu.Unlock()

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, CodeClosed.Wrap("host closed")
	}
	if err := h.checkFabricPlacement(cfg); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	provider := h.providers.fabric
	h.mu.Unlock()

	var runtime ContextRuntime
	var err error
	if provider != nil {
		runtime, err = provider.OpenContext(ctx, cfg)
	} else {
		runtime = newLocalRuntime(cfg)
	}
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.Join(CodeClosed.Wrap("host closed"), runtime.Close())
	}
	h.nextContext++
	id := h.nextContext
	nctx := &NetworkContext{host: h, id: id, kind: cfg.Kind, cfg: cfg, runtime: runtime}
	nctx.fabric = descriptorOf(cfg)
	h.contexts[id] = nctx
	h.mu.Unlock()
	h.broadcast(HostEvent{Kind: EventContextOpened})
	return nctx, nil
}

func descriptorOf(cfg FabricConfig) FabricDescriptor {
	if cfg.Kind == ContextNativeI2P {
		return FabricDescriptor{ID: NativeI2PFabricID, NetworkID: WireNetworkIDPublicI2P, Reviewed: true, Public: true}
	}
	return cfg.Descriptor
}

// checkFabricPlacement enforces single-native and per-context isolation rules.
// Callers hold h.mu.
func (h *Host) checkFabricPlacement(cfg FabricConfig) error {
	nativeSeen := 0
	for _, existing := range h.contexts {
		if existing.cfg.IdentityRef == cfg.IdentityRef {
			return CodeInvalidConfig.Wrap("router identity reuse across contexts is forbidden")
		}
		if cfg.StateDir != "" && existing.cfg.StateDir != "" &&
			filepath.Clean(existing.cfg.StateDir) == filepath.Clean(cfg.StateDir) {
			return CodeInvalidConfig.Wrap("state directory reuse across contexts is forbidden")
		}
		if cfg.Kind == ContextIVNP && existing.kind == ContextIVNP &&
			existing.cfg.Descriptor.ID == cfg.Descriptor.ID {
			return CodeInvalidConfig.Wrap("two contexts cannot pin the same fabric descriptor")
		}
		for _, l := range cfg.Listeners {
			for _, shared := range existing.cfg.Listeners {
				if shared == l {
					return CodeInvalidConfig.Wrap("listener reuse across contexts is forbidden")
				}
			}
		}
		if existing.kind == ContextNativeI2P {
			nativeSeen++
		}
	}
	if cfg.Kind == ContextNativeI2P && nativeSeen > 0 {
		return CodeInvalidConfig.Wrap("at most one shared native public context per isolation group")
	}
	switch h.topology {
	case TopologyNativeI2P:
		if cfg.Kind != ContextNativeI2P {
			return CodeContextScopeMismatch.Wrap("native_i2p topology admits only the public context")
		}
	case TopologyIsolated:
		if cfg.Kind != ContextIVNP {
			return CodeContextScopeMismatch.Wrap("isolated topology admits no native public context")
		}
	case TopologyPublicDualStack:
		// Both kinds admitted; readiness, not construction, proves dual-stack.
	}
	return nil
}

// claimEndpoint registers exclusive ownership of an endpoint identity. A
// second claim — from any realm — is rejected, so a public LS2 key can never
// have two unfenced writers.
func (h *Host) claimEndpoint(id EndpointID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return CodeClosed.Wrap("host closed")
	}
	if _, held := h.endpoints[id]; held {
		return CodeIdentityMismatch.Wrap("destination already owned by a service")
	}
	h.endpoints[id] = struct{}{}
	return nil
}

// releaseEndpoint drops a service's ownership claim.
func (h *Host) releaseEndpoint(id EndpointID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.endpoints, id)
}

// OpenRealm creates a Realm over already-open bound contexts.
func (h *Host) OpenRealm(cfg RealmConfig) (*Realm, error) {
	bound, err := h.checkRealmPlacement(cfg)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, CodeClosed.Wrap("host closed")
	}
	if _, dup := h.realms[cfg.ID]; dup {
		h.mu.Unlock()
		return nil, CodeInvalidConfig.Wrap("realm already open")
	}
	r := &Realm{
		host: h, cfg: cfg, bound: bound, floors: h.floors,
		publicSem: make(chan struct{}, maxRealmPublicQueries),
		discovery: DiscoveryHealthy,
		done:      make(chan struct{}),
	}
	h.realms[cfg.ID] = r
	h.mu.Unlock()
	h.broadcast(HostEvent{Kind: EventRealmOpened, Realm: cfg.ID})
	return r, nil
}

func (h *Host) checkRealmPlacement(cfg RealmConfig) ([]*NetworkContext, error) {
	if cfg.ID == (RealmID{}) {
		return nil, CodeInvalidConfig.Wrap("realm requires an id")
	}
	if !cfg.Admission.valid() || !cfg.Discovery.valid() || !cfg.Privacy.valid() ||
		!cfg.Routing.valid() || !cfg.Publication.valid() {
		return nil, CodeInvalidConfig.Wrap("realm carries an unknown enum value")
	}
	if err := cfg.Prefix.validate(); err != nil {
		return nil, err
	}
	if err := h.checkRealmProviders(cfg); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(cfg.Contexts) == 0 {
		return nil, CodeContextScopeMismatch.Wrap("realm binds no context")
	}
	bound := make([]*NetworkContext, 0, len(cfg.Contexts))
	seen := make(map[ContextID]struct{}, len(cfg.Contexts))
	for _, id := range cfg.Contexts {
		nctx, ok := h.contexts[id]
		if !ok {
			return nil, CodeContextScopeMismatch.Wrap("realm binds an unknown context")
		}
		// A context that is already closed can never serve this realm.
		// nctx.mu under h.mu is safe: no path holds nctx.mu while acquiring
		// h.mu.
		nctx.mu.Lock()
		closed := nctx.closed
		nctx.mu.Unlock()
		if closed {
			return nil, CodeClosed.Wrap("realm binds a closed context")
		}
		if _, dup := seen[id]; dup {
			return nil, CodeContextScopeMismatch.Wrap("realm binds a context twice")
		}
		seen[id] = struct{}{}
		bound = append(bound, nctx)
	}
	if h.topology == TopologyPublicDualStack {
		native, ivnp := 0, 0
		for _, c := range bound {
			switch c.kind {
			case ContextNativeI2P:
				native++
			case ContextIVNP:
				ivnp++
			}
		}
		if native > 1 || ivnp > 1 {
			return nil, CodeContextScopeMismatch.Wrap("dual-stack realm binds at most one native and one ivnp context")
		}
	}
	var native *NetworkContext
	for _, c := range bound {
		if c.kind == ContextNativeI2P {
			native = c
		}
		if cfg.Privacy == PrivacyPrivateConfined && (c.kind == ContextNativeI2P || c.cfg.Descriptor.Public) {
			return nil, CodePrivacyPolicyConflict.Wrap("private_confined realm cannot bind a public context")
		}
	}
	if cfg.Discovery != DiscoveryLocalOnly {
		if native == nil {
			return nil, CodeContextScopeMismatch.Wrap("public discovery requires a bound native context")
		}
	}
	if cfg.Publication == PublicationLS2 || cfg.Publication == PublicationEncryptedLS2 {
		if native == nil {
			return nil, CodeContextScopeMismatch.Wrap("ls2 publication requires a bound native context")
		}
	}
	return bound, nil
}

// checkRealmProviders enforces admission/provider dependencies from the
// configuration invariants.
func (h *Host) checkRealmProviders(cfg RealmConfig) error {
	h.mu.Lock()
	identity, trust := h.providers.identity, h.providers.trust
	secrets := h.providers.secrets
	verifier := h.providers.verifier
	h.mu.Unlock()
	switch cfg.Admission {
	case AdmissionCredential, AdmissionCredentialPSK:
		if identity == nil || trust == nil || verifier == nil {
			return CodeInvalidConfig.Wrap("credential admission requires identity, trust, and credential verifier providers")
		}
	}
	if cfg.Admission == AdmissionPSK || cfg.Admission == AdmissionCredentialPSK {
		if secrets == nil {
			return CodeInvalidConfig.Wrap("psk admission requires a purpose-scoped secret provider")
		}
	}
	if cfg.Admission == AdmissionOpen && !cfg.AcknowledgeOpen {
		return CodeInvalidConfig.Wrap("open admission requires acknowledging unbounded sybil assurance")
	}
	if cfg.Discovery != DiscoveryLocalOnly && cfg.Privacy == PrivacyPrivateConfined {
		return CodeInvalidConfig.Wrap("private_confined forbids public lookup strategies")
	}
	if cfg.Privacy == PrivacyPrivateConfined && cfg.Routing == RoutingOpportunistic {
		return CodeInvalidConfig.Wrap("private_confined forbids public application-data fallback")
	}
	return nil
}

func (h *Host) identityProvider() IdentityProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.identity
}

func (h *Host) trustProvider() TrustProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.trust
}

func (h *Host) credentialVerifier() CredentialVerifier {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.verifier
}

func (h *Host) secretProvider() SecretProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.secrets
}

func (h *Host) bootstrapProvider() BootstrapProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.bootstrap
}

func (h *Host) authorizeProvider() AuthorizationProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.authorize
}

func (h *Host) enrollmentProvider() EnrollmentProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.enroll
}

func (h *Host) bindingProvider() EndpointBindingProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.binding
}

func (h *Host) routeProvider() RouteProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.routes
}

func (h *Host) sessionProvider() SessionProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.providers.sessions
}

func (h *Host) transportProviders() []TransportProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]TransportProvider(nil), h.providers.transports...)
}

func (h *Host) emit(ctx context.Context, event AuditEvent) {
	h.mu.Lock()
	sink := h.providers.audit
	h.mu.Unlock()
	if sink != nil {
		if err := sink.Emit(ctx, event); err != nil {
			h.auditDropped.Add(1)
		}
	}
}

// AuditDropped reports how many security events the audit sink rejected.
func (h *Host) AuditDropped() uint64 { return h.auditDropped.Load() }

// Status reports the multidimensional host view. Every axis aggregates only
// its own evidence; a host with no realms claims no policy satisfaction.
func (h *Host) Status(ctx context.Context) (Evidence, error) {
	h.mu.Lock()
	contexts := make([]*NetworkContext, 0, len(h.contexts))
	for _, c := range h.contexts {
		contexts = append(contexts, c)
	}
	realms := make([]*Realm, 0, len(h.realms))
	for _, r := range h.realms {
		realms = append(realms, r)
	}
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return Evidence{}, CodeClosed.Wrap("host closed")
	}
	var ev Evidence
	for _, c := range contexts {
		conn, err := c.ready(ctx)
		if err != nil {
			continue
		}
		switch c.kind {
		case ContextNativeI2P:
			ev.I2PConnectivity = ev.I2PConnectivity || conn.Connected
			ev.PublicLookup = ev.PublicLookup || conn.PublicLookup
			ev.NativePathReady = ev.NativePathReady || conn.Connected
		case ContextIVNP:
			ev.IVNPConnectivity = ev.IVNPConnectivity || conn.Connected
			ev.IVNPLookup = ev.IVNPLookup || conn.PublicLookup
			ev.FastPathReady = ev.FastPathReady || conn.Connected
		}
	}
	ev.MembershipFresh = len(realms) > 0
	ev.PublicationFresh = len(realms) > 0
	ev.PolicySatisfied = len(realms) > 0
	for _, r := range realms {
		status := r.Status(ctx)
		ev.MembershipFresh = ev.MembershipFresh && status.MembershipFresh
		ev.PublicationFresh = ev.PublicationFresh && status.PublicationCurrent
		ev.PolicySatisfied = ev.PolicySatisfied && status.RoutePolicySatisfied
	}
	return ev, nil
}

// Floors exposes the host's rollback-floor tracker for scoped publication
// checks.
func (h *Host) Floors() *FloorTracker { return h.floors }

// State reports the lifecycle position for readiness evaluation. A closing
// host reports HostStopping until Close finishes, then HostStopped. A host
// that once produced dual-ready evidence degrades rather than reverting to a
// partial-ready state when evidence goes stale.
func (h *Host) State(ctx context.Context) HostState {
	h.mu.Lock()
	closed, done, wasReady := h.closed, h.closeDone, h.wasReady
	h.mu.Unlock()
	if closed {
		select {
		case <-done:
			return HostStopped
		default:
			return HostStopping
		}
	}
	ev, err := h.Status(ctx)
	if err != nil {
		// Status fails only once closed; the position depends on whether
		// Close has finished, not merely begun.
		select {
		case <-done:
			return HostStopped
		default:
			return HostStopping
		}
	}
	if ev.DualReadyEvidence() && !wasReady {
		h.mu.Lock()
		h.wasReady = true
		h.mu.Unlock()
	}
	return EvaluateHostState(ev, false, wasReady)
}

// Capabilities reports which provider contracts are registered so callers can
// check capability honestly rather than discovering a gap at dial time.
type Capabilities struct {
	Identity      bool
	Trust         bool
	Verifier      bool
	Secrets       bool
	Bootstrap     bool
	Fabric        bool
	Binding       bool
	Routes        bool
	Sessions      bool
	Authorization bool
	Enrollment    bool
	Audit         bool
	Inbound       bool
	// Transports lists the registered carrier tokens.
	Transports []string
}

// Capabilities reports the host's implementation/provider capabilities.
func (h *Host) Capabilities() Capabilities {
	h.mu.Lock()
	defer h.mu.Unlock()
	var caps Capabilities
	p := h.providers
	caps.Identity = p.identity != nil
	caps.Trust = p.trust != nil
	caps.Verifier = p.verifier != nil
	caps.Secrets = p.secrets != nil
	caps.Bootstrap = p.bootstrap != nil
	caps.Fabric = p.fabric != nil
	caps.Binding = p.binding != nil
	caps.Routes = p.routes != nil
	caps.Sessions = p.sessions != nil
	caps.Authorization = p.authorize != nil
	caps.Enrollment = p.enroll != nil
	caps.Audit = p.audit != nil
	for _, t := range p.transports {
		caps.Transports = append(caps.Transports, t.Carrier())
		if _, ok := t.(InboundProvider); ok {
			caps.Inbound = true
		}
	}
	return caps
}

// Close cancels and joins all children; it is idempotent.
func (h *Host) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		contexts := make([]*NetworkContext, 0, len(h.contexts))
		for _, c := range h.contexts {
			contexts = append(contexts, c)
		}
		realms := make([]*Realm, 0, len(h.realms))
		for _, r := range h.realms {
			realms = append(realms, r)
		}
		watchers := h.watchers
		h.watchers = nil
		h.mu.Unlock()
		for _, ch := range watchers {
			close(ch)
		}
		for _, r := range realms {
			h.closeErr = errors.Join(h.closeErr, r.Close())
		}
		for _, c := range contexts {
			h.closeErr = errors.Join(h.closeErr, c.Close())
		}
		close(h.closeDone)
	})
	return h.closeErr
}
