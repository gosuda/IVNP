// Package ivnp embeds an in-memory-by-default I2P router and destination-owned
// stream and datagram sockets. Router construction never creates a service
// identity. RouterConfig.Networks plus Realm additionally compose overlay
// network contexts — the official I2P netId=2 context and isolated IVNP
// fabrics — under one membership realm.
package ivnp

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/overlay"
	"gosuda.org/ivnp/state"
)

type (
	Hash              = foundation.Hash
	DestinationPolicy = controlplane.DestinationPolicy
	DestinationKind   = controlplane.DestinationPolicyKind
)

const (
	DestinationPublicLS2     = controlplane.DestinationPublicLS2
	DestinationEncryptedNone = controlplane.DestinationEncryptedNone
	DestinationEncryptedDH   = controlplane.DestinationEncryptedDH
	DestinationEncryptedPSK  = controlplane.DestinationEncryptedPSK
)

// Router owns infrastructure, not an implicit application destination.
// Close joins its children and workers; callers must not copy a Router.
type Router struct {
	core             *node.EmbeddedRouter
	resolver         NameResolver
	defaultNetwork   string
	packetBudget     destination.ByteBudget
	packetWrites     chan struct{}
	packetQueueLimit int64
	ctx              context.Context
	cancel           context.CancelFunc
	// overlay, realmFabrics, fabricNames, realmPrivacy, and realmRouting are
	// populated when RouterConfig.Realm is set; overlay is nil otherwise.
	overlay      *node.OverlayBridge
	realmFabrics []FabricID
	fabricNames  map[string]FabricID
	realmPrivacy PrivacyClass
	realmRouting DataRouting
	overlayPorts map[uint16]struct{}
	mu           sync.Mutex
	closed       bool
	children     map[*Destination]struct{}
	creating     sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error
}

// NewRouter starts local infrastructure. It does not wait for tunnel readiness.
// The context bounds construction only. Nil Persistence keeps owned state in memory.
func NewRouter(ctx context.Context, cfg RouterConfig) (*Router, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, options, spec, err := routerSettings(cfg)
	if err != nil {
		return nil, err
	}
	return newRouter(ctx, cfg, settings, options, spec)
}

// newRouter keeps host transport injection at the composition boundary for
// deterministic embedding scenarios without exporting daemon options.
func newRouter(ctx context.Context, cfg RouterConfig, settings state.ConfigurationOperating, options controlplane.ControllerOptions, spec *node.OverlaySpec) (*Router, error) {
	core, err := node.NewEmbeddedRouterWithOverlay(ctx, settings, options, spec)
	// The bridge keeps its own realm key copy; the spec's is dead once Open
	// returns, success or failure.
	if spec != nil {
		clear(spec.Realm.PSK)
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, core.Close())
	}
	defaultNet, err := resolveDefaultNetwork(cfg)
	if err != nil {
		return nil, errors.Join(err, core.Close())
	}
	lifetime, cancel := context.WithCancel(context.Background())
	r := &Router{
		core: core, resolver: cfg.Resolver,
		defaultNetwork:   defaultNet,
		packetBudget:     newPacketBudget(cfg.Limits.PacketQueueBytes),
		packetWrites:     make(chan struct{}, cfg.Limits.MaxPendingPacketWrites),
		packetQueueLimit: cfg.Limits.PacketQueueBytes,
		ctx:              lifetime, cancel: cancel, children: make(map[*Destination]struct{}),
		overlayPorts: make(map[uint16]struct{}),
	}
	if bridge := core.Overlay(); bridge != nil {
		r.overlay = bridge
		r.realmFabrics = bridge.RealmFabrics()
		realm := cfg.Realm
		if realm == nil {
			realm = cfg.Policy
		}
		if realm != nil {
			r.realmPrivacy, r.realmRouting = realm.Privacy, realm.Routing
		}
		r.fabricNames = make(map[string]FabricID, len(cfg.Networks)+1)
		for i := range cfg.Networks {
			if cfg.Networks[i].Kind == NetworkIVNPFabric && cfg.Networks[i].Fabric != nil {
				r.fabricNames[cfg.Networks[i].Name] = cfg.Networks[i].Fabric.ID
			}
		}
		// The native context resolves only when it is realm-bound; an
		// unbound name resolving would hide a misconfiguration until dial.
		if realm != nil && realm.IncludeNative {
			for i := range cfg.Networks {
				if cfg.Networks[i].Kind == NetworkNativeI2P {
					r.fabricNames[cfg.Networks[i].Name] = overlay.NativeI2PFabricID
					break
				}
			}
			r.fabricNames[networkNativeName] = overlay.NativeI2PFabricID
		}
	}
	return r, nil
}

func (r *Router) Hash() Hash { return r.core.Hash() }

// DefaultNetwork returns the default network name configured or resolved for the router
// ("i2p", an IVNP fabric name, or "ivnp").
func (r *Router) DefaultNetwork() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.defaultNetwork
}

// Overlay returns the composed overlay host for direct domain access, or nil
// when RouterConfig.Realm was not set.
func (r *Router) Overlay() *OverlayHost {
	if r == nil || r.overlay == nil {
		return nil
	}
	return r.overlay.Host()
}

func (r *Router) claimOverlayPort(port uint16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	if r.overlayPorts == nil {
		r.overlayPorts = make(map[uint16]struct{})
	}
	if _, inUse := r.overlayPorts[port]; inUse {
		return ErrAddressInUse
	}
	r.overlayPorts[port] = struct{}{}
	return nil
}

func (r *Router) releaseOverlayPort(port uint16) {
	if port == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.overlayPorts != nil {
		delete(r.overlayPorts, port)
	}
}

func (r *Router) allocateEphemeralOverlayPort() (uint16, error) {
	const (
		ephemeralMin = 49152
		ephemeralMax = 65535
		span         = ephemeralMax - ephemeralMin + 1
	)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, net.ErrClosed
	}
	if r.overlayPorts == nil {
		r.overlayPorts = make(map[uint16]struct{})
	}
	offset := rand.N(uint32(span))
	for i := uint32(0); i < span; i++ {
		candidate := uint16(ephemeralMin + (offset+i)%span)
		if _, inUse := r.overlayPorts[candidate]; !inUse {
			r.overlayPorts[candidate] = struct{}{}
			return candidate, nil
		}
	}
	return 0, ErrResourceLimit
}

// OverlayRealm returns the composed realm, or nil when no realm is configured.
func (r *Router) OverlayRealm() *OverlayRealm {
	if r == nil || r.overlay == nil {
		return nil
	}
	return r.overlay.Realm()
}

// RegisterTransport registers a custom TransportProvider on the running router.
func (r *Router) RegisterTransport(t TransportProvider) error {
	return r.RegisterProvider(t)
}

// RegisterProvider registers an overlay provider (e.g. TransportProvider,
// CredentialVerifier, IdentityProvider, TrustProvider) on the running router.
func (r *Router) RegisterProvider(p any) error {
	if r == nil {
		return net.ErrClosed
	}
	r.mu.Lock()
	closed := r.closed
	bridge := r.overlay
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if bridge == nil {
		return &ConfigError{Field: "Overlay", Err: ErrOverlayRequired}
	}
	return bridge.RegisterProvider(p)
}

// resolveNetworkNames maps destination network names to fabric identities.
// An empty selection admits every realm-bound fabric; a name resolving to a
// fabric the realm did not bind fails here rather than at dial time.
func (r *Router) resolveNetworkNames(names []string) (map[FabricID]struct{}, error) {
	if len(names) == 0 {
		return nil, nil
	}
	bound := make(map[FabricID]struct{}, len(r.realmFabrics))
	for _, id := range r.realmFabrics {
		bound[id] = struct{}{}
	}
	out := make(map[FabricID]struct{}, len(names))
	for _, name := range names {
		id, ok := r.fabricNames[name]
		if !ok {
			return nil, &ConfigError{Field: "Networks", Err: ErrInvalidConfig}
		}
		if _, ok := bound[id]; !ok {
			return nil, &ConfigError{Field: "Networks", Err: ErrInvalidConfig}
		}
		out[id] = struct{}{}
	}
	return out, nil
}

func (r *Router) WaitReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return r.core.WaitReady(ctx)
}

// NewDestination owns its cloned keys until Close. Successful construction
// observes a usable tunnel pair and confirmed publication, not permanent reachability.
func (r *Router) NewDestination(ctx context.Context, cfg DestinationConfig) (*Destination, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	r.creating.Add(1)
	r.mu.Unlock()
	defer r.creating.Done()

	// An overlay service needs the destination's signing key for its contact
	// identity; a nil identity is generated here and owned by the Destination.
	// The generated identity is the legacy ElGamal/Ed25519 shape the I2P
	// streaming layer requires.
	var generated *foundation.LocalDestination
	if cfg.Overlay != nil && len(cfg.Networks) == 0 && len(cfg.Overlay.Networks) > 0 {
		cfg.Networks = append([]string(nil), cfg.Overlay.Networks...)
	}
	if len(cfg.Networks) > 0 && cfg.Overlay == nil {
		return nil, &ConfigError{Field: "Networks", Err: ErrInvalidConfig}
	}
	if cfg.Overlay != nil {
		if r.overlay == nil {
			return nil, &ConfigError{Field: "Overlay", Err: ErrOverlayRequired}
		}
		if cfg.Identity == nil {
			generated, err := foundation.GenerateLegacyLocalDestination()
			if err != nil {
				return nil, err
			}
			cfg.Identity = generated
		}
	}
	defer func() {
		if generated != nil {
			generated.ReleaseSensitive()
		}
	}()

	spec, err := destinationSpec(cfg)
	if err != nil {
		return nil, err
	}
	defer wipeDestinationSpec(&spec)
	if cfg.PacketQueue.MaxBytes > r.packetQueueLimit {
		return nil, &ConfigError{Field: "PacketQueue.MaxBytes", Err: ErrInvalidConfig}
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	endpoint, err := r.core.NewDestination(setup, spec)
	if err != nil {
		if r.ctx.Err() != nil {
			return nil, errors.Join(net.ErrClosed, err)
		}
		switch {
		case errors.Is(err, controlplane.ErrTooManyDestinations):
			err = errors.Join(ErrResourceLimit, err)
		case errors.Is(err, dataplane.RouterErrDestinationExists), errors.Is(err, controlplane.ErrDuplicateDestination):
			err = errors.Join(ErrIdentityInUse, err)
		}
		return nil, err
	}
	if err = setup.Err(); err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	var svc *overlay.Service
	var fabrics map[FabricID]struct{}
	var overlaySpec *overlay.ServiceSpec
	var activePort uint16
	if cfg.Overlay != nil {
		if fabrics, err = r.resolveNetworkNames(cfg.Networks); err != nil {
			return nil, errors.Join(err, endpoint.Close())
		}
		identity, err := cfg.Identity.Identity()
		if err != nil {
			return nil, errors.Join(err, endpoint.Close())
		}
		protocols := cfg.Overlay.Protocols
		if len(protocols) == 0 {
			protocols = []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream}
		}
		svcSpec := overlay.ServiceSpec{
			Destination: identity.Bytes(), Port: cfg.Overlay.Port,
			Protocols: protocols, Publication: cfg.Overlay.Publication,
			Privacy:      orPrivacy(cfg.Overlay.Privacy, r.realmPrivacy),
			Routing:      orRouting(cfg.Overlay.Routing, r.realmRouting),
			DualPresence: cfg.Overlay.DualPresence, PublicationFloor: cfg.Overlay.Floor,
		}
		overlaySpec = &svcSpec
		if cfg.Overlay.Port != 0 {
			if err = r.claimOverlayPort(cfg.Overlay.Port); err != nil {
				return nil, errors.Join(err, endpoint.Close())
			}
			activePort = cfg.Overlay.Port
			if svc, err = r.overlay.OpenService(svcSpec, cfg.Identity); err != nil {
				r.releaseOverlayPort(activePort)
				return nil, errors.Join(err, endpoint.Close())
			}
		}
	}
	lifetime, release := context.WithCancel(r.ctx)
	d := &Destination{
		endpoint: endpoint, owner: r, ctx: lifetime, cancel: release,
		hash: endpoint.Hash(), b32: endpoint.B32(), public: endpoint.Destination(),
		packetQueue: cfg.PacketQueue, resources: make(map[io.Closer]struct{}),
		service: svc, fabrics: fabrics, ownedIdentity: generated,
		overlaySpec: overlaySpec, overlayIdent: cfg.Identity, activePort: activePort,
	}
	generated = nil
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, d.Close())
	}
	r.children[d] = struct{}{}
	r.mu.Unlock()
	return d, nil
}

// NewOverlayDestination creates a Destination configured with an overlay service
// on the given networks. The service logical port is bound dynamically when
// Listen is called (or an ephemeral port is assigned if ":0" is requested).
// If networks is empty, all realm-bound networks are permitted.
func (r *Router) NewOverlayDestination(ctx context.Context, networks ...string) (*Destination, error) {
	return r.NewOverlayDestinationWithPort(ctx, 0, networks...)
}

// NewOverlayDestinationWithPort creates a Destination pre-configured with a specific
// fixed overlay port.
func (r *Router) NewOverlayDestinationWithPort(ctx context.Context, port uint16, networks ...string) (*Destination, error) {
	cfg := DefaultDestinationConfig()
	cfg.Networks = append([]string(nil), networks...)
	cfg.Overlay = &ServiceProfile{
		Port:         port,
		Protocols:    []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream},
		Publication:  PublicationLS2,
		DualPresence: true,
	}
	return r.NewDestination(ctx, cfg)
}

func (r *Router) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		children := make([]*Destination, 0, len(r.children))
		for child := range r.children {
			children = append(children, child)
		}
		r.mu.Unlock()
		for _, child := range children {
			r.closeErr = errors.Join(r.closeErr, child.Close())
		}
		r.creating.Wait()
		r.closeErr = errors.Join(r.closeErr, r.core.Close())
	})
	return r.closeErr
}

// Destination identifies one application and owns all its network resources.
// Public identity snapshots remain available after Close. Do not copy a Destination.
type Destination struct {
	endpoint    destination.DestinationEndpoint
	owner       *Router
	ctx         context.Context
	cancel      context.CancelFunc
	hash        Hash
	b32         string
	public      []byte
	packetQueue PacketQueueConfig
	// service is the destination's overlay service; fabrics bounds its
	// allowed networks; ownedIdentity is the facade-generated identity
	// released at Close.
	service       *overlay.Service
	fabrics       map[FabricID]struct{}
	ownedIdentity *foundation.LocalDestination
	overlaySpec   *overlay.ServiceSpec
	overlayIdent  *foundation.LocalDestination
	activePort    uint16
	mu            sync.Mutex
	closed        bool
	resources     map[io.Closer]struct{}
	operations    sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
}

func (d *Destination) Hash() Hash { return d.hash }

// B32 is the service hostname without a port, URL scheme, or path.
func (d *Destination) B32() string { return d.b32 }

// Destination returns an independent copy of the I2P-base64 public identity.
func (d *Destination) Destination() []byte { return append([]byte(nil), d.public...) }

func (d *Destination) checkOpen() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return net.ErrClosed
	}
	return nil
}

func (d *Destination) beginOperation() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return net.ErrClosed
	}
	d.operations.Add(1)
	return nil
}

func (d *Destination) endOperation() { d.operations.Done() }

func (d *Destination) registerResource(resource io.Closer) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return net.ErrClosed
	}
	d.resources[resource] = struct{}{}
	return nil
}

func (d *Destination) unregisterResource(resource io.Closer) {
	d.mu.Lock()
	delete(d.resources, resource)
	d.mu.Unlock()
}

// EndpointID returns the destination's 32-byte overlay endpoint identity.
func (d *Destination) EndpointID() EndpointID {
	if d == nil {
		return EndpointID{}
	}
	return EndpointID(d.hash)
}

// OverlayService returns the destination's realm service, or nil when
// DestinationConfig.Overlay was not set or has not yet bound a service.
func (d *Destination) OverlayService() *OverlayService {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.service
}

func (d *Destination) ensureOverlayService(port uint16, allocateEphemeral bool) (*overlay.Service, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if d.service != nil {
		if port != 0 && d.service.Port() != port {
			return nil, ErrAddressInvalid
		}
		return d.service, nil
	}
	if d.overlaySpec == nil {
		return nil, ErrOverlayRequired
	}
	targetPort := port
	claimed := false
	if targetPort == 0 {
		if d.overlaySpec.Port != 0 {
			targetPort = d.overlaySpec.Port
		} else if allocateEphemeral || d.overlaySpec.DualPresence || d.overlaySpec.Publication == PublicationLS2 || d.overlaySpec.Publication == PublicationEncryptedLS2 {
			p, err := d.owner.allocateEphemeralOverlayPort()
			if err != nil {
				return nil, err
			}
			targetPort = p
			claimed = true
		}
	} else if d.overlaySpec.Port != 0 && d.overlaySpec.Port != targetPort {
		return nil, ErrAddressInvalid
	}
	if !claimed && targetPort != 0 {
		if err := d.owner.claimOverlayPort(targetPort); err != nil {
			return nil, err
		}
		claimed = true
	}
	spec := *d.overlaySpec
	spec.Port = targetPort
	svc, err := d.owner.overlay.OpenService(spec, d.overlayIdent)
	if err != nil {
		if claimed {
			d.owner.releaseOverlayPort(targetPort)
		}
		return nil, err
	}
	d.service = svc
	d.activePort = targetPort
	return svc, nil
}

// DialOverlay opens a realm connection to target. policy left empty selects
// the destination's allowed networks — DestinationConfig.Networks, or
// every realm-bound fabric when unset — and a non-empty set is intersected
// with them, so a destination restricted to a private fabric can never fall
// back to public I2P. Zero policy fields select neutral defaults:
// RouteClasses and EndpointProtocols admit everything the service allows,
// Privacy adds no constraint beyond the realm's, Fallback prefers IVNP, and
// Failover reconnects rather than resuming.
func (d *Destination) DialOverlay(ctx context.Context, target OverlayTarget, policy ...OverlayDialPolicy) (*OverlayConnection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.beginOperation(); err != nil {
		return nil, err
	}
	defer d.endOperation()
	svc, err := d.ensureOverlayService(0, false)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "overlay", Err: err}
	}
	var p OverlayDialPolicy
	if len(policy) > 0 {
		p = policy[0]
	}
	p.Fabrics = d.allowedFabrics(p.Fabrics)
	if len(p.Fabrics) == 0 {
		return nil, &net.OpError{Op: "dial", Net: "overlay", Err: ErrInvalidConfig}
	}
	if len(p.RouteClasses) == 0 {
		p.RouteClasses = []RouteClass{RouteNativeI2P, RouteDirect, RouteRouted}
	}
	if len(p.EndpointProtocols) == 0 {
		p.EndpointProtocols = []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream}
	}
	if p.Privacy == 0 {
		p.Privacy = PrivacyExplicitDirect
	}
	if p.Fallback == 0 {
		p.Fallback = ProtocolIVNPPreferred
	}
	if p.Failover == 0 {
		p.Failover = FailoverReconnect
	}
	conn, err := svc.Dial(ctx, target, p)
	if err != nil && d.ctx.Err() != nil {
		return nil, errors.Join(net.ErrClosed, err)
	}
	return conn, err
}

// DialOverlayWithPolicy opens a realm connection to target with explicit policy.
func (d *Destination) DialOverlayWithPolicy(ctx context.Context, target OverlayTarget, policy OverlayDialPolicy) (*OverlayConnection, error) {
	return d.DialOverlay(ctx, target, policy)
}

// DialOverlayTarget opens a realm connection to target with default neutral policies.
func (d *Destination) DialOverlayTarget(ctx context.Context, target OverlayTarget) (*OverlayConnection, error) {
	return d.DialOverlay(ctx, target)
}

// DialOverlayAddr opens a realm connection to an address string with default neutral policies.
func (d *Destination) DialOverlayAddr(ctx context.Context, address string) (*OverlayConnection, error) {
	target, err := ParseOverlayTarget(address)
	if err != nil {
		return nil, err
	}
	return d.DialOverlay(ctx, target)
}

// ListenOverlay opens the service's bounded inbound queue under policy using context.Background.
func (d *Destination) ListenOverlay(policy OverlayListenPolicy) (*OverlayListener, error) {
	return d.ListenOverlayContext(context.Background(), policy)
}

// ListenOverlayContext opens the service's bounded inbound queue under policy. Zero
// fields select neutral defaults — the service's full protocol set, every
// route class the realm routing admits, and no privacy constraint beyond the
// service's own.
func (d *Destination) ListenOverlayContext(ctx context.Context, policy OverlayListenPolicy) (*OverlayListener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.beginOperation(); err != nil {
		return nil, err
	}
	defer d.endOperation()
	svc, err := d.ensureOverlayService(0, true)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: "overlay", Err: err}
	}
	if len(policy.Protocols) == 0 {
		policy.Protocols = []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream}
	}
	if len(policy.Classes) == 0 {
		policy.Classes = []RouteClass{RouteNativeI2P, RouteDirect, RouteRouted}
	}
	if policy.Privacy == 0 {
		policy.Privacy = PrivacyExplicitDirect
	}
	return svc.Listen(policy)
}

// allowedFabrics intersects a caller's requested fabric set with the
// destination's configured networks. A nil destination set means every
// realm-bound fabric.
func (d *Destination) allowedFabrics(request []FabricID) []FabricID {
	var allowed map[FabricID]struct{}
	if d.fabrics != nil {
		allowed = d.fabrics
	} else {
		allowed = make(map[FabricID]struct{}, len(d.owner.realmFabrics))
		for _, id := range d.owner.realmFabrics {
			allowed[id] = struct{}{}
		}
	}
	if len(request) == 0 {
		out := make([]FabricID, 0, len(allowed))
		for id := range allowed {
			out = append(out, id)
		}
		return out
	}
	out := make([]FabricID, 0, len(request))
	for _, id := range request {
		if _, ok := allowed[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

func orPrivacy(v, fallback PrivacyClass) PrivacyClass {
	if v == 0 {
		return fallback
	}
	return v
}

func orRouting(v, fallback DataRouting) DataRouting {
	if v == 0 {
		return fallback
	}
	return v
}

func (d *Destination) WaitReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.beginOperation(); err != nil {
		return err
	}
	defer d.endOperation()
	ready, ok := d.endpoint.(destination.ReadyDestinationEndpoint)
	if !ok {
		return ErrUnsupportedIdentity
	}
	waitCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	err := ready.WaitReady(waitCtx)
	if d.ctx.Err() != nil {
		return errors.Join(net.ErrClosed, err)
	}
	return err
}

func (d *Destination) ResolveAddr(ctx context.Context, address string) (Addr, error) {
	if err := ctx.Err(); err != nil {
		return Addr{}, err
	}
	if err := d.beginOperation(); err != nil {
		return Addr{}, err
	}
	defer d.endOperation()
	lookup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	addr, err := resolveAddr(lookup, d.owner.resolver, address)
	if d.ctx.Err() != nil {
		return Addr{}, errors.Join(net.ErrClosed, err)
	}
	return addr, err
}

func (d *Destination) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.cancel()
		resources := make([]io.Closer, 0, len(d.resources))
		for resource := range d.resources {
			resources = append(resources, resource)
		}
		d.mu.Unlock()
		for _, resource := range resources {
			d.closeErr = errors.Join(d.closeErr, resource.Close())
		}
		// The overlay service closes before the native endpoint: inbound
		// fabric channels stop first, then the I2P destination tears down.
		if d.service != nil {
			d.closeErr = errors.Join(d.closeErr, d.service.Close())
		}
		if d.activePort != 0 {
			d.owner.releaseOverlayPort(d.activePort)
		}
		d.closeErr = errors.Join(d.closeErr, d.endpoint.Close())
		d.operations.Wait()
		if d.ownedIdentity != nil {
			d.ownedIdentity.ReleaseSensitive()
		}
		d.owner.mu.Lock()
		delete(d.owner.children, d)
		d.owner.mu.Unlock()
	})
	return d.closeErr
}
