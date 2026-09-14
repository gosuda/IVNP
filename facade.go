// Package ivnp embeds an in-memory-by-default I2P router and destination-owned
// stream and datagram sockets. Router construction never creates a service
// identity. RouterConfig.Networks runs one independent I2P protocol context
// per entry — the official netId=2 network and any dedicated networks — and a
// Destination bound to several networks is reachable under one address on all
// of them.
package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node"
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
	networkNames     map[string]struct{}
	packetBudget     destination.ByteBudget
	packetWrites     chan struct{}
	packetQueueLimit int64
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.Mutex
	closed           bool
	children         map[*Destination]struct{}
	creating         sync.WaitGroup
	closeOnce        sync.Once
	closeErr         error
}

// NewRouter starts local infrastructure. It does not wait for tunnel readiness.
// The context bounds construction only. Nil Persistence keeps owned state in memory.
func NewRouter(ctx context.Context, cfg RouterConfig) (*Router, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	specs, def, err := networkSpecs(cfg)
	if err != nil {
		return nil, err
	}
	return newRouter(ctx, cfg, specs, def)
}

// newRouter keeps host transport injection at the composition boundary for
// deterministic embedding scenarios without exporting daemon options.
func newRouter(ctx context.Context, cfg RouterConfig, specs []node.NetworkSpec, def string) (*Router, error) {
	core, err := node.NewEmbeddedRouterNetworks(ctx, specs)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, core.Close())
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Router{
		core: core, resolver: cfg.Resolver,
		defaultNetwork:   def,
		networkNames:     contextNames(specs),
		packetBudget:     newPacketBudget(cfg.Limits.PacketQueueBytes),
		packetWrites:     make(chan struct{}, cfg.Limits.MaxPendingPacketWrites),
		packetQueueLimit: cfg.Limits.PacketQueueBytes,
		ctx:              lifetime, cancel: cancel, children: make(map[*Destination]struct{}),
	}, nil
}

func contextNames(specs []node.NetworkSpec) map[string]struct{} {
	names := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		names[spec.Name] = struct{}{}
	}
	return names
}

func (r *Router) Hash() Hash { return r.core.Hash() }

// DefaultNetwork returns the network name serving unqualified operations —
// the configured DefaultNetwork, the netId=2 entry, or the first entry.
func (r *Router) DefaultNetwork() string {
	if r == nil {
		return ""
	}
	return r.defaultNetwork
}

// Networks returns the router's network names in configuration order.
func (r *Router) Networks() []string {
	if r == nil {
		return nil
	}
	return r.core.Networks()
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
// observes a usable tunnel pair and confirmed publication on every bound
// network, not permanent reachability.
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

	nets := cfg.Networks
	if len(nets) == 0 {
		nets = []string{r.defaultNetwork}
	}
	seen := make(map[string]struct{}, len(nets))
	for i, name := range nets {
		if _, dup := seen[name]; dup {
			return nil, &ConfigError{Field: "Networks[" + strconv.Itoa(i) + "]", Err: ErrInvalidConfig}
		}
		seen[name] = struct{}{}
		if _, known := r.networkNames[name]; !known {
			return nil, &ConfigError{Field: "Networks[" + strconv.Itoa(i) + "]", Err: ErrInvalidConfig}
		}
	}
	spec, err := destinationSpec(cfg)
	if err != nil {
		return nil, err
	}
	defer wipeDestinationSpec(&spec)
	if spec.Local == nil {
		// One identity must be shared by every bound network — letting each
		// context generate its own would give the destination a different
		// address per network.
		var generated *foundation.LocalDestination
		if spec.Policy.Encrypted {
			generated, err = foundation.GenerateEncryptedLocalDestination()
		} else {
			generated, err = foundation.GenerateLegacyLocalDestination()
		}
		if err != nil {
			return nil, err
		}
		defer generated.ReleaseSensitive()
		spec.Local = generated
	}
	if cfg.PacketQueue.MaxBytes > r.packetQueueLimit {
		return nil, &ConfigError{Field: "PacketQueue.MaxBytes", Err: ErrInvalidConfig}
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	endpoints := make(map[string]destination.DestinationEndpoint, len(nets))
	for _, name := range nets {
		endpoint, err := r.core.NewDestinationOn(setup, name, spec)
		if err == nil {
			err = setup.Err()
		}
		if err != nil {
			for _, bound := range endpoints {
				err = errors.Join(err, bound.Close())
			}
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
		endpoints[name] = endpoint
	}
	first := endpoints[nets[0]]
	lifetime, release := context.WithCancel(r.ctx)
	d := &Destination{
		endpoints: endpoints, nets: append([]string(nil), nets...), owner: r,
		ctx: lifetime, cancel: release,
		hash: first.Hash(), b32: first.B32(), public: first.Destination(),
		dialPolicy:  cfg.DialPolicy,
		packetQueue: cfg.PacketQueue, resources: make(map[io.Closer]struct{}),
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, d.Close())
	}
	r.children[d] = struct{}{}
	r.mu.Unlock()
	return d, nil
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

// Destination identifies one application and owns all its network resources:
// one endpoint per bound network, all carrying the same identity. Public
// identity snapshots remain available after Close. Do not copy a Destination.
type Destination struct {
	endpoints   map[string]destination.DestinationEndpoint
	nets        []string
	owner       *Router
	ctx         context.Context
	cancel      context.CancelFunc
	hash        Hash
	b32         string
	public      []byte
	dialPolicy  DialPolicy
	packetQueue PacketQueueConfig
	mu          sync.Mutex
	closed      bool
	resources   map[io.Closer]struct{}
	operations  sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

func (d *Destination) Hash() Hash { return d.hash }

// B32 is the service hostname without a port, URL scheme, or path. The same
// address reaches this destination on every bound network.
func (d *Destination) B32() string { return d.b32 }

// Destination returns an independent copy of the I2P-base64 public identity.
func (d *Destination) Destination() []byte { return append([]byte(nil), d.public...) }

// Networks returns the destination's bound network names in preference order —
// the order unqualified dials race them in.
func (d *Destination) Networks() []string {
	if d == nil {
		return nil
	}
	return append([]string(nil), d.nets...)
}

// primaryEndpoint returns the endpoint serving unqualified single-network
// operations: the router default when bound, else the first bound network.
func (d *Destination) primaryEndpoint() destination.DestinationEndpoint {
	if ep := d.endpoints[d.owner.defaultNetwork]; ep != nil {
		return ep
	}
	return d.endpoints[d.nets[0]]
}

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

func (d *Destination) WaitReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.beginOperation(); err != nil {
		return err
	}
	defer d.endOperation()
	waitCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	for _, name := range d.nets {
		ready, ok := d.endpoints[name].(destination.ReadyDestinationEndpoint)
		if !ok {
			return ErrUnsupportedIdentity
		}
		if err := ready.WaitReady(waitCtx); err != nil {
			if d.ctx.Err() != nil {
				return errors.Join(net.ErrClosed, err)
			}
			return err
		}
	}
	return nil
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
		for _, name := range d.nets {
			d.closeErr = errors.Join(d.closeErr, d.endpoints[name].Close())
		}
		d.operations.Wait()
		d.owner.mu.Lock()
		delete(d.owner.children, d)
		d.owner.mu.Unlock()
	})
	return d.closeErr
}
