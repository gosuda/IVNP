// Package ivnp embeds an in-memory-by-default I2P router and destination-owned
// stream and datagram sockets. Router construction never creates a service identity.
package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node"
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
	settings, options, err := routerSettings(cfg)
	if err != nil {
		return nil, err
	}
	return newRouter(ctx, cfg, settings, options)
}

// newRouter keeps host transport injection at the composition boundary for
// deterministic embedding scenarios without exporting daemon options.
func newRouter(ctx context.Context, cfg RouterConfig, settings state.ConfigurationOperating, options controlplane.ControllerOptions) (*Router, error) {
	core, err := node.NewEmbeddedRouter(ctx, settings, options)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, core.Close())
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Router{
		core: core, resolver: cfg.Resolver,
		packetBudget:     newPacketBudget(cfg.Limits.PacketQueueBytes),
		packetWrites:     make(chan struct{}, cfg.Limits.MaxPendingPacketWrites),
		packetQueueLimit: cfg.Limits.PacketQueueBytes,
		ctx:              lifetime, cancel: cancel, children: make(map[*Destination]struct{}),
	}, nil
}

func (r *Router) Hash() Hash { return r.core.Hash() }

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
	lifetime, release := context.WithCancel(r.ctx)
	d := &Destination{
		endpoint: endpoint, owner: r, ctx: lifetime, cancel: release,
		hash: endpoint.Hash(), b32: endpoint.B32(), public: endpoint.Destination(),
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
	mu          sync.Mutex
	closed      bool
	resources   map[io.Closer]struct{}
	operations  sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
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
		d.closeErr = errors.Join(d.closeErr, d.endpoint.Close())
		d.operations.Wait()
		d.owner.mu.Lock()
		delete(d.owner.children, d)
		d.owner.mu.Unlock()
	})
	return d.closeErr
}
