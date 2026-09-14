package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/state"
)

var (
	errDestinationReadinessCapability = errors.New("node: destination has no readiness capability")
	errNetworkSpecRequired            = errors.New("node: at least one network spec is required")
)

// NetworkSpec describes one I2P protocol context the router runs: an operating
// configuration scoped to a netId plus that context's controller options. Every
// context is an independent I2P network — public or dedicated — with its own
// transports, NetDB, and tunnel pools.
type NetworkSpec struct {
	Name      string
	Operating state.ConfigurationOperating
	Options   controlplane.ControllerOptions
}

// EmbeddedRouter owns transports and control-plane workers without daemon
// services. It runs one control-plane context per network spec; each context
// has an isolated NetDB scoped to its netId. Close cancels all children and
// joins every owned worker.
type EmbeddedRouter struct {
	contexts map[string]*controlplane.Controller
	order    []string
	def      string
	cancel   context.CancelFunc
	once     sync.Once
	closeErr error
}

// NewEmbeddedRouter uses ctx only during construction. Persistent state is opt-in
// through StatePath and KeyPath; an empty pair selects memory-only storage.
func NewEmbeddedRouter(ctx context.Context, cfg state.ConfigurationOperating, options controlplane.ControllerOptions) (*EmbeddedRouter, error) {
	return NewEmbeddedRouterNetworks(ctx, []NetworkSpec{{Name: "i2p", Operating: cfg, Options: options}})
}

// NewEmbeddedRouterNetworks composes one control-plane context per spec. Every
// context is a complete I2P protocol instance; the public network is simply a
// context with netId 2 and the standard transports and reseeders.
func NewEmbeddedRouterNetworks(ctx context.Context, specs []NetworkSpec) (*EmbeddedRouter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, errNetworkSpecRequired
	}
	lifetime, cancel := context.WithCancel(context.Background())
	router := &EmbeddedRouter{
		contexts: make(map[string]*controlplane.Controller, len(specs)),
		order:    make([]string, 0, len(specs)),
		def:      specs[0].Name,
		cancel:   cancel,
	}
	stop := context.AfterFunc(ctx, cancel)
	for _, spec := range specs {
		if spec.Name == "" {
			return nil, errors.Join(errors.New("node: network spec name is required"), router.Close())
		}
		if _, dup := router.contexts[spec.Name]; dup {
			return nil, errors.Join(fmt.Errorf("node: duplicate network name %q", spec.Name), router.Close())
		}
		options := spec.Options
		options.Embedded = true
		controller, err := controlplane.NewController(spec.Operating, options)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("node: network %q: %w", spec.Name, err), router.Close())
		}
		router.contexts[spec.Name] = controller
		router.order = append(router.order, spec.Name)
		if err = controller.Start(lifetime); err != nil {
			return nil, errors.Join(fmt.Errorf("node: network %q: %w", spec.Name, err), router.Close())
		}
	}
	stopped := stop()
	if err := ctx.Err(); err != nil || !stopped {
		if err == nil {
			err = context.Canceled
		}
		return nil, errors.Join(err, router.Close())
	}
	return router, nil
}

// Context returns the control-plane controller serving the named network, or
// nil when the router has no such context.
func (r *EmbeddedRouter) Context(name string) *controlplane.Controller {
	if r == nil {
		return nil
	}
	return r.contexts[name]
}

// Default returns the control-plane controller for the first configured
// network — the unqualified-dial target.
func (r *EmbeddedRouter) Default() *controlplane.Controller {
	if r == nil {
		return nil
	}
	return r.contexts[r.def]
}

// Networks returns the configured network names in spec order.
func (r *EmbeddedRouter) Networks() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

func (r *EmbeddedRouter) Hash() foundation.Hash {
	if r == nil {
		return foundation.Hash{}
	}
	return r.Default().Hash()
}

// ExportLocalRouterInfo returns a snapshot copy of this router's signed RouterInfo
// wire bytes on the named network context. Empty selects the default network.
func (r *EmbeddedRouter) ExportLocalRouterInfo(network string) ([]byte, error) {
	if r == nil {
		return nil, net.ErrClosed
	}
	c := r.Default()
	if network != "" {
		c = r.contexts[network]
	}
	if c == nil {
		return nil, fmt.Errorf("node: unknown network %q", network)
	}
	return c.ExportLocalRouterInfo()
}

// ExportPeerRouterInfo returns a copy of the named peer's signed RouterInfo wire
// bytes from the specified network's NetDB, if known.
func (r *EmbeddedRouter) ExportPeerRouterInfo(network string, peer foundation.Hash) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	c := r.Default()
	if network != "" {
		c = r.contexts[network]
	}
	if c == nil {
		return nil, false
	}
	return c.ExportPeerRouterInfo(peer)
}

// ImportRouterInfo validates, verifies, and installs one signed RouterInfo wire
// record into the named network context's NetDB.
func (r *EmbeddedRouter) ImportRouterInfo(ctx context.Context, network string, wire []byte) (foundation.Hash, error) {
	if r == nil {
		return foundation.Hash{}, net.ErrClosed
	}
	c := r.Default()
	if network != "" {
		c = r.contexts[network]
	}
	if c == nil {
		return foundation.Hash{}, fmt.Errorf("node: unknown network %q", network)
	}
	return c.ImportRouterInfo(ctx, wire)
}

func (r *EmbeddedRouter) WaitReady(ctx context.Context) error {
	if r == nil {
		return net.ErrClosed
	}
	return r.Default().WaitReady(ctx)
}

// NewDestination creates a destination on the default network. See
// NewDestinationOn.
func (r *EmbeddedRouter) NewDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	return r.NewDestinationOn(ctx, "", spec)
}

// NewDestinationOn creates a destination on the named network — an empty name
// selects the default. It returns only after the destination's tunnels and
// confirmed publication are ready on that network. Cancellation closes the
// partial destination before returning.
func (r *EmbeddedRouter) NewDestinationOn(ctx context.Context, network string, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	if r == nil {
		return nil, net.ErrClosed
	}
	controller := r.Default()
	if network != "" {
		controller = r.contexts[network]
	}
	if controller == nil {
		return nil, fmt.Errorf("node: unknown network %q", network)
	}
	endpoint, err := controller.DestinationController().CreateDestination(ctx, spec)
	if err != nil {
		return nil, err
	}
	ready, ok := endpoint.(destination.ReadyDestinationEndpoint)
	if !ok {
		return nil, errors.Join(errDestinationReadinessCapability, endpoint.Close())
	}
	if err = ready.WaitReady(ctx); err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, endpoint.Close())
	}
	return endpoint, nil
}

func (r *EmbeddedRouter) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.cancel()
		for _, name := range r.order {
			controller := r.contexts[name]
			r.closeErr = errors.Join(r.closeErr, controller.Close(), controller.Wait())
		}
	})
	return r.closeErr
}
