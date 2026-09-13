package node

import (
	"context"
	"errors"
	"net"
	"sync"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node/internal/overlaybridge"
	"gosuda.org/ivnp/state"
)

var errDestinationReadinessCapability = errors.New("node: destination has no readiness capability")

// EmbeddedRouter owns transports and control-plane workers without daemon services.
// Close cancels all children and joins every owned worker.
type EmbeddedRouter struct {
	controller *controlplane.Controller
	bridge     *overlaybridge.Bridge
	cancel     context.CancelFunc
	once       sync.Once
	closeErr   error
}

// NewEmbeddedRouter uses ctx only during construction. Persistent state is opt-in
// through StatePath and KeyPath; an empty pair selects memory-only storage.
func NewEmbeddedRouter(ctx context.Context, cfg state.ConfigurationOperating, options controlplane.ControllerOptions) (*EmbeddedRouter, error) {
	return newEmbeddedRouter(ctx, cfg, options, nil)
}

// NewEmbeddedRouterWithOverlay additionally composes the overlay bridge: the
// native controller becomes the netId=2 context and each configured fabric
// gets its own listeners and peer table. A nil spec is the plain constructor.
func NewEmbeddedRouterWithOverlay(ctx context.Context, cfg state.ConfigurationOperating, options controlplane.ControllerOptions, spec *overlaybridge.Spec) (*EmbeddedRouter, error) {
	return newEmbeddedRouter(ctx, cfg, options, spec)
}

func newEmbeddedRouter(ctx context.Context, cfg state.ConfigurationOperating, options controlplane.ControllerOptions, spec *overlaybridge.Spec) (*EmbeddedRouter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options.Embedded = true
	controller, err := controlplane.NewController(cfg, options)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	router := &EmbeddedRouter{controller: controller, cancel: cancel}
	stop := context.AfterFunc(ctx, cancel)
	err = controller.Start(lifetime)
	stopped := stop()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil || !stopped {
		if err == nil {
			err = context.Canceled
		}
		return nil, errors.Join(err, router.Close())
	}
	if spec != nil {
		bridge, err := overlaybridge.Open(ctx, *spec, controller)
		if err != nil {
			return nil, errors.Join(err, router.Close())
		}
		router.bridge = bridge
	}
	return router, nil
}

func (r *EmbeddedRouter) Hash() foundation.Hash {
	if r == nil {
		return foundation.Hash{}
	}
	return r.controller.Hash()
}

// Overlay returns the composed overlay bridge, or nil when the router was
// built without an overlay spec.
func (r *EmbeddedRouter) Overlay() *overlaybridge.Bridge {
	if r == nil {
		return nil
	}
	return r.bridge
}

func (r *EmbeddedRouter) WaitReady(ctx context.Context) error {
	if r == nil {
		return net.ErrClosed
	}
	return r.controller.WaitReady(ctx)
}

// NewDestination returns only after its own tunnels and confirmed publication
// are ready. Cancellation closes the partial destination before returning.
func (r *EmbeddedRouter) NewDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
	if r == nil {
		return nil, net.ErrClosed
	}
	endpoint, err := r.controller.DestinationController().CreateDestination(ctx, spec)
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
		// The bridge closes first: its listeners stop accepting before the
		// controller tears down the native context they may carry evidence for.
		var bridgeErr error
		if r.bridge != nil {
			bridgeErr = r.bridge.Close()
		}
		r.closeErr = errors.Join(bridgeErr, r.controller.Close(), r.controller.Wait())
	})
	return r.closeErr
}
