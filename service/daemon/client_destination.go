package daemon

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/network/router"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/datagram"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/support/state"
	"net"
	"time"
)

var errDestinationCryptoTypes = errors.New("daemon: unsupported destination crypto type order")

// clientDestinationController is the neutral local-client boundary. It creates
// transient graphs with the same factory used by durable daemon Destinations;
// there is no SAM-specific pool or parallel destination owner.
type clientDestinationController struct{ daemon *Daemon }

// DestinationController returns the neutral dynamic-destination boundary used
// by embedded client protocols. Persistent catalog mutation remains available
// through Daemon.CreateDestination and Daemon.DestroyDestination.
func (d *Daemon) DestinationController() clientapi.DestinationController {
	return clientDestinationController{daemon: d}
}

func (c clientDestinationController) CreateDestination(ctx context.Context, spec clientapi.DestinationSpec) (clientapi.DestinationEndpoint, error) {
	d := c.daemon
	if d == nil || d.destinationFactory == nil || d.destinations == nil {
		return nil, ErrDestinationCreation
	}
	if ctx ==
		nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seenCrypto := make(map[uint16]bool, len(spec.Policy.CryptoTypes))
	for _, cryptoType := range spec.Policy.CryptoTypes {
		createDestinationRejected := (cryptoType != 7 && cryptoType != 6 && cryptoType != 4)
		if !createDestinationRejected {
			createDestinationRejected = seenCrypto[cryptoType]
		}
		if createDestinationRejected {
			return nil, errDestinationCryptoTypes
		}
		seenCrypto[cryptoType] = true
	}
	policy := DestinationPolicy{Kind: DestinationPublicLS2}
	if spec.Policy.Encrypted {
		policy = DestinationPolicy{Kind: DestinationEncryptedNone, Secret: append([]byte(nil), spec.Policy.Secret...)}
		switch {
		case len(spec.Policy.DHClients) != 0 && len(spec.Policy.PSKClients) == 0:
			policy.Kind = DestinationEncryptedDH
			policy.DHClients = append([][32]byte(nil), spec.Policy.DHClients...)
		case len(spec.Policy.PSKClients) != 0 && len(spec.Policy.DHClients) == 0:
			policy.Kind = DestinationEncryptedPSK
			policy.PSKClients = append([][32]byte(nil), spec.Policy.PSKClients...)
		case len(spec.Policy.DHClients) != 0 || len(spec.Policy.PSKClients) != 0:
			return nil, ErrDestinationPolicy
		}
	}
	defer func() {
		clear(policy.Secret)
		for index := range policy.DHClients {
			clear(policy.DHClients[index][:])
		}
		for index := range policy.PSKClients {
			clear(policy.PSKClients[index][:])
		}
	}()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	var local *ivnp.LocalDestination
	var err error
	if spec.Local != nil {
		local, err = spec.Local.Clone()
	} else if spec.Policy.Encrypted {
		local, err = ivnp.GenerateEncryptedLocalDestination()
	} else {
		local, err = ivnp.GenerateLocalDestination()
	}
	if err != nil {
		return nil, err
	}
	name := "sam:" + local.B32()
	var durable *state.EncryptedLeaseSetPolicy
	if policy.Kind != DestinationPublicLS2 {
		durable = policy.durable()
		defer func() {
			if durable != nil {
				clear(durable.Secret)
			}
		}()
	}

	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		local.ReleaseSensitive()
		return nil, net.ErrClosed
	}
	runtime, err := d.destinationFactory.create(name, local, durable, nil, spec.Policy.CryptoTypes)
	if err != nil {
		return nil, err
	}
	runtime.onRelease = d.removeClientRuntime
	d.clientRuntimesMu.Lock()
	d.clientRuntimes = append(d.clientRuntimes, runtime)
	d.clientRuntimesMu.Unlock()
	d.requestDestinationMaintenance(runtime)
	return &clientDestinationEndpoint{runtime: runtime, wake: d.requestDestinationMaintenance}, nil
}

func (c clientDestinationController) DestroyDestination(_ context.Context, endpoint clientapi.DestinationEndpoint) error {
	if endpoint == nil {
		return nil
	}
	return endpoint.Close()
}

type clientDestinationEndpoint struct {
	runtime *destinationRuntime
	wake    func(*destinationRuntime)
}

func (e *clientDestinationEndpoint) session() (*router.DestinationSession, error) {
	if e == nil || e.runtime == nil || !e.runtime.active() || e.runtime.session == nil {
		return nil, net.ErrClosed
	}
	return e.runtime.session, nil
}

func (e *clientDestinationEndpoint) Hash() ivnp.Hash {
	if e == nil || e.runtime == nil || e.runtime.local == nil {
		return ivnp.Hash{}
	}
	return e.runtime.local.Hash()
}
func (e *clientDestinationEndpoint) B32() string {
	if e == nil || e.runtime == nil || e.runtime.local == nil {
		return ""
	}
	return e.runtime.local.B32()
}
func (e *clientDestinationEndpoint) Destination() []byte {
	if e == nil || e.runtime == nil || e.runtime.local == nil {
		return nil
	}
	return e.runtime.local.Destination()
}
func (e *clientDestinationEndpoint) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.DialI2P(ctx, address)
}
func (e *clientDestinationEndpoint) DialI2PFromPort(ctx context.Context, address string, localPort uint16) (net.Conn, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.DialI2PFromPort(ctx, address, localPort)
}
func (e *clientDestinationEndpoint) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.ListenI2P(ctx, address)
}
func (e *clientDestinationEndpoint) SendMessage(ctx context.Context, delivery streamtunnel.Delivery) error {
	session, err := e.session()
	if err != nil {
		return err
	}
	return session.SendMessage(ctx, delivery)
}
func (e *clientDestinationEndpoint) MarshalDatagramV1To(dst, payload []byte) (int, error) {
	if e == nil || e.runtime == nil || e.runtime.local == nil || !e.runtime.active() {
		return 0, net.ErrClosed
	}
	identity, err := e.runtime.local.Identity()
	if err != nil {
		return 0, err
	}
	return datagram.MarshalV1To(dst, identity, payload, e.runtime.local.Sign)
}
func (e *clientDestinationEndpoint) Subscribe(route clientapi.DestinationRoute, capacity int) (clientapi.MessageSubscription, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.Subscribe(route, capacity)
}
func (e *clientDestinationEndpoint) SubscribeBounded(route clientapi.DestinationRoute, capacity int, maxBytes int64, shared clientapi.ByteBudget) (clientapi.MessageSubscription, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.SubscribeBounded(route, capacity, maxBytes, shared)
}
func (e *clientDestinationEndpoint) WaitReady(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		session, err := e.session()
		if err != nil {
			return err
		}
		runtime := e.runtime
		now := runtime.now()
		inbound := runtime.pool.Count(tunnel.Inbound, now) > 0
		outbound := runtime.pool.Count(tunnel.Outbound, now) > 0
		published := false
		if confirmation, ok := runtime.publisher.(interface{ Confirmed() bool }); ok {
			published = confirmation.Confirmed()
		}
		if inbound && outbound && published && session.Hash() == runtime.pool.Owner() {
			return nil
		}
		if e.wake != nil {
			e.wake(runtime)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (e *clientDestinationEndpoint) Close() error {
	if e == nil || e.runtime == nil || e.runtime.session == nil {
		return nil
	}
	err := e.runtime.session.Close()
	if errors.Is(err, router.ErrDestinationNotFound) {
		return nil
	}
	return err
}

var _ clientapi.DestinationController = clientDestinationController{}
var _ clientapi.DestinationEndpoint = (*clientDestinationEndpoint)(nil)
