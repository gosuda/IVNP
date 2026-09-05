package noderuntime

import (
	"context"
	"errors"
	"net"
	"time"

	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking"
	"gosuda.org/ivnp/state"
)

var errDestinationCryptoTypes = errors.New("daemon: unsupported destination crypto type order")

type clientDestinationController struct{ daemon *Daemon }

// DestinationController returns a dynamic destination controller for creating and destroying endpoints.
func (d *Daemon) DestinationController() client.ClientDestinationController {
	return clientDestinationController{daemon: d}
}

func (c clientDestinationController) CreateDestination(ctx context.Context, spec client.ClientDestinationSpec) (client.ClientDestinationEndpoint, error) {
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
	var local *foundation.LocalDestination
	var err error
	if spec.Local != nil {
		local, err = spec.Local.Clone()
	} else if spec.Policy.Encrypted {
		local, err = foundation.GenerateEncryptedLocalDestination()
	} else {
		local, err = foundation.GenerateLegacyLocalDestination()
	}
	if err != nil {
		return nil, err
	}
	name := "sam:" + local.B32()
	var durable *state.SecureStateEncryptedLeaseSetPolicy
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

func (c clientDestinationController) DestroyDestination(_ context.Context, endpoint client.ClientDestinationEndpoint) error {
	if endpoint == nil {
		return nil
	}
	return endpoint.Close()
}

type clientDestinationEndpoint struct {
	runtime *destinationRuntime
	wake    func(*destinationRuntime)
}

func (e *clientDestinationEndpoint) session() (*networking.RouterDestinationSession, error) {
	if e == nil || e.runtime == nil || !e.runtime.active() || e.runtime.session == nil {
		return nil, net.ErrClosed
	}
	return e.runtime.session, nil
}

func (e *clientDestinationEndpoint) Hash() foundation.Hash {
	if e == nil || e.runtime == nil || e.runtime.local == nil {
		return foundation.Hash{}
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
func (e *clientDestinationEndpoint) SendMessage(ctx context.Context, delivery networking.StreamingTunnelDelivery) error {
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
	return networking.DatagramMarshalV1To(dst, identity, payload, e.runtime.local.Sign)
}
func (e *clientDestinationEndpoint) MarshalDatagramV2To(dst []byte, target foundation.Hash, payload []byte) (int, error) {
	if e == nil || e.runtime == nil || e.runtime.local == nil || !e.runtime.active() {
		return 0, net.ErrClosed
	}
	identity, err := e.runtime.local.Identity()
	if err != nil {
		return 0, err
	}
	flags := uint16(2)
	var offline networking.DatagramOfflineSignature
	if meta, ok := e.runtime.local.OfflineSignature(); ok {
		flags |= networking.DatagramFlagOffline
		offline = meta
	}
	return networking.DatagramMarshalV2To(dst, target, identity, flags, foundation.Mapping{}, offline, payload, e.runtime.local.Sign)
}
func (e *clientDestinationEndpoint) MarshalDatagramV3To(dst, payload []byte) (int, error) {
	if e == nil || e.runtime == nil || e.runtime.local == nil || !e.runtime.active() {
		return 0, net.ErrClosed
	}
	return networking.DatagramMarshalV3To(dst, e.Hash(), 3, foundation.Mapping{}, payload)
}
func (e *clientDestinationEndpoint) Subscribe(route client.ClientDestinationRoute, capacity int) (client.ClientMessageSubscription, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.Subscribe(route, capacity)
}
func (e *clientDestinationEndpoint) SubscribeBounded(route client.ClientDestinationRoute, capacity int, maxBytes int64, shared client.ClientByteBudget) (client.ClientMessageSubscription, error) {
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
		inbound := runtime.pool.Count(networking.TunnelInbound, now) > 0
		outbound := runtime.pool.Count(networking.TunnelOutbound, now) > 0
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
	if errors.Is(err, networking.RouterErrDestinationNotFound) {
		return nil
	}
	return err
}

var _ client.ClientDestinationController = clientDestinationController{}
var _ client.ClientDestinationEndpoint = (*clientDestinationEndpoint)(nil)
