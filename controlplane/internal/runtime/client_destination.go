package noderuntime

import (
	"context"
	"errors"
	"net"
	"time"

	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/state"
)

var errDestinationCryptoTypes = errors.New("daemon: unsupported destination crypto type order")

type clientDestinationController struct{ daemon *Controller }

// DestinationController returns a dynamic destination controller for creating and destroying endpoints.
func (d *Controller) DestinationController() destination.DestinationController {
	return clientDestinationController{daemon: d}
}

func (c clientDestinationController) CreateDestination(ctx context.Context, spec destination.DestinationSpec) (destination.DestinationEndpoint, error) {
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
	if spec.Tunnels != nil {
		if err := validateDestinationTunnels(*spec.Tunnels); err != nil {
			return nil, err
		}
	}
	remotePolicies, err := destinationRemotePolicies(spec.RemoteAccess)
	if err != nil {
		return nil, err
	}
	defer releaseRemoteELSAuthorizations(remotePolicies)
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
	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if d.clientRuntimeCount() >= d.config.State.MaxDestinations {
		return nil, ErrTooManyDestinations
	}

	var local *foundation.LocalDestination
	err = nil
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
	owner := local.Hash()
	d.clientRuntimesMu.RLock()
	for _, existing := range d.clientRuntimes {
		// The pool retains its owner through key erasure and until removal
		// from the registry, so closing destinations still reserve their identity.
		if existing.pool.Owner() == owner {
			d.clientRuntimesMu.RUnlock()
			local.ReleaseSensitive()
			return nil, ErrDuplicateDestination
		}
	}
	d.clientRuntimesMu.RUnlock()
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

	runtime, err := d.destinationFactory.create(name, local, durable, remotePolicies, spec.Policy.CryptoTypes, spec.Tunnels)
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

func destinationRemotePolicies(access []destination.RemoteLeaseSetAccess) ([]state.SecureStateRemoteELSAuthorization, error) {
	if len(access) > 64 {
		return nil, ErrDestinationPolicy
	}
	policies := make([]state.SecureStateRemoteELSAuthorization, len(access))
	valid := false
	defer func() {
		if !valid {
			releaseRemoteELSAuthorizations(policies)
		}
	}()
	var zero [32]byte
	for index, credential := range access {
		identity, consumed, err := foundation.ParseIdentity(credential.Identity)
		if err != nil || consumed != len(credential.Identity) || len(credential.Identity) > 0xffff || len(credential.Secret) > 0xffff {
			return nil, ErrDestinationPolicy
		}
		switch identity.SigningKeyType() {
		case foundation.SigningEdDSASHA512Ed25519, foundation.SigningRedDSASHA512Ed25519:
		default:
			return nil, ErrDestinationPolicy
		}
		switch credential.Kind {
		case destination.RemoteAuthNone:
			if credential.DHPrivate != zero || credential.DHPublic != zero || credential.PSK != zero {
				return nil, ErrDestinationPolicy
			}
		case destination.RemoteAuthDH:
			if credential.PSK != zero {
				return nil, ErrDestinationPolicy
			}
		case destination.RemoteAuthPSK:
			if credential.DHPrivate != zero || credential.DHPublic != zero {
				return nil, ErrDestinationPolicy
			}
		default:
			return nil, ErrDestinationPolicy
		}
		policies[index] = state.SecureStateRemoteELSAuthorization{
			Identity: append([]byte(nil), credential.Identity...), Secret: append([]byte(nil), credential.Secret...),
			Kind:      state.SecureStateRemoteELSAuthorizationKind(credential.Kind),
			DHPrivate: credential.DHPrivate, DHPublic: credential.DHPublic, PSK: credential.PSK,
		}
	}
	contexts, err := remoteELSContexts(policies)
	if err != nil {
		return nil, err
	}
	defer releaseRemoteELSContexts(contexts)
	if err := router.ValidateRemoteELSContexts(contexts); err != nil {
		return nil, err
	}
	valid = true
	return policies, nil
}

func (c clientDestinationController) DestroyDestination(_ context.Context, endpoint destination.DestinationEndpoint) error {
	if endpoint == nil {
		return nil
	}
	return endpoint.Close()
}

type clientDestinationEndpoint struct {
	runtime *destinationRuntime
	wake    func(*destinationRuntime)
}

func (e *clientDestinationEndpoint) DialStream(ctx context.Context, address string, localPort uint16) (net.Conn, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.DialStream(ctx, address, localPort)
}

func (e *clientDestinationEndpoint) ListenStream(ctx context.Context, address string) (net.Listener, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.ListenStream(ctx, address)
}

func (e *clientDestinationEndpoint) DatagramMaxPayload(protocol uint8) (int, error) {
	if _, err := e.session(); err != nil {
		return 0, err
	}
	switch protocol {
	case dataplane.DatagramProtocolRaw:
		return dataplane.DatagramMaxSize, nil
	case dataplane.DatagramProtocolDatagram3:
		return dataplane.DatagramMaxSize - 34, nil
	case dataplane.DatagramProtocolDatagram1, dataplane.DatagramProtocolDatagram2:
	default:
		return 0, dataplane.DatagramErrProtocol
	}
	identity, err := e.runtime.local.Identity()
	if err != nil {
		return 0, err
	}
	signature, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return 0, foundation.ErrUnknownKeyType
	}
	overhead := identity.EncodedLen() + signature
	if protocol == dataplane.DatagramProtocolDatagram2 {
		overhead += 2
	}
	if offline, present := e.runtime.local.OfflineSignature(); present {
		if protocol == dataplane.DatagramProtocolDatagram1 {
			return 0, foundation.ErrInvalidIdentity
		}
		key, keyOK := offline.Type.PublicKeyLen()
		transientSignature, signatureOK := offline.Type.SignatureLen()
		if !keyOK || !signatureOK {
			return 0, foundation.ErrUnknownKeyType
		}
		overhead += 6 + key + transientSignature
	}
	if overhead > dataplane.DatagramMaxSize {
		return 0, foundation.ErrInvalidIdentity
	}
	return dataplane.DatagramMaxSize - overhead, nil
}

func (e *clientDestinationEndpoint) session() (*dataplane.RouterDestinationSession, error) {
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
func (e *clientDestinationEndpoint) SendMessage(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
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
	if _, offline := e.runtime.local.OfflineSignature(); offline {
		return 0, foundation.ErrInvalidIdentity
	}
	identity, err := e.runtime.local.Identity()
	if err != nil {
		return 0, err
	}
	return dataplane.DatagramMarshalV1To(dst, identity, payload, e.runtime.local.Sign)
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
	var offline dataplane.DatagramOfflineSignature
	if meta, ok := e.runtime.local.OfflineSignature(); ok {
		flags |= dataplane.DatagramFlagOffline
		offline = meta
	}
	return dataplane.DatagramMarshalV2To(dst, target, identity, flags, foundation.Mapping{}, offline, payload, e.runtime.local.Sign)
}
func (e *clientDestinationEndpoint) MarshalDatagramV3To(dst, payload []byte) (int, error) {
	if e == nil || e.runtime == nil || e.runtime.local == nil || !e.runtime.active() {
		return 0, net.ErrClosed
	}
	return dataplane.DatagramMarshalV3To(dst, e.Hash(), 3, foundation.Mapping{}, payload)
}
func (e *clientDestinationEndpoint) Subscribe(route destination.DestinationRoute, capacity int) (destination.MessageSubscription, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.Subscribe(route, capacity)
}
func (e *clientDestinationEndpoint) SubscribeBounded(route destination.DestinationRoute, capacity int, maxBytes int64, shared destination.ByteBudget) (destination.MessageSubscription, error) {
	session, err := e.session()
	if err != nil {
		return nil, err
	}
	return session.SubscribeBounded(route, capacity, maxBytes, shared)
}

func (e *clientDestinationEndpoint) PrepareDestination(ctx context.Context, target foundation.Hash) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		session, err := e.session()
		if err != nil {
			return err
		}
		runtime := e.runtime
		changed := runtime.changes()
		if !runtime.active() {
			return net.ErrClosed
		}
		if runtime.pool.Owner() != session.Hash() {
			return dataplane.RouterErrGarlicDestination
		}
		if _, ok := runtime.requestPath.Pair(runtime.now()); ok {
			return runtime.sender.PrepareDestination(ctx, target)
		}
		if e.wake != nil {
			e.wake(runtime)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
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
		published := runtime.publisher != nil && runtime.publisher.Confirmed()
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
	if errors.Is(err, dataplane.RouterErrDestinationNotFound) {
		return nil
	}
	return err
}

var _ destination.DestinationController = clientDestinationController{}
var _ destination.DestinationEndpoint = (*clientDestinationEndpoint)(nil)
var _ destination.PreparingDestinationEndpoint = (*clientDestinationEndpoint)(nil)
