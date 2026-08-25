package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/network/router"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	streamtunnel "gosuda.org/ivnp/protocol/streaming/tunnel"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/support/config"
	"gosuda.org/ivnp/support/observability"
	"gosuda.org/ivnp/support/state"
)

var (
	ErrDestinationExists   = errors.New("daemon: destination name already exists")
	ErrDestinationPolicy   = errors.New("daemon: invalid destination policy")
	ErrDestinationName     = errors.New("daemon: invalid destination name")
	ErrDestinationCreation = errors.New("daemon: destination creation unavailable")
)

// DestinationPolicyKind selects the durable publication format and, for ELS2,
// its client-authorization mode.
type DestinationPolicyKind uint8

const (
	DestinationPublicLS2 DestinationPolicyKind = iota
	DestinationEncryptedNone
	DestinationEncryptedDH
	DestinationEncryptedPSK
)

// DestinationPolicy is validated before identity generation or state changes.
// Secret is the optional ELS2 blinding secret. DHClients and PSKClients contain
// the 32-byte client public keys or pre-shared keys admitted by the publisher.
type DestinationPolicy struct {
	Kind       DestinationPolicyKind
	Secret     []byte
	DHClients  [][32]byte
	PSKClients [][32]byte
}

// Validate rejects ambiguous or unrepresentable LS2/ELS2 policies.
func (p DestinationPolicy) Validate() error {
	if len(p.Secret) > 0xffff || len(p.DHClients) > 0xffff || len(p.PSKClients) > 0xffff {
		return ErrDestinationPolicy
	}
	clients := len(p.DHClients) + len(p.PSKClients)
	if clients > 0xffff || 1+32+2+40*clients+33 >= netdb.MaxLeaseSetBytes {
		return ErrDestinationPolicy
	}
	switch p.Kind {
	case DestinationPublicLS2:
		if len(p.Secret) != 0 || clients != 0 {
			return ErrDestinationPolicy
		}
	case DestinationEncryptedNone:
		if clients != 0 {
			return ErrDestinationPolicy
		}
	case DestinationEncryptedDH:
		if len(p.DHClients) == 0 || len(p.PSKClients) != 0 {
			return ErrDestinationPolicy
		}
	case DestinationEncryptedPSK:
		if len(p.PSKClients) == 0 || len(p.DHClients) != 0 {
			return ErrDestinationPolicy
		}
	default:
		return ErrDestinationPolicy
	}
	return nil
}

func (p DestinationPolicy) durable() *state.EncryptedLeaseSetPolicy {
	if p.Kind == DestinationPublicLS2 {
		return nil
	}
	return &state.EncryptedLeaseSetPolicy{
		Secret:     append([]byte(nil), p.Secret...),
		DHClients:  append([][32]byte(nil), p.DHClients...),
		PSKClients: append([][32]byte(nil), p.PSKClients...),
	}
}

type destinationBuildReplyRegistry struct {
	mu       sync.RWMutex
	next     uint64
	handlers []destinationBuildReplyRegistration
}

type destinationBuildReplyRegistration struct {
	id      uint64
	handler *tunnel.BuildManager
}

func (r *destinationBuildReplyRegistry) register(handler *tunnel.BuildManager) func() {
	if r == nil || handler == nil {
		return func() {}
	}
	r.mu.Lock()
	r.next++
	id := r.next
	r.handlers = append(r.handlers, destinationBuildReplyRegistration{id: id, handler: handler})
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			for index := range r.handlers {
				if r.handlers[index].id == id {
					copy(r.handlers[index:], r.handlers[index+1:])
					r.handlers[len(r.handlers)-1] = destinationBuildReplyRegistration{}
					r.handlers = r.handlers[:len(r.handlers)-1]
					break
				}
			}
			r.mu.Unlock()
		})
	}
}

func (r *destinationBuildReplyRegistry) HandleInboundReply(message i2np.Message) error {
	if r == nil {
		return tunnel.ErrBuildPending
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		err := registration.handler.HandleInboundReply(message)
		if !errors.Is(err, tunnel.ErrBuildPending) {
			return err
		}
	}
	return tunnel.ErrBuildPending
}

func (r *destinationBuildReplyRegistry) HandleReply(message i2np.Message) error {
	if r == nil {
		return tunnel.ErrBuildPending
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		err := registration.handler.HandleReply(message)
		if !errors.Is(err, tunnel.ErrBuildPending) {
			return err
		}
	}
	return tunnel.ErrBuildPending
}

type destinationRequestRegistry struct {
	mu       sync.RWMutex
	next     uint64
	handlers []destinationRequestRegistration
}

type destinationRequestRegistration struct {
	id      uint64
	handler *netdb.RequestManager
}

func (r *destinationRequestRegistry) register(handler *netdb.RequestManager) func() {
	if r == nil || handler == nil {
		return func() {}
	}
	r.mu.Lock()
	r.next++
	id := r.next
	r.handlers = append(r.handlers, destinationRequestRegistration{id: id, handler: handler})
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			for index := range r.handlers {
				if r.handlers[index].id == id {
					copy(r.handlers[index:], r.handlers[index+1:])
					r.handlers[len(r.handlers)-1] = destinationRequestRegistration{}
					r.handlers = r.handlers[:len(r.handlers)-1]
					break
				}
			}
			r.mu.Unlock()
		})
	}
}

func (r *destinationRequestRegistry) HandleDatabaseSearchReply(reply i2np.DatabaseSearchReplyMessage) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		registration.handler.HandleDatabaseSearchReply(reply)
	}
}

func (r *destinationRequestRegistry) HandleDatabaseStore(store i2np.DatabaseStoreMessage) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		registration.handler.HandleDatabaseStore(store)
	}
}

type destinationPublisherRegistry struct {
	mu         sync.RWMutex
	next       uint64
	publishers []destinationPublisherRegistration
}

type destinationPublisherRegistration struct {
	id        uint64
	publisher netdb.ConfirmedPublisher
}

func (r *destinationPublisherRegistry) register(publisher netdb.ConfirmedPublisher) func() {
	if r == nil || publisher == nil {
		return func() {}
	}
	r.mu.Lock()
	r.next++
	id := r.next
	r.publishers = append(r.publishers, destinationPublisherRegistration{id: id, publisher: publisher})
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			for index := range r.publishers {
				if r.publishers[index].id == id {
					copy(r.publishers[index:], r.publishers[index+1:])
					r.publishers[len(r.publishers)-1] = destinationPublisherRegistration{}
					r.publishers = r.publishers[:len(r.publishers)-1]
					break
				}
			}
			r.mu.Unlock()
		})
	}
}

func (r *destinationPublisherRegistry) Maintain(ctx context.Context) (int, error) {
	if r == nil {
		return 0, nil
	}
	r.mu.RLock()
	publishers := make([]netdb.ConfirmedPublisher, 0, len(r.publishers))
	for _, registration := range r.publishers {
		publishers = append(publishers, registration.publisher)
	}
	r.mu.RUnlock()
	if len(publishers) == 0 {
		return 0, nil
	}
	workers := parallelism.Workers(len(publishers))
	jobs := make(chan netdb.ConfirmedPublisher)
	results := make(chan struct {
		sent int
		err  error
	}, len(publishers))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for publisher := range jobs {
				count, err := publisher.Maintain(ctx)
				results <- struct {
					sent int
					err  error
				}{sent: count, err: err}
			}
		}()
	}
	for _, publisher := range publishers {
		jobs <- publisher
	}
	close(jobs)
	group.Wait()
	close(results)
	var sent int
	var result error
	for outcome := range results {
		sent += outcome.sent
		result = errors.Join(result, outcome.err)
	}
	return sent, result
}

type destinationRuntimeFactory struct {
	cfg               config.Operating
	database          *netdb.Database
	service           *router.Service
	tunnels           *tunnel.Runtime
	destinations      *router.DestinationManager
	replyKeys         *garlic.ReplyKeyRegistry
	replySender       *router.BuildReplySender
	transport         tunnel.Sender
	localRouter       ivnp.Hash
	staticPrivate     []byte
	preferredPeers    []ivnp.Hash
	responders        *netdb.ResponderProfiles
	now               func() uint64
	clockNow          func() time.Time
	garlicReceiver    *router.GarlicReceiver
	status            *router.DeliveryStatusMux
	buildReplies      *destinationBuildReplyRegistry
	requests          *destinationRequestRegistry
	publishers        *destinationPublisherRegistry
	publicationTokens *netdb.PublicationTokenRegistry
	metrics           *observability.Registry
	logger            *slog.Logger
}

func (f *destinationRuntimeFactory) create(name string, destination *ivnp.LocalDestination, policy *state.EncryptedLeaseSetPolicy, remotePolicies []state.RemoteELSAuthorization, requestedCrypto []uint16) (*destinationRuntime, error) {
	if f == nil || destination == nil || f.database == nil || f.service == nil || f.tunnels == nil || f.destinations == nil || f.replyKeys == nil || f.replySender == nil || f.transport == nil || f.now == nil || f.clockNow == nil || f.garlicReceiver == nil || f.status == nil || f.buildReplies == nil || f.requests == nil || f.publishers == nil {
		if destination != nil {
			destination.ReleaseSensitive()
		}
		return nil, ErrDestinationCreation
	}
	releaseDestination := true
	defer func() {
		if releaseDestination {
			destination.ReleaseSensitive()
		}
	}()

	ratchet, err := garlic.NewRatchetManager(destination, garlic.RatchetConfig{Metrics: f.metrics})
	if err != nil {
		return nil, err
	}
	releaseRatchet := true
	defer func() {
		if releaseRatchet {
			ratchet.ReleaseSensitive()
		}
	}()

	owner := destination.Hash()
	preferredPeers := append([]ivnp.Hash(nil), f.preferredPeers...)
	if len(preferredPeers) > 1 {
		// Keep destination-owned pool maintenance from racing the router's
		// exploratory pool for the same first bootstrap peer. Concurrent NTCP2
		// handshakes to one peer replace each other in native routers and can
		// discard a just-sent build. Every destination deterministically starts
		// at a nonzero offset while retaining the complete verified set.
		offset := 1 + int(owner[0])%(len(preferredPeers)-1)
		preferredPeers = append(preferredPeers[offset:], preferredPeers[:offset]...)
	}
	pool := tunnel.NewOwnedPool(owner, f.cfg.Tunnel.PoolCapacity)
	profiles := tunnel.NewPeerProfiles(tunnel.PeerProfilesConfig{})
	build, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: f.tunnels, Pool: pool, Sender: f.transport, ReplyKeys: f.replyKeys, ReplySender: f.replySender,
		LocalRouter: f.localRouter, StaticPrivate: f.staticPrivate,
		StaticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
		SeedReplyRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
		Bandwidth:           func(tunnel.ShortBuildRequest) uint32 { return uint32(f.cfg.Tunnel.BandwidthRateBytesPerSecond / 1024) },
		LocalDelivery:       func(message i2np.Message) error { return f.service.HandleI2NP(message, f.now(), false) },
		Now:                 f.now, MaxPending: f.cfg.Tunnel.BuildPendingCapacity, Profiles: profiles, Logger: f.logger, Metrics: f.metrics,
	})
	if err != nil {
		return nil, err
	}
	releaseBuild := true
	defer func() {
		if releaseBuild {
			build.ReleaseSensitive()
		}
	}()
	inboundSource, err := tunnel.NewNetDBInboundBuildSource(tunnel.NetDBInboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: f.cfg.Tunnel.Hops,
		PreferredPeers: preferredPeers, Lifetime: uint64(f.cfg.Tunnel.Lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
	})
	if err != nil {
		return nil, err
	}
	outboundSource, err := tunnel.NewNetDBOutboundBuildSource(tunnel.NetDBOutboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: f.cfg.Tunnel.Hops,
		PreferredPeers: preferredPeers, Lifetime: uint64(f.cfg.Tunnel.Lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
	})
	if err != nil {
		return nil, err
	}
	maintainer, err := tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{
		Pool: pool, Runtime: f.tunnels, Builder: build, InboundSource: inboundSource, OutboundSource: outboundSource,
		Now: f.now, InboundTarget: f.cfg.Tunnel.InboundTarget, OutboundTarget: f.cfg.Tunnel.OutboundTarget,
		RenewBefore: uint64(f.cfg.Tunnel.RenewBefore.Milliseconds()),
	})
	if err != nil {
		return nil, err
	}
	releaseMaintainer := true
	defer func() {
		if releaseMaintainer {
			_ = maintainer.Close()
		}
	}()
	health, err := tunnel.NewHealth(tunnel.HealthConfig{
		Runtime: f.tunnels, Pool: pool, Maintainer: maintainer, Profiles: profiles, Now: f.now,
		Timeout: daemonHealthProbeTimeoutMillis, MaxPending: f.cfg.Tunnel.BuildPendingCapacity,
	})
	if err != nil {
		return nil, err
	}
	releaseHealth := true
	defer func() {
		if releaseHealth {
			_ = health.Close()
		}
	}()
	replyRoute := daemonReplyRoute{local: f.localRouter, maintainer: maintainer, now: f.now}
	requests, err := netdb.NewRequestManager(f.database, muxRequestSender{
		sender: f.transport, tunnels: f.tunnels, pairs: maintainer, now: f.now, replyKeys: f.replyKeys,
		staticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
		seedReplyRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
	}, replyRoute, netdb.RequestManagerConfig{
		Capacity: f.cfg.Tunnel.BuildPendingCapacity, MaxCandidates: daemonNetDBLookupCandidates, MaxWaiters: 64,
		TimeoutMillis: daemonNetDBLookupTimeoutMillis, Now: f.now, Responders: f.responders,
	})
	if err != nil {
		return nil, err
	}
	releaseRequests := true
	defer func() {
		if releaseRequests {
			_ = requests.Close()
		}
	}()
	remoteELS, err := remoteELSContexts(remotePolicies)
	if err != nil {
		return nil, err
	}
	defer releaseRemoteELSContexts(remoteELS)
	rate, burst := f.cfg.Tunnel.BandwidthRateBytesPerSecond, f.cfg.Tunnel.BandwidthBurstBytes
	if rate == 0 {
		rate = 1 << 20
	}
	if burst == 0 {
		burst = 2 << 20
	}
	bandwidth, err := router.NewDestinationBandwidthLimiter(router.DestinationBandwidthConfig{
		RateBytesPerSecond: uint64(rate), BurstBytes: uint64(burst), Now: f.clockNow,
	})
	if err != nil {
		return nil, err
	}
	sender, err := router.NewStreamingTunnelSender(router.StreamingTunnelSenderConfig{
		Database: f.database, Requests: requests, Ratchet: ratchet, RemoteELS: remoteELS,
		Tunnels: f.tunnels, Pool: pool, SeedRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
		Now: f.now, NextID: randomMessageID, Limiter: bandwidth, Metrics: f.metrics,
	})
	if err != nil {
		return nil, err
	}
	releaseSender := true
	defer func() {
		if releaseSender {
			sender.ReleaseSensitive()
		}
	}()
	cryptoTypes := make([]ivnp.CryptoKeyType, len(requestedCrypto))
	for index, cryptoType := range requestedCrypto {
		cryptoTypes[index] = ivnp.CryptoKeyType(cryptoType)
	}
	localLeaseSet, err := netdb.NewLocalLeaseSet2WithTypes(destination, cryptoTypes)
	if err != nil {
		return nil, err
	}
	publisherConfig := netdb.LeaseSetPublisherConfig{
		Local2: localLeaseSet, Database: f.database, InboundLeases: inboundLeaseSource{pool: pool}, Sender: muxLeaseSetSender{
			sender: f.transport, tunnels: f.tunnels, pairs: maintainer, now: f.now,
			staticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
			seedReplyRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
		},
		Discovery: requests, Sign: destination.Sign, Now: f.now, Random: randomNonZeroID, FloodfillLimit: netdb.PublicationFloodfillK,
		RepublishBefore: uint64(f.cfg.Tunnel.RenewBefore.Milliseconds()), Registry: f.publicationTokens,
		ReplyPath: daemonReplyRoute{local: f.localRouter, maintainer: maintainer, now: f.now}, PreferredTargets: preferredPeers, Logger: f.logger,
	}
	var encrypted *netdb.LocalEncryptedLeaseSet
	if policy != nil {
		var encryptedErr error
		encrypted, encryptedErr = netdb.NewLocalEncryptedLeaseSet(destination, localLeaseSet, netdb.EncryptedLeaseSetAuthorization{DHClients: policy.DHClients, PSKClients: policy.PSKClients}, policy.Secret)
		if encryptedErr != nil {
			return nil, encryptedErr
		}
		publisherConfig.Local2, publisherConfig.Encrypted = nil, encrypted
	}
	publisher, err := netdb.NewLeaseSetPublisher(publisherConfig)
	if err != nil {
		encrypted.ReleaseSensitive()
		return nil, err
	}

	runtime := &destinationRuntime{name: name, local: destination, ratchet: ratchet, pool: pool, profiles: profiles, build: build, maintainer: maintainer, health: health, requests: requests, publisher: publisher, tunnels: f.tunnels, sender: sender, bandwidth: bandwidth, now: f.now}
	runtime.unregister = append(runtime.unregister,
		f.buildReplies.register(build),
		f.requests.register(requests),
		f.status.Register(health),
		f.status.Register(publisher),
		f.publishers.register(publisher),
	)
	removeGarlic, registerErr := f.garlicReceiver.RegisterDestination(owner, router.GarlicDestination{Ratchet: ratchet, SendRatchetReply: sender.SendRatchetReply, Limiter: bandwidth})
	if registerErr != nil {
		runtime.release()
		releaseDestination, releaseRatchet = false, false
		return nil, registerErr
	}
	runtime.unregister = append(runtime.unregister, removeGarlic)
	session, createErr := f.destinations.Create(router.DestinationSessionConfig{
		Streaming: streamtunnel.TunnelNetworkConfig{Destination: destination, Sender: sender}, Default: name == "default", Release: runtime.release,
	})
	if createErr != nil {
		runtime.release()
		releaseDestination, releaseRatchet = false, false
		return nil, createErr
	}
	runtime.session = session
	releaseDestination, releaseRatchet = false, false
	releaseBuild, releaseSender = false, false
	releaseMaintainer, releaseHealth, releaseRequests = false, false, false
	return runtime, nil
}

// CreateDestination atomically persists a new private destination and its ELS2
// policy before activating the production runtime. Any later construction
// failure restores the previous durable bundle and releases all sensitive state.
func (d *Daemon) CreateDestination(ctx context.Context, name string, policy DestinationPolicy) (clientapi.Destination, error) {
	if d == nil || d.store == nil {
		return clientapi.Destination{}, net.ErrClosed
	}
	if err := policy.Validate(); err != nil {
		return clientapi.Destination{}, err
	}
	if name == "" || !utf8.ValidString(name) || len(name) > d.config.State.MaxNameBytes {
		return clientapi.Destination{}, ErrDestinationName
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return clientapi.Destination{}, err
	}

	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	if d.closed || d.destinationFactory == nil {
		d.mu.Unlock()
		return clientapi.Destination{}, ErrDestinationCreation
	}
	if d.bundle.DestinationPrivate[name] != nil || d.bundle.Destinations[name].Destination != nil {
		d.mu.Unlock()
		return clientapi.Destination{}, ErrDestinationExists
	}
	if len(d.bundle.DestinationPrivate)+len(d.bundle.Destinations) >= d.config.State.MaxDestinations || len(d.bundle.DestinationPrivate) >= 64 {
		d.mu.Unlock()
		return clientapi.Destination{}, ErrTooManyDestinations
	}
	d.mu.Unlock()

	var destination *ivnp.LocalDestination
	var err error
	if policy.Kind == DestinationPublicLS2 {
		destination, err = ivnp.GenerateLocalDestination()
	} else {
		destination, err = ivnp.GenerateEncryptedLocalDestination()
	}
	if err != nil {
		return clientapi.Destination{}, err
	}
	encoded, err := destinationPrivate(destination)
	if err != nil {
		destination.ReleaseSensitive()
		return clientapi.Destination{}, err
	}

	d.mu.Lock()
	previous := d.bundle
	next := d.bundle
	next.DestinationPrivate = cloneDestinationPrivate(d.bundle.DestinationPrivate)
	next.EncryptedLeaseSetPolicies = cloneEncryptedLeaseSetPolicies(d.bundle.EncryptedLeaseSetPolicies)
	next.DestinationPrivate[name] = append([]byte(nil), encoded...)
	durable := policy.durable()
	defer releaseEncryptedLeaseSetPolicy(durable)
	if durable == nil {
		delete(next.EncryptedLeaseSetPolicies, name)
	} else {
		next.EncryptedLeaseSetPolicies[name] = cloneEncryptedLeaseSetPolicy(*durable)
	}
	if err = d.store.Save(next); err != nil {
		d.mu.Unlock()
		releaseDestinationPrivate(next.DestinationPrivate)
		releaseEncryptedLeaseSetPolicies(next.EncryptedLeaseSetPolicies)
		destination.ReleaseSensitive()
		clear(encoded)
		return clientapi.Destination{}, err
	}
	d.bundle = next
	d.mu.Unlock()
	clear(encoded)

	runtime, err := d.destinationFactory.create(name, destination, durable, nil, nil)
	if err != nil {
		d.mu.Lock()
		rollbackErr := d.store.Save(previous)
		if rollbackErr == nil {
			d.bundle = previous
		}
		d.mu.Unlock()
		if rollbackErr == nil {
			releaseDestinationPrivate(next.DestinationPrivate)
			releaseEncryptedLeaseSetPolicies(next.EncryptedLeaseSetPolicies)
		} else {
			releaseDestinationPrivate(previous.DestinationPrivate)
			releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
		}
		return clientapi.Destination{}, errors.Join(err, rollbackErr)
	}
	runtime.onRelease = d.removeClientRuntime
	d.clientRuntimesMu.Lock()
	d.clientRuntimes = append(d.clientRuntimes, runtime)
	d.clientRuntimesMu.Unlock()
	releaseDestinationPrivate(previous.DestinationPrivate)
	releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
	return clientapi.Destination{Name: name, Address: runtime.local.B32(), Default: name == "default"}, nil
}

// DestroyDestination durably removes one named destination before tearing down
// exactly its production session and owner-scoped runtime.
func (d *Daemon) DestroyDestination(ctx context.Context, name string) error {
	if d == nil || d.store == nil {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	var runtime *destinationRuntime
	for _, candidate := range d.clientRuntimeSnapshot() {
		if candidate.name == name && candidate.active() {
			runtime = candidate
			break
		}
	}
	if runtime == nil {
		return router.ErrDestinationNotFound
	}
	d.mu.Lock()
	previous := d.bundle
	next := d.bundle
	next.DestinationPrivate = cloneDestinationPrivate(d.bundle.DestinationPrivate)
	next.EncryptedLeaseSetPolicies = cloneEncryptedLeaseSetPolicies(d.bundle.EncryptedLeaseSetPolicies)
	next.DestinationAddressPolicies = cloneDestinationAddressPolicies(d.bundle.DestinationAddressPolicies)
	clear(next.DestinationPrivate[name])
	delete(next.DestinationPrivate, name)
	if policy, exists := next.EncryptedLeaseSetPolicies[name]; exists {
		releaseEncryptedLeaseSetPolicy(&policy)
		delete(next.EncryptedLeaseSetPolicies, name)
	}
	releaseRemoteELSAuthorizations(next.DestinationAddressPolicies[name])
	delete(next.DestinationAddressPolicies, name)
	if err := d.store.Save(next); err != nil {
		d.mu.Unlock()
		releaseDestinationPrivate(next.DestinationPrivate)
		releaseEncryptedLeaseSetPolicies(next.EncryptedLeaseSetPolicies)
		releaseDestinationAddressPolicies(next.DestinationAddressPolicies)
		return err
	}
	d.bundle = next
	d.mu.Unlock()
	if err := d.destinations.Destroy(runtime.local.Hash()); err != nil {
		d.mu.Lock()
		rollbackErr := d.store.Save(previous)
		if rollbackErr == nil {
			d.bundle = previous
		}
		d.mu.Unlock()
		if rollbackErr == nil {
			releaseDestinationPrivate(next.DestinationPrivate)
			releaseEncryptedLeaseSetPolicies(next.EncryptedLeaseSetPolicies)
			releaseDestinationAddressPolicies(next.DestinationAddressPolicies)
		} else {
			releaseDestinationPrivate(previous.DestinationPrivate)
			releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
			releaseDestinationAddressPolicies(previous.DestinationAddressPolicies)
		}
		return errors.Join(err, rollbackErr)
	}
	releaseDestinationPrivate(previous.DestinationPrivate)
	releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
	releaseDestinationAddressPolicies(previous.DestinationAddressPolicies)
	return nil
}

func cloneDestinationPrivate(source map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(source)+1)
	for name, private := range source {
		cloned[name] = append([]byte(nil), private...)
	}
	return cloned
}

func cloneEncryptedLeaseSetPolicies(source map[string]state.EncryptedLeaseSetPolicy) map[string]state.EncryptedLeaseSetPolicy {
	cloned := make(map[string]state.EncryptedLeaseSetPolicy, len(source)+1)
	for name, policy := range source {
		cloned[name] = cloneEncryptedLeaseSetPolicy(policy)
	}
	return cloned
}

func cloneEncryptedLeaseSetPolicy(policy state.EncryptedLeaseSetPolicy) state.EncryptedLeaseSetPolicy {
	return state.EncryptedLeaseSetPolicy{
		Secret:     append([]byte(nil), policy.Secret...),
		DHClients:  append([][32]byte(nil), policy.DHClients...),
		PSKClients: append([][32]byte(nil), policy.PSKClients...),
	}
}

func releaseDestinationPrivate(destinations map[string][]byte) {
	for name, private := range destinations {
		clear(private)
		delete(destinations, name)
	}
}

func releaseEncryptedLeaseSetPolicy(policy *state.EncryptedLeaseSetPolicy) {
	if policy == nil {
		return
	}
	clear(policy.Secret)
	for index := range policy.DHClients {
		clear(policy.DHClients[index][:])
	}
	for index := range policy.PSKClients {
		clear(policy.PSKClients[index][:])
	}
	clear(policy.DHClients)
	clear(policy.PSKClients)
	*policy = state.EncryptedLeaseSetPolicy{}
}

func releaseEncryptedLeaseSetPolicies(policies map[string]state.EncryptedLeaseSetPolicy) {
	for name, policy := range policies {
		releaseEncryptedLeaseSetPolicy(&policy)
		delete(policies, name)
	}
}

var (
	_ router.TunnelBuildReplyHandler = (*destinationBuildReplyRegistry)(nil)
	_ router.NetDBRequestHandler     = (*destinationRequestRegistry)(nil)
)
