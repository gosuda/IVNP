package noderuntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

var (
	ErrDestinationExists   = errors.New("daemon: destination name already exists")
	ErrDestinationPolicy   = errors.New("daemon: invalid destination policy")
	ErrDestinationName     = errors.New("daemon: invalid destination name")
	ErrDestinationCreation = errors.New("daemon: destination creation unavailable")
)

// DestinationPolicyKind selects the publication format (public LeaseSet2 or encrypted ELS2).
type DestinationPolicyKind uint8

const (
	DestinationPublicLS2 DestinationPolicyKind = iota
	DestinationEncryptedNone
	DestinationEncryptedDH
	DestinationEncryptedPSK
)

// DestinationPolicy configures access control and publication settings for a local destination.
type DestinationPolicy struct {
	Kind       DestinationPolicyKind
	Secret     []byte
	DHClients  [][32]byte
	PSKClients [][32]byte
}

// Validate checks whether the destination policy settings are valid.
func (p DestinationPolicy) Validate() error {
	if len(p.Secret) > 0xffff || len(p.DHClients) > 0xffff || len(p.PSKClients) > 0xffff {
		return ErrDestinationPolicy
	}
	clients := len(p.DHClients) + len(p.PSKClients)
	if clients > 0xffff || 1+32+2+40*clients+33 >= networking.NetworkDatabaseMaxLeaseSetBytes {
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

func (p DestinationPolicy) durable() *state.SecureStateEncryptedLeaseSetPolicy {
	if p.Kind == DestinationPublicLS2 {
		return nil
	}
	return &state.SecureStateEncryptedLeaseSetPolicy{
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
	handler *networking.TunnelBuildManager
}

func (r *destinationBuildReplyRegistry) register(handler *networking.TunnelBuildManager) func() {
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

func (r *destinationBuildReplyRegistry) HandleInboundReply(message networking.I2NPMessage) error {
	if r == nil {
		return networking.TunnelErrBuildPending
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		err := registration.handler.HandleInboundReply(message)
		if !errors.Is(err, networking.TunnelErrBuildPending) {
			return err
		}
	}
	return networking.TunnelErrBuildPending
}

func (r *destinationBuildReplyRegistry) HandleReply(message networking.I2NPMessage) error {
	if r == nil {
		return networking.TunnelErrBuildPending
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		err := registration.handler.HandleReply(message)
		if !errors.Is(err, networking.TunnelErrBuildPending) {
			return err
		}
	}
	return networking.TunnelErrBuildPending
}

type destinationRequestRegistry struct {
	mu       sync.RWMutex
	next     uint64
	handlers []destinationRequestRegistration
}

type destinationRequestRegistration struct {
	id      uint64
	handler *networking.NetworkDatabaseRequestManager
}

func (r *destinationRequestRegistry) register(handler *networking.NetworkDatabaseRequestManager) func() {
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

func (r *destinationRequestRegistry) HandleDatabaseSearchReply(reply networking.I2NPDatabaseSearchReplyMessage) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		registration.handler.HandleDatabaseSearchReply(reply)
	}
}

func (r *destinationRequestRegistry) ExpectsDatabaseStore(store networking.I2NPDatabaseStoreMessage) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		if registration.handler.ExpectsDatabaseStore(store) {
			return true
		}
	}
	return false
}

func (r *destinationRequestRegistry) HandleDatabaseStore(store networking.I2NPDatabaseStoreMessage) {
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
	publisher networking.NetworkDatabaseConfirmedPublisher
}

func (r *destinationPublisherRegistry) register(publisher networking.NetworkDatabaseConfirmedPublisher) func() {
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
	publishers := make([]networking.NetworkDatabaseConfirmedPublisher, 0, len(r.publishers))
	for _, registration := range r.publishers {
		publishers = append(publishers, registration.publisher)
	}
	r.mu.RUnlock()
	if len(publishers) == 0 {
		return 0, nil
	}
	workers := parallelism.Workers(len(publishers))
	jobs := make(chan networking.NetworkDatabaseConfirmedPublisher)
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
	cfg                      state.ConfigurationOperating
	database                 *networking.NetworkDatabase
	service                  *networking.RouterService
	tunnels                  *networking.TunnelRuntime
	destinations             *networking.RouterDestinationManager
	replyKeys                *networking.GarlicReplyKeyRegistry
	replySender              *networking.RouterBuildReplySender
	transport                networking.TunnelSender
	localRouter              foundation.Hash
	staticPrivate            []byte
	preferredPeers           []foundation.Hash
	profiles                 *networking.TunnelPeerProfiles
	eligible                 func(foundation.Hash) bool
	allowUnknownTransports   bool
	responders               *networking.NetworkDatabaseResponderProfiles
	now                      func() uint64
	clockNow                 func() time.Time
	garlicReceiver           *networking.RouterGarlicReceiver
	status                   *networking.RouterDeliveryStatusMux
	buildReplies             *destinationBuildReplyRegistry
	requests                 *destinationRequestRegistry
	publishers               *destinationPublisherRegistry
	publicationTokens        *networking.NetworkDatabasePublicationTokenRegistry
	metrics                  *observability.Registry
	logger                   *slog.Logger
	requestTunnelMaintenance func(*destinationRuntime)
}

func (f *destinationRuntimeFactory) create(name string, destination *foundation.LocalDestination, policy *state.SecureStateEncryptedLeaseSetPolicy, remotePolicies []state.SecureStateRemoteELSAuthorization, requestedCrypto []uint16) (*destinationRuntime, error) {
	createSelected := f == nil || destination == nil || f.database == nil || f.service == nil || f.tunnels == nil || f.destinations == nil || f.replyKeys == nil || f.replySender == nil || f.transport == nil || f.profiles == nil || f.now == nil || f.clockNow == nil || f.garlicReceiver == nil || f.status == nil || f.buildReplies == nil || f.requests == nil
	if !createSelected {
		createSelected = f.publishers == nil
	}
	if createSelected {
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

	ratchet, err := networking.GarlicNewRatchetManager(destination, networking.GarlicRatchetConfig{Metrics: f.metrics})
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
	preferredPeers := append([]foundation.Hash(nil), f.preferredPeers...)
	if len(preferredPeers) > 1 {
		// Spread destination LeaseSet publication across the verified bootstrap
		// responders instead of making every destination target the same
		// floodfill first.
		offset := 1 + int(owner[0])%(len(preferredPeers)-1)
		preferredPeers = append(preferredPeers[offset:], preferredPeers[:offset]...)
	}
	pool := networking.TunnelNewOwnedPool(owner, f.cfg.Tunnel.ClientPoolCapacity)
	var runtime *destinationRuntime
	profiles := f.profiles
	build, err := networking.TunnelNewBuildManager(networking.TunnelBuildManagerConfig{
		Runtime: f.tunnels, Pool: pool, Sender: f.transport, ReplyKeys: f.replyKeys, ReplySender: f.replySender,
		LocalRouter: f.localRouter, StaticPrivate: f.staticPrivate,
		StaticKeyLookup: networking.TunnelNewNetDBBuildStaticKeyLookup(f.database.Routers()),
		Bandwidth: func(networking.TunnelShortBuildRequest) uint32 {
			return uint32(f.cfg.Tunnel.BandwidthRateBytesPerSecond / 1024)
		},
		LocalDelivery: func(message networking.I2NPMessage) error { return f.service.HandleI2NP(message, f.now(), false) },
		Now:           f.now, MaxPending: f.cfg.Tunnel.BuildPendingCapacity, Profiles: profiles, Logger: f.logger, Metrics: f.metrics,
		OnBuildEvent: func() {
			if runtime != nil && f.requestTunnelMaintenance != nil {
				f.requestTunnelMaintenance(runtime)
			}
		},
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
	inboundSource, err := networking.TunnelNewNetDBInboundBuildSource(networking.TunnelNetDBInboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: f.cfg.Tunnel.Hops,
		Lifetime: uint64(f.cfg.Tunnel.Lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID, CandidateLimit: daemonTunnelBuildCandidates,
		Eligible: f.eligible, AllowUnknownTransports: f.allowUnknownTransports,
	})
	if err != nil {
		return nil, fmt.Errorf("create destination inbound build source: %w", err)
	}
	outboundSource, err := networking.TunnelNewNetDBOutboundBuildSource(networking.TunnelNetDBOutboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: f.cfg.Tunnel.Hops,
		Lifetime: uint64(f.cfg.Tunnel.Lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID, CandidateLimit: daemonTunnelBuildCandidates,
		Eligible: f.eligible, AllowUnknownTransports: f.allowUnknownTransports,
	})
	if err != nil {
		return nil, fmt.Errorf("create destination outbound build source: %w", err)
	}
	maintainer, err := networking.TunnelNewPairedPoolMaintainer(networking.TunnelPairedPoolMaintainerConfig{
		Pool: pool, Runtime: f.tunnels, Builder: build, InboundSource: inboundSource, OutboundSource: outboundSource,
		Now: f.now, InboundTarget: f.cfg.Tunnel.ClientInboundTarget, OutboundTarget: f.cfg.Tunnel.ClientOutboundTarget,
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
	health, err := networking.TunnelNewHealth(networking.TunnelHealthConfig{
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
	requests, err := networking.NetworkDatabaseNewRequestManager(f.database, muxRequestSender{
		sender: f.transport, tunnels: f.tunnels, pairs: maintainer, now: f.now, replyKeys: f.replyKeys,
		staticKeyLookup:     networking.TunnelNewNetDBBuildStaticKeyLookup(f.database.Routers()),
		seedReplyRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
	}, replyRoute, networking.NetworkDatabaseRequestManagerConfig{
		Capacity: f.cfg.NetDB.LookupCapacity, MaxCandidates: daemonNetDBLookupCandidates, MaxWaiters: 64,
		TimeoutMillis: daemonDestinationNetDBLookupTimeoutMillis, Now: f.now, Metrics: f.metrics, Responders: f.responders, Logger: f.logger,
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

	rate = cmp.Or(rate, 1<<20)

	burst = cmp.Or(burst, 2<<20)

	bandwidth, err := networking.RouterNewDestinationBandwidthLimiter(networking.RouterDestinationBandwidthConfig{
		RateBytesPerSecond: uint64(rate), BurstBytes: uint64(burst), Now: f.clockNow,
	})
	if err != nil {
		return nil, err
	}
	sender, err := networking.RouterNewStreamingTunnelSender(networking.RouterStreamingTunnelSenderConfig{
		Database: f.database, Requests: requests, Ratchet: ratchet, RemoteELS: remoteELS,
		Tunnels: f.tunnels, Pool: pool, SeedRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
		Now: f.now, NextID: randomMessageID, Limiter: bandwidth, Metrics: f.metrics, Logger: f.logger,
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
	cryptoTypes := make([]foundation.CryptoKeyType, len(requestedCrypto))
	for index, cryptoType := range requestedCrypto {
		cryptoTypes[index] = foundation.CryptoKeyType(cryptoType)
	}
	localLeaseSet, err := networking.NetworkDatabaseNewLocalLeaseSet2WithTypes(destination, cryptoTypes)
	if err != nil {
		return nil, err
	}
	publisherConfig := networking.NetworkDatabaseLeaseSetPublisherConfig{
		Local2: localLeaseSet, Database: f.database, InboundLeases: inboundLeaseSource{pool: pool}, Sender: muxLeaseSetSender{
			sender: f.transport, tunnels: f.tunnels, pairs: maintainer, now: f.now,
			staticKeyLookup:     networking.TunnelNewNetDBBuildStaticKeyLookup(f.database.Routers()),
			seedReplyRouterInfo: buildReplyRouterInfoSeeder(f.database, f.transport, f.now),
		},
		Discovery: requests, Sign: destination.Sign, Now: f.now, Random: randomNonZeroID, FloodfillLimit: networking.NetworkDatabasePublicationFloodfillK,
		RepublishBefore: uint64(f.cfg.Tunnel.RenewBefore.Milliseconds()), Registry: f.publicationTokens,
		ReplyPath: daemonReplyRoute{local: f.localRouter, maintainer: maintainer, now: f.now}, PreferredTargets: preferredPeers, Logger: f.logger,
	}
	var encrypted *networking.NetworkDatabaseLocalEncryptedLeaseSet
	if policy != nil {
		var encryptedErr error
		encrypted, encryptedErr = networking.NetworkDatabaseNewLocalEncryptedLeaseSet(destination, localLeaseSet, networking.NetworkDatabaseEncryptedLeaseSetAuthorization{DHClients: policy.DHClients, PSKClients: policy.PSKClients}, policy.Secret)
		if encryptedErr != nil {
			return nil, encryptedErr
		}
		publisherConfig.Local2, publisherConfig.Encrypted = nil, encrypted
	}
	publisher, err := networking.NetworkDatabaseNewLeaseSetPublisher(publisherConfig)
	if err != nil {
		encrypted.ReleaseSensitive()
		return nil, err
	}

	runtime = &destinationRuntime{name: name, local: destination, ratchet: ratchet, pool: pool, profiles: profiles, build: build, maintainer: maintainer, health: health, requests: requests, publisher: publisher, tunnels: f.tunnels, sender: sender, bandwidth: bandwidth, now: f.now}
	runtime.unregister = append(runtime.unregister,
		f.buildReplies.register(build),
		f.requests.register(requests),
		f.status.Register(health),
		f.status.Register(publisher),
		f.publishers.register(publisher),
	)
	removeGarlic, registerErr := f.garlicReceiver.RegisterDestination(owner, networking.RouterGarlicDestination{Ratchet: ratchet, SendRatchetReply: sender.SendRatchetReply, Limiter: bandwidth})
	if registerErr != nil {
		runtime.release()
		releaseDestination, releaseRatchet = false, false
		return nil, registerErr
	}
	runtime.unregister = append(runtime.unregister, removeGarlic)
	session, createErr := f.destinations.Create(networking.RouterDestinationSessionConfig{
		Streaming: networking.StreamingTunnelTunnelNetworkConfig{Destination: destination, Sender: sender}, Default: name == "default", Release: runtime.release,
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

// CreateDestination creates and starts a new local destination with the given name and policy.
func (d *Daemon) CreateDestination(ctx context.Context, name string, policy DestinationPolicy) (client.ClientDestination, error) {
	if d == nil || d.store == nil {
		return client.ClientDestination{}, net.ErrClosed
	}
	if err := policy.Validate(); err != nil {
		return client.ClientDestination{}, err
	}
	if name == "" || !utf8.ValidString(name) || len(name) > d.config.State.MaxNameBytes {
		return client.ClientDestination{}, ErrDestinationName
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return client.ClientDestination{}, err
	}

	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	if d.closed || d.destinationFactory == nil {
		d.mu.Unlock()
		return client.ClientDestination{}, ErrDestinationCreation
	}
	if d.bundle.DestinationPrivate[name] != nil || d.bundle.Destinations[name].Destination != nil {
		d.mu.Unlock()
		return client.ClientDestination{}, ErrDestinationExists
	}
	if len(d.bundle.DestinationPrivate)+len(d.bundle.Destinations) >= d.config.State.MaxDestinations || len(d.bundle.DestinationPrivate) >= 64 {
		d.mu.Unlock()
		return client.ClientDestination{}, ErrTooManyDestinations
	}
	d.mu.Unlock()

	var destination *foundation.LocalDestination
	var err error
	if policy.Kind == DestinationPublicLS2 {
		destination, err = foundation.GenerateLegacyLocalDestination()
	} else {
		destination, err = foundation.GenerateEncryptedLocalDestination()
	}
	if err != nil {
		return client.ClientDestination{}, err
	}
	encoded, err := destinationPrivate(destination)
	if err != nil {
		destination.ReleaseSensitive()
		return client.ClientDestination{}, err
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
		return client.ClientDestination{}, err
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
		return client.ClientDestination{}, errors.Join(err, rollbackErr)
	}
	runtime.onRelease = d.removeClientRuntime
	d.clientRuntimesMu.Lock()
	d.clientRuntimes = append(d.clientRuntimes, runtime)
	d.clientRuntimesMu.Unlock()
	releaseDestinationPrivate(previous.DestinationPrivate)
	releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
	return client.ClientDestination{Name: name, Address: runtime.local.B32(), Default: name == "default"}, nil
}

// DestroyDestination removes a named destination from persistent storage and stops its runtime.
func (d *Daemon) DestroyDestination(ctx context.Context, name string) error {
	if d == nil || d.store == nil {
		return net.ErrClosed
	}
	if ctx ==
		nil {
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
		return networking.RouterErrDestinationNotFound
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

func cloneEncryptedLeaseSetPolicies(source map[string]state.SecureStateEncryptedLeaseSetPolicy) map[string]state.SecureStateEncryptedLeaseSetPolicy {
	cloned := make(map[string]state.SecureStateEncryptedLeaseSetPolicy, len(source)+1)
	for name, policy := range source {
		cloned[name] = cloneEncryptedLeaseSetPolicy(policy)
	}
	return cloned
}

func cloneEncryptedLeaseSetPolicy(policy state.SecureStateEncryptedLeaseSetPolicy) state.SecureStateEncryptedLeaseSetPolicy {
	return state.SecureStateEncryptedLeaseSetPolicy{
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

func releaseEncryptedLeaseSetPolicy(policy *state.SecureStateEncryptedLeaseSetPolicy) {
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
	*policy = state.SecureStateEncryptedLeaseSetPolicy{}
}

func releaseEncryptedLeaseSetPolicies(policies map[string]state.SecureStateEncryptedLeaseSetPolicy) {
	for name, policy := range policies {
		releaseEncryptedLeaseSetPolicy(&policy)
		delete(policies, name)
	}
}

var (
	_ networking.RouterTunnelBuildReplyHandler = (*destinationBuildReplyRegistry)(nil)
	_ networking.RouterNetDBRequestHandler     = (*destinationRequestRegistry)(nil)
)
