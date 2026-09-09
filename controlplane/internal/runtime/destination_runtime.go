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

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/parallelism"
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
	if clients > 0xffff || 1+32+2+40*clients+33 >= foundation.NetworkDatabaseMaxLeaseSetBytes {
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

func (r *destinationBuildReplyRegistry) HandleInboundReply(message foundation.I2NPMessage) error {
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

func (r *destinationBuildReplyRegistry) HandleReply(message foundation.I2NPMessage) error {
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

func (r *destinationRequestRegistry) HandleDatabaseSearchReply(ctx context.Context, reply foundation.I2NPDatabaseSearchReplyMessage) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		registration.handler.HandleDatabaseSearchReply(ctx, reply)
	}
}

func (r *destinationRequestRegistry) ExpectsDatabaseStore(store foundation.I2NPDatabaseStoreMessage) bool {
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

func (r *destinationRequestRegistry) HandleDatabaseStore(ctx context.Context, store foundation.I2NPDatabaseStoreMessage) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, registration := range r.handlers {
		registration.handler.HandleDatabaseStore(ctx, store)
	}
}

func (r *destinationRequestRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	handlers := append([]destinationRequestRegistration(nil), r.handlers...)
	r.mu.RUnlock()
	var result error
	for _, registration := range handlers {
		result = errors.Join(result, registration.handler.Close())
	}
	return result
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
	cfg                      state.ConfigurationOperating
	database                 *netdb.Database
	service                  *dataplane.RouterService
	tunnels                  *dataplane.TunnelRuntime
	destinations             *dataplane.RouterDestinationManager
	replyKeys                *dataplane.GarlicReplyKeyRegistry
	creatorBudget            *tunnel.CreatorBudget
	replySender              *router.BuildReplySender
	transport                dataplane.TunnelSender
	localRouter              foundation.Hash
	staticPrivate            []byte
	preferredPeers           []foundation.Hash
	profiles                 *tunnel.PeerProfiles
	eligible                 func(foundation.Hash) bool
	connected                func(foundation.Hash) bool
	allowUnknownTransports   bool
	responders               *netdb.ResponderProfiles
	now                      func() uint64
	clockNow                 func() time.Time
	garlicReceiver           *dataplane.RouterGarlicReceiver
	status                   *router.DeliveryStatusMux
	buildReplies             *destinationBuildReplyRegistry
	requests                 *destinationRequestRegistry
	publishers               *destinationPublisherRegistry
	publicationTokens        *netdb.PublicationTokenRegistry
	metrics                  *observability.Registry
	logger                   *slog.Logger
	requestTunnelMaintenance func(*destinationRuntime)
	prepareTunnel            func(context.Context, foundation.Hash) error
	seedRouterInfo           tunnel.RouterInfoSeeder
	awaitControl             func(context.Context) error
}

type destinationRequestPath struct {
	pool       *tunnel.Pool
	tunnels    *dataplane.TunnelRuntime
	maintainer *tunnel.PairedPoolMaintainer
	now        func() uint64
}

func (p destinationRequestPath) Pair(now uint64) (tunnel.CircuitPair, bool) {
	pair, ok := p.maintainer.Pair(now)
	if !ok {
		return pair, false
	}
	for _, id := range [...]uint32{pair.InboundLocalID, pair.OutboundID} {
		entry, found := p.pool.Get(id, now)
		circuit, installed := p.tunnels.InspectCircuit(id)
		if !found || !installed || entry.Owner != p.pool.Owner() || circuit.Owner != entry.Owner || circuit.Token != entry.Circuit {
			return tunnel.CircuitPair{}, false
		}
	}
	return pair, true
}

func (p destinationRequestPath) SendBlock(ctx context.Context, id uint32, block dataplane.TunnelBlock) error {
	entry, found := p.pool.Get(id, p.now())
	if !found || entry.Direction != tunnel.Outbound || entry.Owner != p.pool.Owner() {
		return dataplane.TunnelErrCircuitNotFound
	}
	return p.tunnels.SendBlockPrepared(ctx, entry.Circuit, block)
}

func (f *destinationRuntimeFactory) create(name string, local *foundation.LocalDestination, policy *state.SecureStateEncryptedLeaseSetPolicy, remotePolicies []state.SecureStateRemoteELSAuthorization, requestedCrypto []uint16, requestedTunnels *destination.TunnelPoolConfig) (*destinationRuntime, error) {
	createSelected := f == nil || local == nil || f.database == nil || f.service == nil || f.tunnels == nil || f.destinations == nil || f.replyKeys == nil || f.replySender == nil || f.transport == nil || f.profiles == nil || f.now == nil || f.clockNow == nil || f.garlicReceiver == nil || f.status == nil || f.buildReplies == nil || f.requests == nil
	if !createSelected {
		createSelected = f.publishers == nil
	}
	if createSelected {
		if local != nil {
			local.ReleaseSensitive()
		}
		return nil, ErrDestinationCreation
	}
	releaseDestination := true
	defer func() {
		if releaseDestination {
			local.ReleaseSensitive()
		}
	}()
	tunnelPolicy := destination.TunnelPoolConfig{
		Inbound:     destination.TunnelDirectionConfig{Hops: f.cfg.Tunnel.Hops, Count: f.cfg.Tunnel.ClientInboundTarget},
		Outbound:    destination.TunnelDirectionConfig{Hops: f.cfg.Tunnel.Hops, Count: f.cfg.Tunnel.ClientOutboundTarget},
		RenewBefore: f.cfg.Tunnel.RenewBefore,
	}
	capacity := f.cfg.Tunnel.ClientPoolCapacity
	lifetime := f.cfg.Tunnel.Lifetime
	if requestedTunnels != nil {
		tunnelPolicy = *requestedTunnels
		if err := validateDestinationTunnels(tunnelPolicy); err != nil {
			return nil, err
		}
		capacity = 2 * (tunnelPolicy.Inbound.Count + tunnelPolicy.Inbound.Backup + tunnelPolicy.Outbound.Count + tunnelPolicy.Outbound.Backup)
		lifetime = 10 * time.Minute
	}

	ratchet, err := dataplane.GarlicNewRatchetManager(local, dataplane.GarlicRatchetConfig{Metrics: f.metrics})
	if err != nil {
		return nil, err
	}
	releaseRatchet := true
	defer func() {
		if releaseRatchet {
			ratchet.ReleaseSensitive()
		}
	}()

	owner := local.Hash()
	preferredPeers := append([]foundation.Hash(nil), f.preferredPeers...)
	if len(preferredPeers) > 1 {
		// Spread destination LeaseSet publication across the verified bootstrap
		// responders instead of making every destination target the same
		// floodfill first.
		offset := 1 + int(owner[0])%(len(preferredPeers)-1)
		preferredPeers = append(preferredPeers[offset:], preferredPeers[:offset]...)
	}
	pool := tunnel.NewOwnedPool(owner, capacity)
	var runtime *destinationRuntime
	profiles := f.profiles
	build, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: f.tunnels, Pool: pool, Sender: f.transport, ReplyKeys: f.replyKeys, ReplySender: f.replySender,
		LocalRouter: f.localRouter, StaticPrivate: f.staticPrivate,
		StaticKeyLookup: tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
		Bandwidth: func(tunnel.ShortBuildRequest) uint32 {
			return uint32(f.cfg.Tunnel.BandwidthRateBytesPerSecond / 1024)
		},
		LocalDelivery: func(message foundation.I2NPMessage) error { return f.service.HandleI2NP(message, f.now(), false) },
		Now:           f.now, MaxPending: f.cfg.Tunnel.BuildPendingCapacity, Profiles: profiles, Logger: f.logger, Metrics: f.metrics,
		CreatorBudget: f.creatorBudget,
		OnBuildEvent: func() {
			if runtime != nil {
				runtime.notifyChanged()
				if f.requestTunnelMaintenance != nil {
					f.requestTunnelMaintenance(runtime)
				}
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
	inboundSource, err := tunnel.NewNetDBInboundBuildSource(tunnel.NetDBInboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: tunnelPolicy.Inbound.Hops,
		Lifetime: uint64(lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
		Eligible: f.eligible, Connected: f.connected, AllowUnknownTransports: f.allowUnknownTransports,
	})
	if err != nil {
		return nil, fmt.Errorf("create destination inbound build source: %w", err)
	}
	outboundSource, err := tunnel.NewNetDBOutboundBuildSource(tunnel.NetDBOutboundBuildSourceConfig{
		Table: f.database.Routers(), Profiles: profiles, LocalRouter: f.localRouter, Hops: tunnelPolicy.Outbound.Hops,
		Lifetime: uint64(lifetime.Milliseconds()), CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
		Eligible: f.eligible, Connected: f.connected, AllowUnknownTransports: f.allowUnknownTransports,
	})
	if err != nil {
		return nil, fmt.Errorf("create destination outbound build source: %w", err)
	}
	maintainer, err := tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{
		Pool: pool, Runtime: f.tunnels, Builder: build, InboundSource: inboundSource, OutboundSource: outboundSource,
		Now: f.now, InboundTarget: tunnelPolicy.Inbound.Count, OutboundTarget: tunnelPolicy.Outbound.Count,
		InboundBackup: tunnelPolicy.Inbound.Backup, OutboundBackup: tunnelPolicy.Outbound.Backup,
		RenewBefore: uint64(tunnelPolicy.RenewBefore.Milliseconds()),
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
	requestPath := destinationRequestPath{pool: pool, tunnels: f.tunnels, maintainer: maintainer, now: f.now}
	replyRoute := daemonReplyRoute{maintainer: requestPath, now: f.now}
	requests, err := netdb.NewRequestManager(f.database, muxRequestSender{
		sender: f.transport, tunnels: requestPath, pairs: requestPath, now: f.now, replyKeys: f.replyKeys,
		private:             true,
		staticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
		seedReplyRouterInfo: f.seedRouterInfo,
	}, replyRoute, netdb.RequestManagerConfig{
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

	bandwidth, err := dataplane.RouterNewDestinationBandwidthLimiter(dataplane.RouterDestinationBandwidthConfig{
		RateBytesPerSecond: uint64(rate), BurstBytes: uint64(burst), Now: f.clockNow,
	})
	if err != nil {
		return nil, err
	}
	sender, err := router.NewStreamingTunnelSender(router.StreamingTunnelSenderConfig{
		Owner: owner, PrepareTunnel: f.prepareTunnel, AwaitControl: f.awaitControl,
		Database: f.database, Requests: requests, Ratchet: ratchet, RemoteELS: remoteELS,
		Tunnels: f.tunnels, Pool: pool, SeedRouterInfo: f.seedRouterInfo,
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
	localLeaseSet, err := netdb.NewLocalLeaseSet2WithTypes(local, cryptoTypes)
	if err != nil {
		return nil, err
	}
	publisherConfig := netdb.LeaseSetPublisherConfig{
		Local2: localLeaseSet, Database: f.database, InboundLeases: inboundLeaseSource{pool: pool}, Sender: muxLeaseSetSender{
			sender: f.transport, tunnels: f.tunnels, pairs: maintainer, now: f.now,
			staticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(f.database.Routers()),
			seedReplyRouterInfo: f.seedRouterInfo,
		},
		Discovery: requests, Sign: local.Sign, Now: f.now, Random: randomNonZeroID, FloodfillLimit: netdb.PublicationFloodfillK,
		RepublishBefore: uint64(tunnelPolicy.RenewBefore.Milliseconds()), Registry: f.publicationTokens,
		ReplyPath: daemonReplyRoute{local: f.localRouter, maintainer: maintainer, now: f.now}, PreferredTargets: preferredPeers, Logger: f.logger,
	}
	var encrypted *netdb.LocalEncryptedLeaseSet
	if policy != nil {
		var encryptedErr error
		encrypted, encryptedErr = netdb.NewLocalEncryptedLeaseSet(local, localLeaseSet, netdb.EncryptedLeaseSetAuthorization{DHClients: policy.DHClients, PSKClients: policy.PSKClients}, policy.Secret)
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
	published := &destinationPublisher{publisher: publisher, sender: sender}

	runtime = &destinationRuntime{name: name, local: local, ratchet: ratchet, pool: pool, profiles: profiles, build: build, maintainer: maintainer, health: health, requests: requests, publisher: published, tunnels: f.tunnels, sender: sender, bandwidth: bandwidth, now: f.now}
	runtime.requestPath = requestPath
	runtime.unregister = append(runtime.unregister,
		f.buildReplies.register(build),
		f.requests.register(requests),
		f.status.Register(health),
		f.status.Register(published),
		f.publishers.register(published),
	)
	removeGarlic, registerErr := f.garlicReceiver.RegisterDestination(owner, dataplane.RouterGarlicDestination{Ratchet: ratchet, ReserveRatchetReply: sender.ReserveRatchetReply, Limiter: bandwidth})
	if registerErr != nil {
		runtime.release()
		releaseDestination, releaseRatchet = false, false
		return nil, registerErr
	}
	runtime.unregister = append(runtime.unregister, removeGarlic)
	session, createErr := f.destinations.Create(dataplane.RouterDestinationSessionConfig{
		Streaming: dataplane.StreamingTunnelTunnelNetworkConfig{Destination: local, Sender: sender, HandshakeObserver: sender}, Default: name == "default", Release: runtime.release,
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

func validateDestinationTunnels(policy destination.TunnelPoolConfig) error {
	for _, direction := range [...]destination.TunnelDirectionConfig{policy.Inbound, policy.Outbound} {
		if direction.Hops < 1 || direction.Hops > 7 {
			return tunnel.ErrPairedMaintenanceConfig
		}
		if direction.Count < 1 || direction.Count > 16 {
			return tunnel.ErrPairedMaintenanceConfig
		}
		validBackup := direction.Backup >= 0 && direction.Backup <= 15
		if !validBackup || direction.Count+direction.Backup > 16 {
			return tunnel.ErrPairedMaintenanceConfig
		}
	}
	if policy.RenewBefore < time.Second || policy.RenewBefore >= 10*time.Minute {
		return tunnel.ErrPairedMaintenanceConfig
	}
	return nil
}

// CreateDestination creates and starts a new local destination with the given name and policy.
func (d *Controller) CreateDestination(ctx context.Context, name string, policy DestinationPolicy) (DestinationSummary, error) {
	if d == nil || d.store == nil {
		return DestinationSummary{}, net.ErrClosed
	}
	if err := policy.Validate(); err != nil {
		return DestinationSummary{}, err
	}
	if name == "" || !utf8.ValidString(name) || len(name) > d.config.State.MaxNameBytes {
		return DestinationSummary{}, ErrDestinationName
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return DestinationSummary{}, err
	}

	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	if d.closed || d.destinationFactory == nil {
		d.mu.Unlock()
		return DestinationSummary{}, ErrDestinationCreation
	}
	if d.bundle.DestinationPrivate[name] != nil || d.bundle.Destinations[name].Destination != nil {
		d.mu.Unlock()
		return DestinationSummary{}, ErrDestinationExists
	}
	if len(d.bundle.DestinationPrivate)+len(d.bundle.Destinations) >= d.config.State.MaxDestinations || d.clientRuntimeCount() >= d.config.State.MaxDestinations {
		d.mu.Unlock()
		return DestinationSummary{}, ErrTooManyDestinations
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
		return DestinationSummary{}, err
	}
	encoded, err := destinationPrivate(destination)
	if err != nil {
		destination.ReleaseSensitive()
		return DestinationSummary{}, err
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
		return DestinationSummary{}, err
	}
	d.bundle = next
	d.mu.Unlock()
	clear(encoded)

	runtime, err := d.destinationFactory.create(name, destination, durable, nil, nil, nil)
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
		return DestinationSummary{}, errors.Join(err, rollbackErr)
	}
	runtime.onRelease = d.removeClientRuntime
	d.clientRuntimesMu.Lock()
	d.clientRuntimes = append(d.clientRuntimes, runtime)
	d.clientRuntimesMu.Unlock()
	releaseDestinationPrivate(previous.DestinationPrivate)
	releaseEncryptedLeaseSetPolicies(previous.EncryptedLeaseSetPolicies)
	return DestinationSummary{Name: name, Address: runtime.local.B32(), Default: name == "default"}, nil
}

// DestroyDestination removes a named destination from persistent storage and stops its runtime.
func (d *Controller) DestroyDestination(ctx context.Context, name string) error {
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
		return dataplane.RouterErrDestinationNotFound
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
	_ router.TunnelBuildReplyHandler = (*destinationBuildReplyRegistry)(nil)
	_ router.NetDBRequestHandler     = (*destinationRequestRegistry)(nil)
)
