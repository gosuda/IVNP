// Package daemon composes IVNP's durable state, native router runtime, and local services.
package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/network/reseed"
	"gosuda.org/ivnp/network/router"
	"gosuda.org/ivnp/network/tunnel"
	"gosuda.org/ivnp/protocol/garlic"
	eciesgarlic "gosuda.org/ivnp/protocol/garlic/ecies"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/protocol/netdb"
	"gosuda.org/ivnp/service/addressbook"
	"gosuda.org/ivnp/service/clientapi"
	"gosuda.org/ivnp/service/sam"
	"gosuda.org/ivnp/support/config"
	"gosuda.org/ivnp/support/observability"
	"gosuda.org/ivnp/support/state"
)

var (
	ErrStarted                   = errors.New("daemon: already started")
	ErrProxyWithoutTunnels       = errors.New("daemon: proxies require enabled tunnels")
	ErrTooManyDestinations       = errors.New("daemon: too many destinations")
	ErrDuplicateDestination      = errors.New("daemon: duplicate destination identity")
	ErrPacketListenerUnsupported = errors.New("daemon: packet listener edge not configured")
)

const (
	daemonHealthProbeTimeoutMillis = uint64(time.Minute / time.Millisecond)
	daemonNetDBLookupTimeoutMillis = uint64((30 * time.Second) / time.Millisecond)
	daemonNetDBLookupCandidates    = 32
	daemonNetDBExplorationInterval = 5 * time.Second
)

// Listener owns both local stream and packet listener edges used by
// daemon-managed services.
type Listener interface {
	Listen(context.Context, string, string) (net.Listener, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
}

// ListenerFunc adapts a stream-only listener function. Packet listening fails
// explicitly rather than bypassing the injected edge with a native socket.
type ListenerFunc func(context.Context, string, string) (net.Listener, error)

func (f ListenerFunc) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return f(ctx, network, address)
}
func (ListenerFunc) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, ErrPacketListenerUnsupported
}

type PacketListenerFunc func(context.Context, string, string) (net.PacketConn, error)

type ListenerFuncs struct {
	Stream ListenerFunc
	Packet PacketListenerFunc
}

func (f ListenerFuncs) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if f.Stream == nil {
		return nil, net.ErrClosed
	}
	return f.Stream(ctx, network, address)
}
func (f ListenerFuncs) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if f.Packet == nil {
		return nil, ErrPacketListenerUnsupported
	}
	return f.Packet(ctx, network, address)
}

// NATRuntime owns all injectable NAT discovery and mapping dependencies.
// Implementations must supply a coherent view of routing, interface prefixes,
// and retry timing instead of independent callbacks that can disagree.
type NATRuntime interface {
	NewNATPMP(netip.AddrPort) natPMPClient
	UPnP() upnpClient
	Prefixes() ([]netip.Prefix, error)
	Route(context.Context, string, uint16) (netip.Addr, error)
	RetryInterval() time.Duration
	Wait(context.Context, time.Duration) bool
}

type nativeListener struct{}

func (nativeListener) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, network, address)
}
func (nativeListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

// Options supplies replaceable process edges. New only uses the durable state
// store; all network resources are opened by Start.
type Options struct {
	// SocketRuntime injects native transport sockets for deterministic tests.
	SocketRuntime router.SocketRuntime
	// Transport replaces the native NTCP2/SSU2 mux while preserving Router's
	// production bindings and authenticated Service dispatch.
	Transport     router.TransportManager
	HTTPClient    *http.Client
	Clock         router.Clock
	Logger        *slog.Logger
	Listener      Listener
	NAT           NATRuntime
	PanicReporter ingress.Reporter
}

type slogPanicReporter struct{ logger *slog.Logger }

func (r slogPanicReporter) ReportRecoveredPanic(p ingress.Panic) {
	if r.logger != nil {
		r.logger.Error("contained untrusted ingress panic", "boundary", p.Boundary, "peer", p.Peer, "type", p.ValueType)
	}
}

type metricPanicReporter struct {
	metrics *observability.Registry
	next    ingress.Reporter
}

func (r metricPanicReporter) ReportRecoveredPanic(p ingress.Panic) {
	r.metrics.IncIngressRecoveredPanics()
	if r.next != nil {
		r.next.ReportRecoveredPanic(p)
	}
}

// Status is the daemon-wide lifecycle snapshot.
type Status struct {
	Running bool
	Error   error
	Router  router.Status
}

// destinationRuntime is the complete client-side ownership boundary. Router
// exploratory/transit components are intentionally not retained here.
type destinationRuntime struct {
	name              string
	local             *ivnp.LocalDestination
	ratchet           *garlic.RatchetManager
	pool              *tunnel.Pool
	profiles          *tunnel.PeerProfiles
	build             *tunnel.BuildManager
	maintainer        *tunnel.PairedPoolMaintainer
	health            *tunnel.Health
	requests          *netdb.RequestManager
	publisher         netdb.ConfirmedPublisher
	tunnels           *tunnel.Runtime
	sender            *router.StreamingTunnelSender
	bandwidth         *router.DestinationBandwidthLimiter
	session           *router.DestinationSession
	unregister        []func()
	once              sync.Once
	maintenanceMu     sync.Mutex
	released          atomic.Bool
	onRelease         func(*destinationRuntime)
	now               func() uint64
	maintenanceQueued atomic.Bool
}

func (r *destinationRuntime) release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.maintenanceMu.Lock()
		r.released.Store(true)
		// Cancel and join every destination-owned control-plane owner before
		// removing its reply handlers. Late authenticated replies then observe
		// a closed owner rather than stranded pending state.
		if r.maintainer != nil {
			_ = r.maintainer.Close()
		}
		if r.health != nil {
			_ = r.health.Close()
		}
		if r.requests != nil {
			_ = r.requests.Close()
		}
		if r.build != nil {
			_ = r.build.Close()
		}
		if closer, ok := r.publisher.(interface{ Close() }); ok {
			closer.Close()
		}
		for index := len(r.unregister) - 1; index >= 0; index-- {
			r.unregister[index]()
		}
		r.unregister = nil
		if r.sender != nil {
			r.sender.ReleaseSensitive()
		}
		if r.pool != nil {
			r.pool.Clear()
		}
		if r.tunnels != nil && r.local != nil {
			r.tunnels.RemoveOwner(r.local.Hash())
		}
		if r.ratchet != nil {
			r.ratchet.ReleaseSensitive()
		}
		if r.local != nil {
			r.local.ReleaseSensitive()
		}
		r.maintenanceMu.Unlock()
		if r.onRelease != nil {
			r.onRelease(r)
		}
	})
}

func (r *destinationRuntime) active() bool {
	return r != nil && !r.released.Load()
}

func (r *destinationRuntime) maintain(ctx context.Context, now uint64) error {
	if r == nil {
		return nil
	}
	r.maintenanceMu.Lock()
	defer r.maintenanceMu.Unlock()
	if r.released.Load() {
		return nil
	}
	var result error
	if r.maintainer != nil {
		_, err := r.maintainer.Maintain(ctx)
		result = errors.Join(result, err)
	}
	if r.requests != nil {
		r.requests.Expire(now)
	}
	if r.health != nil {
		_, err := r.health.Expire(ctx)
		result = errors.Join(result, err)
		if err == nil && r.maintainer != nil {
			if pair, ok := r.maintainer.Pair(now); ok && pair.PeerCount != 0 {
				_, err = r.health.Probe(ctx, pair, ivnp.Hash{})
				if !errors.Is(err, tunnel.ErrProbePending) && !errors.Is(err, tunnel.ErrProbeNotReady) {
					result = errors.Join(result, err)
				}
			}
		}
	}
	return result
}

// Daemon owns exactly one embedded router and its local management services.
type Daemon struct {
	config     config.Operating
	store      *state.Store
	stateLock  *state.Lock
	bundle     state.Bundle
	database   *netdb.Database
	netdbStore *netdb.RouterInfoStore
	explorer   *netdb.Explorer
	localInfo  *router.LocalRouterInfo
	router     *router.Router
	registry   *observability.Registry
	logger     *slog.Logger
	clock      router.Clock

	service               *router.Service
	tunnels               *tunnel.Runtime
	pool                  *tunnel.Pool
	profiles              *tunnel.PeerProfiles
	tunnelHealth          *tunnel.Health
	replyKeys             *garlic.ReplyKeyRegistry
	buildManager          *tunnel.BuildManager
	maintainer            *tunnel.PairedPoolMaintainer
	requests              *netdb.RequestManager
	destinations          *router.DestinationManager
	garlicSessions        []*garlic.SessionManager
	garlicReceiver        *router.GarlicReceiver
	statusMux             *router.DeliveryStatusMux
	publication           *router.PublicationMaintenance
	destinationFactory    *destinationRuntimeFactory
	buildReplies          *destinationBuildReplyRegistry
	requestHandlers       *destinationRequestRegistry
	destinationPublishers *destinationPublisherRegistry
	clientRuntimes        []*destinationRuntime
	clientRuntimesMu      sync.RWMutex
	destinationMu         sync.Mutex
	control               *clientapi.Control
	httpProxy             *clientapi.HTTPProxy
	socks5                *clientapi.SOCKS5Proxy
	addressBook           *addressbook.Service
	samServer             *sam.Server
	maintenanceDone       chan struct{}
	explorationDone       chan struct{}
	publicationWake       chan struct{}
	destinationWake       chan *destinationRuntime
	netdbSaveWake         chan struct{}
	metrics               *http.Server
	metricsListener       net.Listener
	listener              Listener
	startReady            chan struct{}

	mu           sync.Mutex
	started      bool
	closed       bool
	ctx          context.Context
	cancel       context.CancelFunc
	err          error
	teardownOnce sync.Once
	teardownErr  error
	wg           sync.WaitGroup
}

// New validates and wires the daemon without opening a network socket. It may
// create the encrypted router state when no state exists yet.
func New(cfg config.Operating, options Options) (*Daemon, error) {
	if cfg.Network.ID > 255 {
		return nil, fmt.Errorf("daemon: network id %d cannot be used by native transports", cfg.Network.ID)
	}
	if cfg.Tunnel.Enabled && cfg.Tunnel.Lifetime != 10*time.Minute {
		return nil, fmt.Errorf("%w: enabled tunnel lifetime must be exactly 10m", config.ErrInvalidOperating)
	}
	if (cfg.HTTPProxy.Enabled || cfg.SOCKS5.Enabled) && !cfg.Tunnel.Enabled {
		return nil, ErrProxyWithoutTunnels
	}
	if (cfg.HTTPProxy.BearerToken != "" || cfg.SOCKS5.BearerToken != "") ||
		(cfg.HTTPProxy.Enabled && !loopbackEndpoint(cfg.HTTPProxy.Address)) ||
		(cfg.SOCKS5.Enabled && !loopbackEndpoint(cfg.SOCKS5.Address)) ||
		(cfg.SAM.Enabled && (!loopbackEndpoint(cfg.SAM.Address) || (cfg.SAM.UDPAddress.Host != "" && !loopbackEndpoint(cfg.SAM.UDPAddress)))) ||
		(cfg.Metrics.Enabled && !loopbackEndpoint(cfg.Metrics.Address) && cfg.Metrics.BearerToken == "") {
		return nil, clientapi.ErrInvalidConfig
	}
	clock := options.Clock
	if clock == nil {
		clock = router.WallClock{}
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	registry := observability.NewRegistry()
	registry.SetBootstrapStage(1)
	sockets := options.SocketRuntime
	if sockets == nil {
		sockets = &router.NativeSocketRuntime{}
	}
	store, err := state.NewStore(cfg.StatePath, cfg.KeyPath)
	reporter := options.PanicReporter
	if reporter == nil {
		reporter = slogPanicReporter{logger: logger}
	}
	reporter = metricPanicReporter{metrics: registry, next: reporter}
	if err != nil {
		return nil, err
	}
	store.MaxStateBytes = int(cfg.State.MaxBytes)
	store.MaxDestinations = cfg.State.MaxDestinations
	store.MaxNameBytes = cfg.State.MaxNameBytes
	stateLock, err := store.AcquireLock()
	if err != nil {
		return nil, err
	}
	keepStateLock := false
	defer func() {
		if !keepStateLock {
			_ = stateLock.Close()
		}
	}()
	bundle, err := store.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	if cfg.Tunnel.Enabled && len(bundle.Destinations)+len(bundle.DestinationPrivate) > 64 {
		return nil, ErrTooManyDestinations
	}
	if cfg.Tunnel.Enabled {
		if bundle.DestinationPrivate == nil {
			bundle.DestinationPrivate = make(map[string][]byte)
		}
		migrated := false
		legacyHashes := make(map[ivnp.Hash]string, len(bundle.Destinations))
		for name, address := range bundle.Destinations {
			if previous, exists := legacyHashes[address.Hash]; exists {
				return nil, fmt.Errorf("%w: %q and %q", ErrDuplicateDestination, previous, name)
			}
			legacyHashes[address.Hash] = name
		}
		for name := range bundle.Destinations {
			local, localErr := ivnp.GenerateLocalDestination()
			if localErr != nil {
				return nil, localErr
			}
			private, privateErr := destinationPrivate(local)
			local.ReleaseSensitive()
			if privateErr != nil {
				return nil, privateErr
			}
			bundle.DestinationPrivate[name] = private
			delete(bundle.Destinations, name)
			migrated = true
		}
		if len(bundle.DestinationPrivate) == 0 {
			local, localErr := ivnp.GenerateLocalDestination()
			if localErr != nil {
				return nil, localErr
			}
			private, privateErr := destinationPrivate(local)
			local.ReleaseSensitive()
			if privateErr != nil {
				return nil, privateErr
			}
			bundle.DestinationPrivate["default"] = private
			migrated = true
		}
		if migrated {
			if saveErr := store.Save(bundle); saveErr != nil {
				return nil, saveErr
			}
		}
	}
	database := netdb.NewDatabase(bundle.Router.Hash, cfg.NetDB.BucketCapacity)
	database.SetMetrics(registry)
	registry.SetNetDBRouters(uint64(database.Routers().Len()))
	netdbStore, err := netdb.NewRouterInfoStore(netdb.RouterInfoStoreConfig{
		Path: filepath.Join(cfg.StateDir, "netdb.routers"), Database: database, NetworkID: cfg.Network.ID,
	})
	if err != nil {
		return nil, err
	}
	if _, loadErr := netdbStore.Load(uint64(clock.Now().UnixMilli())); loadErr != nil {
		logger.Warn("ignoring invalid NetDB router snapshot", "path", netdbStore.Path(), "error", loadErr)
	}
	var bootstrapPeers []ivnp.Hash
	if len(cfg.NetDB.BootstrapRouterInfoPaths) != 0 {
		loadedPeers, loadErr := netdb.LoadStaticRouterInfos(cfg.NetDB.BootstrapRouterInfoPaths, database, uint64(clock.Now().UnixMilli()))
		if loadErr != nil {
			return nil, loadErr
		}
		bootstrapPeers = loadedPeers
		logger.Info("loaded verified static bootstrap RouterInfos", "count", len(bootstrapPeers))
	}
	localInfo, err := router.NewLocalRouterInfo(router.LocalRouterInfoConfig{
		Local: bundle.Router, Database: database, Clock: clock, NetworkID: cfg.Network.ID, Metrics: registry,
		RouterVersion: cfg.Router.Version,
		Options:       routerFamilyOption(cfg.Router.Family),
	})
	if err != nil {
		return nil, err
	}
	staticAddresses, err := newStaticAddressPublisher(cfg, bundle)
	if err != nil {
		return nil, err
	}
	addresses := newNATMappingPublisher(
		staticAddresses,
		automaticTransportConfig(cfg.NTCP2),
		automaticTransportConfig(cfg.SSU2),
		cfg.NAT.NATPMPEndpoint,
		cfg.NAT.UPnPEndpoint,
		localInfo,
		logger,
	)
	if publisher, ok := addresses.(*natMappingPublisher); ok && options.NAT != nil {
		publisher.newNATPMP = options.NAT.NewNATPMP
		publisher.upnp = options.NAT.UPnP()
		publisher.prefixes = options.NAT.Prefixes
		publisher.route = options.NAT.Route
		if retry := options.NAT.RetryInterval(); retry > 0 {
			publisher.retryInterval = retry
		}
		publisher.wait = options.NAT.Wait
	}
	var ntcp router.TransportManager
	if cfg.NTCP2.Enabled {
		ntcp, err = router.NewNTCP2Manager(router.NTCP2ManagerConfig{
			Database: database, StaticPrivate: bundle.NTCP2StaticPrivate, StaticIV: bundle.NTCP2StaticIV,
			NetworkID: uint8(cfg.Network.ID), MaxSessions: cfg.NTCP2.MaxSessions, PanicReporter: reporter, Metrics: registry, Logger: logger,
		})
		if err != nil {
			return nil, err
		}
	}
	var ssu router.TransportManager
	if cfg.SSU2.Enabled {
		ssu, err = router.NewSSU2Manager(router.SSU2ManagerConfig{
			Database: database, StaticPrivate: bundle.SSU2StaticPrivate, IntroKey: bundle.SSU2IntroKey,
			NetworkID: uint8(cfg.Network.ID), IdleTimeout: cfg.SSU2.IdleTimeout, MaxSessions: cfg.SSU2.MaxSessions, PanicReporter: reporter, Metrics: registry, Logger: logger,
			SignControl: func(message []byte) ([]byte, error) { return ed25519.Sign(bundle.Router.SigningPrivate, message), nil },
		})
		if err != nil {
			return nil, err
		}
	}
	var mux router.TransportManager
	if options.Transport != nil {
		mux = options.Transport
	} else {
		mux, err = router.NewTransportMux(router.TransportMuxConfig{Database: database, NTCP2: ntcp, SSU2: ssu})
		if err != nil {
			return nil, err
		}
	}
	now := nowFromClock(clock)
	publicationTokens := netdb.NewPublicationTokenRegistry(now, randomNonZeroID)
	lookupResponder, err := netdb.NewLookupResponder(netdb.LookupResponderConfig{
		Database: database,
		Sender:   daemonReplySender{sender: mux, now: now},
		Local:    bundle.Router.Hash,
		Now:      now,
		Random:   randomNonZeroID,
		Wrapper:  garlic.DatabaseLookupReplyWrapper{MessageID: randomNonZeroID},
	})
	if err != nil {
		return nil, err
	}
	routerPublisher, err := netdb.NewRouterInfoPublisher(netdb.RouterInfoPublisherConfig{
		Local: localInfo, Database: database, Sender: muxLeaseSetSender{sender: mux},
		ReplyPath: daemonReplyRoute{local: bundle.Router.Hash, now: now}, Registry: publicationTokens, Now: now, Random: randomNonZeroID, PreferredTargets: bootstrapPeers, Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	var reseedRunner router.ReseedRunner
	if cfg.Reseed.Enabled {
		httpClient := options.HTTPClient
		if httpClient == nil {
			httpClient = &http.Client{Timeout: cfg.Reseed.Timeout}
		} else if httpClient.Timeout <= 0 {
			copyClient := *httpClient
			copyClient.Timeout = cfg.Reseed.Timeout
			httpClient = &copyClient
		}
		signers, signerErr := reseed.DefaultSU3SignersAt(clock.Now())
		if signerErr != nil {
			return nil, fmt.Errorf("daemon: load pinned reseed signers: %w", signerErr)
		}
		client := &reseed.Client{
			HTTPClient: httpClient, SU3Signers: signers,
			MaxArchiveBytes: cfg.Reseed.MaxArchiveBytes, MaxRouterInfos: cfg.Reseed.MaxRouterInfos, MaxTotalRouterBytes: cfg.Reseed.MaxTotalBytes,
		}
		reseedRunner = client
	}
	service := router.NewService(database)
	var (
		tunnels               *tunnel.Runtime
		pool                  *tunnel.Pool
		profiles              *tunnel.PeerProfiles
		replyKeys             *garlic.ReplyKeyRegistry
		buildManager          *tunnel.BuildManager
		maintainer            *tunnel.PairedPoolMaintainer
		requests              *netdb.RequestManager
		responders            *netdb.ResponderProfiles
		destinations          *router.DestinationManager
		garlicSessions        []*garlic.SessionManager
		garlicReceiver        *router.GarlicReceiver
		health                *tunnel.Health
		explorer              *netdb.Explorer
		statusMux             *router.DeliveryStatusMux
		buildReplies          *destinationBuildReplyRegistry
		requestHandlers       *destinationRequestRegistry
		destinationPublishers *destinationPublisherRegistry
		destinationFactory    *destinationRuntimeFactory
		publication           *router.PublicationMaintenance
		clientRuntimes        []*destinationRuntime
	)
	newOK := false
	defer func() {
		if newOK {
			return
		}
		if destinations != nil {
			_ = destinations.Close()
		}
		for _, sessions := range garlicSessions {
			sessions.Close()
		}
		for _, runtime := range clientRuntimes {
			runtime.release()
		}
		if garlicReceiver != nil {
			garlicReceiver.ReleaseSensitive()
		}
		if buildManager != nil {
			buildManager.ReleaseSensitive()
		}
		bundle.ReleaseSensitive()
	}()
	if cfg.Tunnel.Enabled {
		if len(bundle.DestinationPrivate) > 64 {
			return nil, ErrTooManyDestinations
		}
		seenDestinations := make(map[ivnp.Hash]string, len(bundle.DestinationPrivate))
		for name, encoded := range bundle.DestinationPrivate {
			destination, importErr := ivnp.ImportLocalDestination(encoded)
			if importErr != nil {
				return nil, importErr
			}
			hash := destination.Hash()
			destination.ReleaseSensitive()
			if previous, exists := seenDestinations[hash]; exists {
				return nil, fmt.Errorf("%w: %q and %q", ErrDuplicateDestination, previous, name)
			}
			seenDestinations[hash] = name
		}
	}
	if cfg.Tunnel.Enabled {
		tunnels = tunnel.NewRuntime(tunnel.RuntimeConfig{Sender: mux, Now: now})
		pool = tunnel.NewPool(cfg.Tunnel.PoolCapacity)
		profiles = tunnel.NewPeerProfiles(tunnel.PeerProfilesConfig{})
		responders = netdb.NewResponderProfiles(0)
		for _, peer := range bootstrapPeers {
			responders.Record(peer)
		}
		replyKeys = garlic.NewReplyKeyRegistry(cfg.Tunnel.BuildPendingCapacity * (2*cfg.State.MaxDestinations + 2))
		replySender, replyErr := router.NewBuildReplySender(router.BuildReplySenderConfig{Sender: mux, Service: service, LocalRouter: bundle.Router.Hash, Now: now, NextID: randomMessageID})
		if replyErr != nil {
			return nil, replyErr
		}
		buildManager, err = tunnel.NewBuildManager(tunnel.BuildManagerConfig{
			Runtime: tunnels, Pool: pool, Sender: mux, ReplyKeys: replyKeys, ReplySender: replySender,
			LocalRouter: bundle.Router.Hash, StaticPrivate: bundle.Router.X25519Private[:],
			StaticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(database.Routers()),
			SeedReplyRouterInfo: buildReplyRouterInfoSeeder(database, mux, now),
			Bandwidth:           func(tunnel.ShortBuildRequest) uint32 { return uint32(cfg.Tunnel.BandwidthRateBytesPerSecond / 1024) },
			LocalDelivery:       func(message i2np.Message) error { return service.HandleI2NP(message, now(), false) },
			Now:                 now, MaxPending: cfg.Tunnel.BuildPendingCapacity, Profiles: profiles, Logger: logger, Metrics: registry,
		})
		if err != nil {
			return nil, err
		}
		inboundSource, sourceErr := tunnel.NewNetDBInboundBuildSource(tunnel.NetDBInboundBuildSourceConfig{
			Table: database.Routers(), Profiles: profiles, LocalRouter: bundle.Router.Hash, Hops: cfg.Tunnel.Hops,
			PreferredPeers: bootstrapPeers, Lifetime: uint64(cfg.Tunnel.Lifetime / time.Millisecond),
			CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
		})
		if sourceErr != nil {
			return nil, sourceErr
		}
		outboundSource, sourceErr := tunnel.NewNetDBOutboundBuildSource(tunnel.NetDBOutboundBuildSourceConfig{
			Table: database.Routers(), Profiles: profiles, LocalRouter: bundle.Router.Hash, Hops: cfg.Tunnel.Hops,
			PreferredPeers: bootstrapPeers, Lifetime: uint64(cfg.Tunnel.Lifetime / time.Millisecond),
			CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
		})
		if sourceErr != nil {
			return nil, sourceErr
		}
		maintainer, err = tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{
			Pool: pool, Runtime: tunnels, Builder: buildManager, InboundSource: inboundSource, OutboundSource: outboundSource,
			Now: now, InboundTarget: cfg.Tunnel.InboundTarget, OutboundTarget: cfg.Tunnel.OutboundTarget,
			RenewBefore: uint64(cfg.Tunnel.RenewBefore / time.Millisecond),
		})
		if err != nil {
			return nil, err
		}
		health, err = tunnel.NewHealth(tunnel.HealthConfig{
			Runtime: tunnels, Pool: pool, Maintainer: maintainer, Profiles: profiles, Now: now,
			Timeout: daemonHealthProbeTimeoutMillis, MaxPending: cfg.Tunnel.BuildPendingCapacity,
		})
		if err != nil {
			return nil, err
		}
		replyRoute := daemonReplyRoute{local: bundle.Router.Hash, maintainer: maintainer, now: now}
		requests, err = netdb.NewRequestManager(database, muxRequestSender{
			sender: mux, tunnels: tunnels, pairs: maintainer, now: now, replyKeys: replyKeys,
			staticKeyLookup:     tunnel.NewNetDBBuildStaticKeyLookup(database.Routers()),
			seedReplyRouterInfo: buildReplyRouterInfoSeeder(database, mux, now),
		}, replyRoute, netdb.RequestManagerConfig{
			Capacity: cfg.Tunnel.BuildPendingCapacity, MaxCandidates: daemonNetDBLookupCandidates, MaxWaiters: 64,
			TimeoutMillis: daemonNetDBLookupTimeoutMillis, Now: now, Metrics: registry, Responders: responders,
		})
		if err != nil {
			return nil, err
		}
		explorer, err = netdb.NewExplorer(netdb.ExplorerConfig{Table: database.Routers(), Requests: requests, Now: now})
		if err != nil {
			return nil, err
		}
		destinations = router.NewDestinationManager()
		garlicReceiver, err = router.NewGarlicReceiver(router.GarlicReceiverConfig{
			Service: service, Destinations: nil, ReplyKeys: replyKeys, Now: now, Metrics: registry,
			StaticPrivate: bundle.Router.X25519Private[:],
		})
		if err != nil {
			return nil, err
		}
		statusMux = router.NewDeliveryStatusMux(routerPublisher, health)
		buildReplies = new(destinationBuildReplyRegistry)
		requestHandlers = new(destinationRequestRegistry)
		requestHandlers.register(requests)
		destinationPublishers = new(destinationPublisherRegistry)
		destinationFactory = &destinationRuntimeFactory{
			cfg: cfg, database: database, service: service, tunnels: tunnels, destinations: destinations,
			replyKeys: replyKeys, replySender: replySender, transport: mux,
			localRouter: bundle.Router.Hash, staticPrivate: bundle.Router.X25519Private[:],
			now: now, clockNow: clock.Now, garlicReceiver: garlicReceiver, status: statusMux,
			buildReplies: buildReplies, requests: requestHandlers, publishers: destinationPublishers,
			publicationTokens: publicationTokens,
			preferredPeers:    append([]ivnp.Hash(nil), bootstrapPeers...),
			responders:        responders,
			metrics:           registry,
			logger:            logger,
		}
		for name, encoded := range bundle.DestinationPrivate {
			destination, importErr := ivnp.ImportLocalDestination(encoded)
			if importErr != nil {
				return nil, importErr
			}
			var policy *state.EncryptedLeaseSetPolicy
			if encrypted, ok := bundle.EncryptedLeaseSetPolicies[name]; ok {
				policy = &encrypted
			}
			clientRuntime, createErr := destinationFactory.create(name, destination, policy, bundle.DestinationAddressPolicies[name], nil)
			if createErr != nil {
				return nil, createErr
			}
			clientRuntimes = append(clientRuntimes, clientRuntime)
		}
	}
	var tunnelTest router.DeliveryStatusHandler
	if health != nil {
		tunnelTest = health
	}
	publicationRefresh := uint64(cfg.Tunnel.MaintenanceInterval / time.Millisecond)
	if publicationRefresh == 0 {
		publicationRefresh = uint64(time.Minute / time.Millisecond)
	}
	publication, err = router.NewPublicationMaintenance(router.PublicationMaintenanceConfig{
		RouterInfo: localInfo, NetworkRouterInfo: routerPublisher, LeaseSet: destinationPublishers,
		Now: now, RouterInfoRefresh: publicationRefresh,
	})

	if err != nil {
		return nil, err
	}
	var d *Daemon
	runtime, err := router.New(router.Config{
		NTCP2: ntcp2Endpoint(cfg.NTCP2), SSU2: transportEndpoint(cfg.SSU2, "udp"),
		ReseedEndpoints: append([]string(nil), cfg.Reseed.Endpoints...), RequireReseed: cfg.Reseed.Required,
	}, router.Dependencies{
		Database: database, Service: service, LocalInfo: localInfo, Transport: mux, Sockets: sockets, Addresses: addresses, Reseed: reseedRunner, Clock: clock,
		ReseedOutcome: func(err error) { d.recordReseedOutcome(err) },
		StreamBackend: destinations, Destinations: destinations, Tunnels: tunnels, BuildManager: buildManager,
		ClientBuildReplies: buildReplies, RequestHandler: requestHandlers,
		LookupResponder: lookupResponder, DeliveryStatusMux: statusMux, TunnelTest: tunnelTest, GarlicReceiver: garlicReceiver,
		RouterDelivery: func(target ivnp.Hash, message i2np.Message) error {
			if target == (ivnp.Hash{}) || target == bundle.Router.Hash {
				return router.ErrDataPlaneConfig
			}
			return mux.Send(context.Background(), target, message)
		},
		TunnelDelivery: func(target ivnp.Hash, tunnelID uint32, message i2np.Message) error {
			if target == (ivnp.Hash{}) || tunnelID == 0 {
				return router.ErrDataPlaneConfig
			}
			if target == bundle.Router.Hash {
				if tunnels == nil {
					return router.ErrDataPlaneConfig
				}
				return tunnels.HandleGateway(tunnelID, message)
			}
			frame := make([]byte, message.EncodedLen())
			if _, err := message.MarshalTo(frame); err != nil {
				return err
			}
			payload := make([]byte, i2np.TunnelGatewayHeaderLen+len(frame))
			binary.BigEndian.PutUint32(payload[:4], tunnelID)
			binary.BigEndian.PutUint16(payload[4:6], uint16(len(frame)))
			copy(payload[6:], frame)
			gateway := i2np.Message{Header: i2np.Header{Type: i2np.TunnelGateway, ID: randomNonZeroID(), Expiration: message.Header.Expiration}, Payload: payload}
			return mux.Send(context.Background(), target, gateway)
		},
		DatabaseStoreReply: daemonReplySender{sender: mux, tunnels: tunnels, pool: pool, now: now}.SendStatus,
	})
	if err != nil {
		return nil, err
	}
	listener := options.Listener
	if listener == nil {
		listener = nativeListener{}
	}
	d = &Daemon{
		config: cfg, store: store, stateLock: stateLock, bundle: bundle, database: database, netdbStore: netdbStore, explorer: explorer, localInfo: localInfo, router: runtime, registry: registry, logger: logger, clock: clock, listener: listener,
		service: service, tunnels: tunnels, pool: pool, profiles: profiles, tunnelHealth: health, replyKeys: replyKeys, buildManager: buildManager, maintainer: maintainer, requests: requests, destinations: destinations, garlicSessions: garlicSessions, garlicReceiver: garlicReceiver, statusMux: statusMux, publication: publication,
		destinationFactory: destinationFactory, buildReplies: buildReplies, requestHandlers: requestHandlers, destinationPublishers: destinationPublishers, clientRuntimes: clientRuntimes,
		startReady:      make(chan struct{}),
		destinationWake: make(chan *destinationRuntime, max(1, cfg.State.MaxDestinations)),
		netdbSaveWake:   make(chan struct{}, 1),
	}
	for _, clientRuntime := range d.clientRuntimes {
		clientRuntime.onRelease = d.removeClientRuntime
	}
	if cfg.AddressBook.Enabled {
		d.addressBook, err = addressbook.NewService(addressbook.Config{
			PrivateHostsPath: cfg.AddressBook.PrivateHostsPath, UserHostsPath: cfg.AddressBook.UserHostsPath,
			HostsPath: cfg.AddressBook.HostsPath, StatePath: cfg.AddressBook.StatePath,
			Subscriptions:   append([]string(nil), cfg.AddressBook.Subscriptions...),
			RefreshInterval: cfg.AddressBook.RefreshInterval, RetryInterval: cfg.AddressBook.RetryInterval,
			RequestTimeout: cfg.AddressBook.RequestTimeout, MaxEntries: cfg.AddressBook.MaxEntries,
			MaxFileBytes: cfg.AddressBook.MaxFileBytes, MaxResponseBytes: cfg.AddressBook.MaxResponseBytes,
			MaxRedirects: cfg.AddressBook.MaxRedirects, HTTPClient: options.HTTPClient,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.SAM.Enabled {
		if destinationFactory == nil {
			return nil, router.ErrDefaultDestination
		}
		udpAddress := ""
		if cfg.SAM.UDPAddress.Host != "" {
			udpAddress = cfg.SAM.UDPAddress.String()
		}
		d.samServer, err = sam.NewServer(sam.ServerConfig{
			Address: cfg.SAM.Address.String(), UDPAddress: udpAddress, Listen: sam.ListenFunc(listener.Listen),
			ListenPacket: sam.ListenPacketFunc(listener.ListenPacket), Controller: d.DestinationController(), Resolver: d.addressBook,
			PanicReporter: reporter, Metrics: registry, MaxConnections: cfg.SAM.MaxConnections,
			MaxSessions: cfg.State.MaxDestinations, ReadinessTimeout: cfg.SAM.ReadinessTimeout, SessionQueue: cfg.SAM.SessionQueue,
			MaxSessionQueueBytes: cfg.SAM.MaxSessionQueueBytes, MaxServerQueueBytes: cfg.SAM.MaxServerQueueBytes, AllowLoopbackForward: true,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.Control.Enabled {
		d.control, err = clientapi.NewControl(clientapi.ControlConfig{
			ListenAddress: cfg.Control.Address.String(), AllowRemote: true, BearerToken: cfg.Control.BearerToken, MaxConnections: cfg.Control.MaxConnections,
			Status: d, Catalog: d, Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.HTTPProxy.Enabled {
		if destinations == nil {
			return nil, router.ErrDefaultDestination
		}
		d.httpProxy, err = clientapi.NewHTTPProxy(clientapi.HTTPProxyConfig{
			Network: destinations, Resolver: d.addressBook,
			ListenAddress: cfg.HTTPProxy.Address.String(), MaxConnections: cfg.HTTPProxy.MaxConnections,
			Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.SOCKS5.Enabled {
		if destinations == nil {
			return nil, router.ErrDefaultDestination
		}
		d.socks5, err = clientapi.NewSOCKS5Proxy(clientapi.SOCKS5Config{
			Network: destinations, ListenAddress: cfg.SOCKS5.Address.String(), MaxConnections: cfg.SOCKS5.MaxConnections,
			Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
	}
	newOK = true
	keepStateLock = true
	return d, nil
}

func routerFamilyOption(family string) []router.MappingOption {
	if family == "" {
		return nil
	}
	return []router.MappingOption{{Key: "family", Value: family}}
}

func transportEndpoint(transport config.Transport, network string) router.Endpoint {
	if !transport.Enabled {
		return router.Endpoint{}
	}
	return router.Endpoint{Network: network, Address: transport.Bind.String()}
}

func ntcp2Endpoint(transport config.Transport) router.Endpoint {
	if transport.Advertised.Port == 0 && loopbackEndpoint(transport.Bind) {
		return router.Endpoint{}
	}
	return transportEndpoint(transport, "tcp")
}

func loopbackEndpoint(endpoint config.Endpoint) bool {
	if endpoint.Host == "localhost" {
		return true
	}
	address := net.ParseIP(endpoint.Host)
	return address != nil && address.IsLoopback()
}

// Start starts the router before opening management listeners. A failed later
// listener is rolled back so callers never observe a partially started daemon.
func (d *Daemon) Start(parent context.Context) error {
	if d == nil {
		return net.ErrClosed
	}
	if parent == nil {
		parent = context.Background()
	}
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return ErrStarted
	}
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.started = true
	d.ctx, d.cancel = context.WithCancel(parent)
	ready := d.startReady
	d.mu.Unlock()
	defer close(ready)
	if err := d.router.Start(d.ctx); err != nil {
		d.failStart(err)
		return err
	}
	if err := d.startAllowed(); err != nil {
		d.failStart(err)
		return err
	}
	if d.addressBook != nil {
		if err := d.addressBook.Start(d.ctx); err != nil {
			d.failStart(err)
			return err
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.recordError(d.addressBook.Wait()) }()
	}
	if d.samServer != nil {
		if err := d.samServer.Start(d.ctx); err != nil {
			d.failStart(err)
			return err
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.recordError(d.samServer.Wait()) }()
	}
	if d.config.Metrics.Enabled {
		listener, err := d.listener.Listen(d.ctx, "tcp", d.config.Metrics.Address.String())
		if err != nil {
			d.failStart(err)
			return err
		}
		if err := d.startAllowed(); err != nil {
			_ = listener.Close()
			d.failStart(err)
			return err
		}
		maxConnections := d.config.Metrics.MaxConnections
		if maxConnections < 1 {
			maxConnections = 64
		}
		d.metricsListener = clientapi.NewConnectionLimitedListener(listener, maxConnections)
		handler := observability.NewHandler(d.registry, d.health)
		if d.config.Metrics.BearerToken != "" {
			handler = observability.RequireBearer(handler, d.config.Metrics.BearerToken)
		}
		d.metrics = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			if err := d.metrics.Serve(d.metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				d.recordError(err)
			}
		}()
	}
	if d.control != nil {
		if err := d.startAllowed(); err != nil {
			d.failStart(err)
			return err
		}
		if err := d.control.Start(d.ctx); err != nil {
			d.failStart(err)
			return err
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.recordError(d.control.Wait()) }()
	}
	if d.httpProxy != nil {
		if err := d.startAllowed(); err != nil {
			d.failStart(err)
			return err
		}
		if err := d.httpProxy.Start(d.ctx); err != nil {
			d.failStart(err)
			return err
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.recordError(d.httpProxy.Wait()) }()
	}
	if d.socks5 != nil {
		if err := d.startAllowed(); err != nil {
			d.failStart(err)
			return err
		}
		if err := d.socks5.Start(d.ctx); err != nil {
			d.failStart(err)
			return err
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.recordError(d.socks5.Wait()) }()
	}
	if err := d.startAllowed(); err != nil {
		d.failStart(err)
		return err
	}
	d.registry.IncLifecycleStarts()
	d.registry.SetLifecycleRunning(1)
	d.registry.SetBootstrapStage(2)
	d.refreshObservability()
	d.startMaintenance()
	select {
	case d.publicationWake <- struct{}{}:
	default:
	}
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.recordError(d.router.Wait()); _ = d.Close() }()
	return nil
}

func (d *Daemon) startAllowed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if d.ctx == nil {
		return net.ErrClosed
	}
	return d.ctx.Err()
}

func (d *Daemon) failStart(err error) {
	d.recordError(err)
	d.beginClose()
	_ = d.teardown()
}

func (d *Daemon) startMaintenance() {
	interval := d.config.Tunnel.MaintenanceInterval
	if interval <= 0 {
		interval = time.Minute
	}
	d.maintenanceDone = make(chan struct{})
	d.publicationWake = make(chan struct{}, 1)
	destinationWorkers := parallelism.Workers(max(1, d.config.State.MaxDestinations))
	d.wg.Add(4 + destinationWorkers)
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-d.publicationWake:
				publicationContext, cancel := context.WithTimeout(d.ctx, 30*time.Second)
				if d.publication != nil {
					if _, err := d.publication.Maintain(publicationContext); err != nil && d.ctx.Err() == nil {
						if errors.Is(err, context.DeadlineExceeded) {
							d.logger.Debug("bounded publication maintenance timed out", "error", err)
						} else {
							d.recordMaintenanceError(err)
						}
					}
				} else if err := d.localInfo.Publish(publicationContext); err != nil && d.ctx.Err() == nil {
					if errors.Is(err, context.DeadlineExceeded) {
						d.logger.Debug("bounded local publication timed out", "error", err)
					} else {
						d.recordMaintenanceError(err)
					}
				}
				cancel()
			}
		}
	}()
	go func() {
		defer d.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-ticker.C:
				d.refreshObservability()
			}
		}
	}()
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-d.netdbSaveWake:
				if d.netdbStore != nil {
					if err := d.netdbStore.Save(); err != nil && d.ctx.Err() == nil {
						d.recordMaintenanceError(err)
					}
				}
			}
		}
	}()
	if d.explorer != nil {
		d.explorationDone = make(chan struct{})
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer close(d.explorationDone)
			ticker := time.NewTicker(daemonNetDBExplorationInterval)
			defer ticker.Stop()
			for {
				now := uint64(d.clock.Now().UnixMilli())
				if d.requests != nil {
					d.requests.Expire(now)
				}
				if err := d.explorer.Maintain(d.ctx); err != nil && d.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
					d.recordMaintenanceError(err)
				}
				select {
				case <-d.ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	for range destinationWorkers {
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-d.ctx.Done():
					return
				case runtime := <-d.destinationWake:
					if runtime == nil {
						continue
					}
					var maintenanceErr, publicationErr error
					var publicationTask sync.WaitGroup
					if runtime.publisher != nil {
						publicationTask.Add(1)
						go func() {
							defer publicationTask.Done()
							publicationContext, publicationCancel := context.WithTimeout(d.ctx, 30*time.Second)
							_, publicationErr = runtime.publisher.Maintain(publicationContext)
							publicationCancel()
						}()
					}
					maintenanceContext, maintenanceCancel := context.WithTimeout(d.ctx, 30*time.Second)
					maintenanceErr = runtime.maintain(maintenanceContext, uint64(d.clock.Now().UnixMilli()))
					maintenanceCancel()
					publicationTask.Wait()
					err := errors.Join(maintenanceErr, publicationErr)
					runtime.maintenanceQueued.Store(false)
					if err != nil && d.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						d.recordMaintenanceError(err)
					}
				}
			}
		}()
	}
	go func() {
		defer d.wg.Done()
		defer close(d.maintenanceDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-ticker.C:
				now := uint64(d.clock.Now().UnixMilli())
				d.database.ExpireLeases(now)
				if now > netdb.ReseedRouterInfoMaxAgeMillis {
					d.database.Routers().Expire(now - netdb.ReseedRouterInfoMaxAgeMillis)
				}
				d.router.MaintainReseed(d.ctx)
				if d.maintainer != nil {
					if _, err := d.maintainer.Maintain(d.ctx); err != nil && d.ctx.Err() == nil {
						d.recordMaintenanceError(err)
					}
				}
				for _, runtime := range d.clientRuntimeSnapshot() {
					d.requestDestinationMaintenance(runtime)
				}
				if d.tunnelHealth != nil {
					if _, err := d.tunnelHealth.Expire(d.ctx); err != nil && d.ctx.Err() == nil {
						d.recordMaintenanceError(err)
					}
					if d.maintainer != nil {
						if pair, ok := d.maintainer.Pair(now); ok && pair.PeerCount != 0 {
							if _, err := d.tunnelHealth.Probe(d.ctx, pair, ivnp.Hash{}); err != nil && !errors.Is(err, tunnel.ErrProbePending) && !errors.Is(err, tunnel.ErrProbeNotReady) && d.ctx.Err() == nil {
								d.recordMaintenanceError(err)
							}
						}
					}
				}
				if d.replyKeys != nil {
					d.replyKeys.Expire(now)
				}
				expireWorkers := parallelism.Workers(len(d.garlicSessions))
				expireJobs := make(chan *garlic.SessionManager)
				var expireSessions sync.WaitGroup
				expireSessions.Add(expireWorkers)
				for range expireWorkers {
					go func() {
						defer expireSessions.Done()
						for sessions := range expireJobs {
							sessions.Expire(now)
						}
					}()
				}
				for _, sessions := range d.garlicSessions {
					expireJobs <- sessions
				}
				close(expireJobs)
				expireSessions.Wait()
				select {
				case d.publicationWake <- struct{}{}:
				default:
				}
				if d.netdbStore != nil {
					select {
					case d.netdbSaveWake <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	for _, runtime := range d.clientRuntimeSnapshot() {
		d.requestDestinationMaintenance(runtime)
	}
}

func (d *Daemon) requestDestinationMaintenance(runtime *destinationRuntime) {
	if d == nil || runtime == nil || !runtime.active() || d.destinationWake == nil || !runtime.maintenanceQueued.CompareAndSwap(false, true) {
		return
	}
	select {
	case d.destinationWake <- runtime:
	default:
		runtime.maintenanceQueued.Store(false)
	}
}

func (d *Daemon) refreshObservability() {
	if d == nil || d.registry == nil {
		return
	}
	routers := uint64(d.database.Routers().Len())
	d.registry.SetNetDBRouters(routers)
	if d.localInfo.Reachability() == router.ReachabilityReachable {
		d.registry.SetRouterReachable(1)
	} else {
		d.registry.SetRouterReachable(0)
	}
	if d.pool != nil {
		now := uint64(d.clock.Now().UnixMilli())
		exploratoryInbound := uint64(d.pool.Count(tunnel.Inbound, now))
		exploratoryOutbound := uint64(d.pool.Count(tunnel.Outbound, now))
		var clientInbound, clientOutbound uint64
		for _, runtime := range d.clientRuntimeSnapshot() {
			if runtime == nil || runtime.released.Load() || runtime.pool == nil {
				continue
			}
			clientInbound += uint64(runtime.pool.Count(tunnel.Inbound, now))
			clientOutbound += uint64(runtime.pool.Count(tunnel.Outbound, now))
		}
		d.registry.SetTunnelExploratoryInboundActive(exploratoryInbound)
		d.registry.SetTunnelExploratoryOutboundActive(exploratoryOutbound)
		d.registry.SetTunnelClientInboundActive(clientInbound)
		d.registry.SetTunnelClientOutboundActive(clientOutbound)
		d.registry.SetTunnelActive(exploratoryInbound + exploratoryOutbound + clientInbound + clientOutbound)
	}
	snapshot := d.registry.Snapshot()
	stage := snapshot.Bootstrap.Stage
	if stage < 3 &&
		routers >= 50 &&
		snapshot.Publication.RouterInfoSuccesses != 0 &&
		snapshot.Publication.LeaseSet2Successes != 0 &&
		snapshot.Tunnel.ExploratoryInboundActive != 0 &&
		snapshot.Tunnel.ExploratoryOutboundActive != 0 &&
		snapshot.Tunnel.ClientInboundActive != 0 &&
		snapshot.Tunnel.ClientOutboundActive != 0 &&
		snapshot.SSU2.VectorIOEnabled != 0 &&
		snapshot.SSU2.KernelDropAccounting != 0 {
		stage = 3
	}
	if stage == 3 &&
		snapshot.Publication.RouterInfoSuccesses != 0 &&
		snapshot.Publication.LeaseSet2Successes != 0 &&
		snapshot.Tunnel.ExploratoryInboundActive != 0 &&
		snapshot.Tunnel.ExploratoryOutboundActive != 0 &&
		snapshot.Tunnel.ClientInboundActive != 0 &&
		snapshot.Tunnel.ClientOutboundActive != 0 &&
		snapshot.SSU2.VectorIOEnabled != 0 &&
		snapshot.SSU2.KernelDropAccounting != 0 &&
		snapshot.Bootstrap.RouterReachable != 0 {
		stage = 4
	}
	d.registry.SetBootstrapStage(stage)
}

func (d *Daemon) recordMaintenanceError(err error) {
	if errors.Is(err, tunnel.ErrNoEligiblePeers) {
		d.registry.IncTunnelBuildFailures()
		d.logger.Debug("tunnel bootstrap waiting for eligible peers", "error", err)
		return
	}
	if router.IsRetryableTransportError(err) {
		d.registry.IncTunnelBuildFailures()
		d.logger.Debug("tunnel bootstrap transport attempt failed", "error", err)
		return
	}
	if errors.Is(err, netdb.ErrNoFloodfill) {
		d.registry.IncNetDBLookupFailures()
		d.logger.Debug("netdb publication waiting for floodfill", "error", err)
		return
	}
	d.recordError(err)
}

func (d *Daemon) recordReseedOutcome(err error) {
	d.registry.IncReseedAttempts()
	if err == nil {
		d.registry.IncReseedSuccesses()
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	d.registry.IncReseedFailures()
	d.logger.Warn("reseed failed", "error", err)
}

// Close cancels startup before waiting for its registration phase, then releases
// local management resources before router sockets.
func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	started, ready := d.beginClose()
	if started {
		<-ready
	}
	return d.teardown()
}

func (d *Daemon) beginClose() (bool, <-chan struct{}) {
	// Serialize the closed transition with destination creation, destruction,
	// and address-policy replacement. Once beginClose returns, no policy Save
	// can race runtime sensitive release or the final bundle persistence.
	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()
	d.mu.Lock()
	d.closed = true
	if d.cancel != nil {
		d.cancel()
	}
	started, ready := d.started, d.startReady
	d.mu.Unlock()
	return started, ready
}

func (d *Daemon) teardown() error {
	d.teardownOnce.Do(func() {
		var result error
		if d.samServer != nil {
			result = errors.Join(result, d.samServer.Close())
		}
		if d.addressBook != nil {
			result = errors.Join(result, d.addressBook.Close())
		}
		if d.httpProxy != nil {
			result = errors.Join(result, d.httpProxy.Close())
		}
		if d.socks5 != nil {
			result = errors.Join(result, d.socks5.Close())
		}
		if d.control != nil {
			result = errors.Join(result, d.control.Close())
		}
		if d.metrics != nil {
			result = errors.Join(result, d.metrics.Close())
		} else if d.metricsListener != nil {
			result = errors.Join(result, d.metricsListener.Close())
		}
		if d.destinations != nil {
			result = errors.Join(result, d.destinations.Close())
		}
		for _, sessions := range d.garlicSessions {
			sessions.Close()
		}
		for _, runtime := range d.clientRuntimeSnapshot() {
			runtime.release()
		}
		result = errors.Join(result, d.router.Close())
		if d.maintenanceDone != nil {
			<-d.maintenanceDone
		}
		if d.explorationDone != nil {
			<-d.explorationDone
		}
		if d.garlicReceiver != nil {
			d.garlicReceiver.ReleaseSensitive()
		}
		if d.buildManager != nil {
			d.buildManager.ReleaseSensitive()
		}
		if d.explorer != nil {
			d.explorer.Close()
		}
		if d.netdbStore != nil {
			result = errors.Join(result, d.netdbStore.Save())
		}
		if d.store != nil {
			result = errors.Join(result, d.store.Save(d.bundle))
		}
		d.bundle.ReleaseSensitive()
		if d.stateLock != nil {
			result = errors.Join(result, d.stateLock.Close())
		}
		d.registry.IncLifecycleStops()
		d.registry.SetLifecycleRunning(0)
		d.teardownErr = result
	})
	return d.teardownErr
}

// Wait blocks for every daemon-owned worker and reports the first error.
func (d *Daemon) Wait() error {
	if d == nil {
		return net.ErrClosed
	}
	d.mu.Lock()
	started, ready := d.started, d.startReady
	d.mu.Unlock()
	if !started {
		return nil
	}
	<-ready
	d.wg.Wait()
	d.mu.Lock()
	err := d.err
	d.mu.Unlock()
	return err
}

func (d *Daemon) recordError(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	d.mu.Lock()
	if d.err == nil {
		d.err = err
		d.registry.IncLifecycleFailures()
		d.logger.Error("daemon lifecycle error", "error", err)
	}
	d.mu.Unlock()
}

func (d *Daemon) health(context.Context) observability.HealthStatus {
	if d != nil && d.router.Running() {
		return observability.HealthOK
	}
	return observability.HealthUnavailable
}

// Status returns the daemon and router lifecycle state.
func (d *Daemon) Status() Status {
	if d == nil {
		return Status{}
	}
	d.mu.Lock()
	running, err := d.started && !d.closed && d.router.Running(), d.err
	d.mu.Unlock()
	return Status{Running: running, Error: err, Router: d.router.Status()}
}

// ClientStatus adapts authoritative readiness evidence to the authenticated
// control API.
func (d *Daemon) ClientStatus(context.Context) (clientapi.Status, error) {
	status := d.Status()
	d.refreshObservability()
	snapshot := d.registry.Snapshot()
	routerHash := d.localInfo.Hash()
	readiness := clientapi.ReadinessDetails{
		BootstrapStage:             snapshot.Bootstrap.Stage,
		NetDBRouters:               snapshot.NetDB.Routers,
		RouterInfoPublications:     snapshot.Publication.RouterInfoSuccesses,
		LeaseSet2Publications:      snapshot.Publication.LeaseSet2Successes,
		ExploratoryInboundTunnels:  snapshot.Tunnel.ExploratoryInboundActive,
		ExploratoryOutboundTunnels: snapshot.Tunnel.ExploratoryOutboundActive,
		ClientInboundTunnels:       snapshot.Tunnel.ClientInboundActive,
		ClientOutboundTunnels:      snapshot.Tunnel.ClientOutboundActive,
		RouterReachable:            snapshot.Bootstrap.RouterReachable != 0,
		SSU2VectorIO:               snapshot.SSU2.VectorIOEnabled != 0,
		SSU2KernelDropAccounting:   snapshot.SSU2.KernelDropAccounting != 0,
		ProcessGoroutines:          snapshot.Process.Goroutines,
		ProcessHeapInuseBytes:      snapshot.Process.HeapInuseBytes,
		ProcessHeapObjects:         snapshot.Process.HeapObjects,
	}
	return clientapi.Status{
		Ready:      status.Running && snapshot.Bootstrap.Stage >= 4,
		State:      routerStateString(status.Router.State),
		RouterHash: ivnp.EncodeI2PBase64(routerHash[:]),
		Readiness:  readiness,
	}, status.Error
}

func routerStateString(state router.State) string {
	switch state {
	case router.StateNew:
		return "new"
	case router.StateStarting:
		return "starting"
	case router.StateRunning:
		return "running"
	case router.StateStopping:
		return "stopping"
	case router.StateStopped:
		return "stopped"
	case router.StateFailed:
		return "failed"
	}
	return "unknown"
}

// ListDestinations reports durable ECIES local destination names.
func (d *Daemon) ListDestinations(context.Context) ([]clientapi.Destination, error) {
	if d == nil {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	private := make(map[string][]byte, len(d.bundle.DestinationPrivate))
	for name, encoded := range d.bundle.DestinationPrivate {
		private[name] = append([]byte(nil), encoded...)
	}
	d.mu.Unlock()
	items := make([]clientapi.Destination, 0, len(private))
	for name, encoded := range private {
		destination, err := ivnp.ImportLocalDestination(encoded)
		clear(encoded)
		if err != nil {
			return nil, err
		}
		items = append(items, clientapi.Destination{Name: name, Address: destination.B32(), Default: name == "default"})
		destination.ReleaseSensitive()
	}
	return items, nil
}

// UpdateDestinationAddressPolicies persists one local destination's remote
// ELS2 authorization policies and atomically applies them to its sender. An
// empty set removes all encrypted-only remote address policies for that local
// destination.
func (d *Daemon) UpdateDestinationAddressPolicies(name string, policies []state.RemoteELSAuthorization) error {
	if d == nil || d.store == nil {
		return net.ErrClosed
	}
	d.destinationMu.Lock()
	defer d.destinationMu.Unlock()

	contexts, err := remoteELSContexts(policies)
	if err != nil {
		return err
	}
	defer releaseRemoteELSContexts(contexts)
	if err = router.ValidateRemoteELSContexts(contexts); err != nil {
		return err
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	if d.bundle.DestinationPrivate[name] == nil && d.bundle.Destinations[name].Destination == nil {
		d.mu.Unlock()
		return router.ErrDestinationNotFound
	}
	previous := d.bundle
	next := d.bundle
	next.DestinationAddressPolicies = cloneDestinationAddressPolicies(previous.DestinationAddressPolicies)
	releaseRemoteELSAuthorizations(next.DestinationAddressPolicies[name])
	if len(policies) == 0 {
		delete(next.DestinationAddressPolicies, name)
	} else {
		next.DestinationAddressPolicies[name] = cloneRemoteELSAuthorizations(policies)
	}
	d.mu.Unlock()

	committed := false
	defer func() {
		if !committed {
			releaseDestinationAddressPolicies(next.DestinationAddressPolicies)
		}
	}()

	var active *destinationRuntime
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.name == name && runtime.active() && runtime.sender != nil {
			active = runtime
			break
		}
	}
	var previousContexts map[ivnp.Hash]router.RemoteELSContext
	if active != nil {
		previousContexts, err = remoteELSContexts(previous.DestinationAddressPolicies[name])
		if err != nil {
			return err
		}
		defer releaseRemoteELSContexts(previousContexts)
		if err = active.sender.UpdateRemoteELS(contexts); err != nil {
			return err
		}
	}

	if err = d.store.Save(next); err != nil {
		if active != nil {
			err = errors.Join(err, active.sender.UpdateRemoteELS(previousContexts))
		}
		return err
	}

	d.mu.Lock()
	d.bundle = next
	d.mu.Unlock()
	committed = true
	// The replacement map is a deep clone, so every superseded in-memory
	// credential can be wiped without touching the newly committed bundle.
	releaseDestinationAddressPolicies(previous.DestinationAddressPolicies)
	return nil
}

func remoteELSContexts(policies []state.RemoteELSAuthorization) (map[ivnp.Hash]router.RemoteELSContext, error) {
	contexts := make(map[ivnp.Hash]router.RemoteELSContext, len(policies))
	for _, policy := range policies {
		identity, consumed, err := ivnp.ParseIdentity(policy.Identity)
		if err != nil || consumed != len(policy.Identity) {
			releaseRemoteELSContexts(contexts)
			return nil, router.ErrDataPlaneConfig
		}
		context := router.RemoteELSContext{Identity: identity, Secret: append([]byte(nil), policy.Secret...)}
		switch policy.Kind {
		case state.RemoteELSAuthorizationNone:
		case state.RemoteELSAuthorizationDH:
			context.Authorization = netdb.ELSClientAuthorization{UseDH: true, DHPrivate: policy.DHPrivate, DHPublic: policy.DHPublic}
		case state.RemoteELSAuthorizationPSK:
			context.Authorization = netdb.ELSClientAuthorization{UsePSK: true, PSK: policy.PSK}
		default:
			releaseRemoteELSContext(&context)
			releaseRemoteELSContexts(contexts)
			return nil, router.ErrDataPlaneConfig
		}
		hash := identity.Hash()
		if _, exists := contexts[hash]; exists {
			releaseRemoteELSContext(&context)
			releaseRemoteELSContexts(contexts)
			return nil, router.ErrDataPlaneConfig
		}
		contexts[hash] = context
	}
	return contexts, nil
}

func releaseRemoteELSContext(context *router.RemoteELSContext) {
	if context == nil {
		return
	}
	clear(context.Secret)
	clear(context.Authorization.DHPrivate[:])
	clear(context.Authorization.DHPublic[:])
	clear(context.Authorization.PSK[:])
	*context = router.RemoteELSContext{}
}

func releaseRemoteELSContexts(contexts map[ivnp.Hash]router.RemoteELSContext) {
	for hash, context := range contexts {
		releaseRemoteELSContext(&context)
		contexts[hash] = context
		delete(contexts, hash)
	}
}

func cloneDestinationAddressPolicies(source map[string][]state.RemoteELSAuthorization) map[string][]state.RemoteELSAuthorization {
	cloned := make(map[string][]state.RemoteELSAuthorization, len(source))
	for name, policies := range source {
		cloned[name] = cloneRemoteELSAuthorizations(policies)
	}
	return cloned
}

func cloneRemoteELSAuthorizations(source []state.RemoteELSAuthorization) []state.RemoteELSAuthorization {
	cloned := make([]state.RemoteELSAuthorization, len(source))
	for index, policy := range source {
		cloned[index] = policy
		cloned[index].Identity = append([]byte(nil), policy.Identity...)
		cloned[index].Secret = append([]byte(nil), policy.Secret...)
	}
	return cloned
}

func releaseRemoteELSAuthorizations(policies []state.RemoteELSAuthorization) {
	for index := range policies {
		clear(policies[index].Identity)
		clear(policies[index].Secret)
		clear(policies[index].DHPrivate[:])
		clear(policies[index].DHPublic[:])
		clear(policies[index].PSK[:])
		policies[index] = state.RemoteELSAuthorization{}
	}
	clear(policies)
}

func releaseDestinationAddressPolicies(policies map[string][]state.RemoteELSAuthorization) {
	for name, entries := range policies {
		releaseRemoteELSAuthorizations(entries)
		delete(policies, name)
	}
}

// DestinationBandwidthSnapshot returns non-sensitive pacing counters for one
// active local destination.
func (d *Daemon) DestinationBandwidthSnapshot(name string) (router.DestinationBandwidthSnapshot, bool) {
	if d == nil || name == "" {
		return router.DestinationBandwidthSnapshot{}, false
	}
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.name == name && runtime.active() && runtime.bandwidth != nil {
			return runtime.bandwidth.Snapshot(), true
		}
	}
	return router.DestinationBandwidthSnapshot{}, false
}

func (d *Daemon) clientRuntimeSnapshot() []*destinationRuntime {
	d.clientRuntimesMu.RLock()
	snapshot := append([]*destinationRuntime(nil), d.clientRuntimes...)
	d.clientRuntimesMu.RUnlock()
	return snapshot
}

func (d *Daemon) removeClientRuntime(target *destinationRuntime) {
	if d == nil || target == nil {
		return
	}
	d.clientRuntimesMu.Lock()
	for index, runtime := range d.clientRuntimes {
		if runtime == target {
			copy(d.clientRuntimes[index:], d.clientRuntimes[index+1:])
			d.clientRuntimes[len(d.clientRuntimes)-1] = nil
			d.clientRuntimes = d.clientRuntimes[:len(d.clientRuntimes)-1]
			break
		}
	}
	d.clientRuntimesMu.Unlock()
}

type requestTunnelSender interface {
	SendBlock(context.Context, uint32, tunnel.Block) error
}

type requestPairSource interface {
	Pair(uint64) (tunnel.CircuitPair, bool)
}

type muxRequestSender struct {
	sender              tunnel.Sender
	tunnels             requestTunnelSender
	pairs               requestPairSource
	now                 func() uint64
	replyKeys           *garlic.ReplyKeyRegistry
	staticKeyLookup     tunnel.BuildStaticKeyLookup
	seedReplyRouterInfo tunnel.ReplyRouterInfoSeeder
}

func (s muxRequestSender) Send(ctx context.Context, peer netdb.RouterRef, message i2np.Message) error {
	if message.Header.Type != i2np.DatabaseLookup {
		return s.sender.Send(ctx, peer.Hash, message)
	}
	lookup, err := i2np.ParseDatabaseLookup(message.Payload)
	if err != nil {
		return err
	}
	if s.seedReplyRouterInfo != nil && lookup.ReplyThroughTunnel() {
		if err = s.seedReplyRouterInfo(ctx, peer.Hash, lookup.From); err != nil {
			return err
		}
	}
	var replyTag [8]byte
	registered := false
	if lookup.LookupType() == uint8(netdb.LeaseSetLookup) && lookup.ReplyThroughTunnel() && !lookup.ReplyEncrypted() && s.replyKeys != nil {
		var replyKey tunnel.GarlicReplyKey
		if _, err = cryptorand.Read(replyKey.Key[:]); err != nil {
			return err
		}
		defer clear(replyKey.Key[:])
		if _, err = cryptorand.Read(replyKey.Tag[:]); err != nil {
			return err
		}
		replyKey.ExpiresAt = message.Header.Expiration
		if err = s.replyKeys.RegisterGarlicReplyKey(replyKey); err != nil {
			return err
		}
		replyTag, registered = replyKey.Tag, true
		payload := make([]byte, len(message.Payload)+32+1+8)
		copy(payload, message.Payload)
		payload[64] |= 1 << 4
		copy(payload[len(message.Payload):], replyKey.Key[:])
		payload[len(message.Payload)+32] = 1
		copy(payload[len(message.Payload)+33:], replyKey.Tag[:])
		message.Payload = payload
	}
	err = sendNetDBThroughPair(ctx, peer, message, s.sender, s.tunnels, s.pairs, s.now, s.staticKeyLookup, s.seedReplyRouterInfo)
	if err != nil && registered {
		s.replyKeys.RemoveGarlicReplyKey(replyTag)
	}
	return err
}

type muxLeaseSetSender struct {
	sender              tunnel.Sender
	tunnels             requestTunnelSender
	pairs               requestPairSource
	now                 func() uint64
	staticKeyLookup     tunnel.BuildStaticKeyLookup
	seedReplyRouterInfo tunnel.ReplyRouterInfoSeeder
}

func (s muxLeaseSetSender) Send(ctx context.Context, peer netdb.RouterRef, message i2np.Message) error {
	store, err := i2np.ParseDatabaseStore(message.Payload)
	if err != nil {
		return err
	}
	if s.seedReplyRouterInfo != nil && store.ReplyToken != 0 && store.ReplyTunnelID != 0 {
		if err = s.seedReplyRouterInfo(ctx, peer.Hash, store.ReplyGateway); err != nil {
			return err
		}
	}
	return sendNetDBThroughPair(ctx, peer, message, s.sender, s.tunnels, s.pairs, s.now, s.staticKeyLookup, s.seedReplyRouterInfo)
}
func (s muxLeaseSetSender) Eligible(peer netdb.RouterRef) bool {
	eligible := transportPeerEligibility(s.sender)
	return eligible == nil || eligible(peer.Hash)
}

func sendNetDBThroughPair(ctx context.Context, peer netdb.RouterRef, message i2np.Message, sender tunnel.Sender, tunnels requestTunnelSender, pairs requestPairSource, now func() uint64, staticKeyLookup tunnel.BuildStaticKeyLookup, seedReplyRouterInfo tunnel.ReplyRouterInfoSeeder) error {
	if tunnels == nil || pairs == nil || now == nil {
		return sender.Send(ctx, peer.Hash, message)
	}
	pair, ok := pairs.Pair(now())
	if !ok {
		return sender.Send(ctx, peer.Hash, message)
	}
	if seedReplyRouterInfo != nil && pair.OutboundEndpoint != (ivnp.Hash{}) {
		if err := seedReplyRouterInfo(ctx, pair.OutboundEndpoint, peer.Hash); err != nil {
			return err
		}
	}
	frameMessage := message
	var staticKey [32]byte
	found := false
	if staticKeyLookup != nil {
		staticKey, found = staticKeyLookup(peer.Hash)
	}
	if found {
		encrypted := make([]byte, 32+7+3+10+message.EncodedLen()+16)
		sealed, err := eciesgarlic.SealRouterMessage(encrypted, staticKey[:], message, now(), cryptorand.Reader)
		if err != nil {
			return err
		}
		garlicPayload := make([]byte, 4+len(sealed))
		binary.BigEndian.PutUint32(garlicPayload[:4], uint32(len(sealed)))
		copy(garlicPayload[4:], sealed)
		frameMessage = i2np.Message{
			Header:  i2np.Header{Type: i2np.Garlic, ID: randomNonZeroID(), Expiration: message.Header.Expiration},
			Payload: garlicPayload,
		}
	}
	frame := make([]byte, frameMessage.EncodedLen())
	if _, err := frameMessage.MarshalTo(frame); err != nil {
		return err
	}
	return tunnels.SendBlock(ctx, pair.OutboundID, tunnel.Block{
		Delivery: tunnel.DeliveryRouter, Gateway: peer.Hash, Last: true, Data: frame,
	})
}

func transportPeerEligibility(sender tunnel.Sender) func(ivnp.Hash) bool {
	selector, ok := sender.(interface{ CanSend(ivnp.Hash) bool })
	if !ok {
		return nil
	}
	return selector.CanSend
}

type daemonReplyRoute struct {
	local      ivnp.Hash
	maintainer *tunnel.PairedPoolMaintainer
	now        func() uint64
}

func (r daemonReplyRoute) DatabaseLookupReplyRoute() (ivnp.Hash, uint32, bool) {
	if r.maintainer != nil {
		if pair, ok := r.maintainer.Pair(r.now()); ok {
			return pair.ReplyRouter, pair.InboundID, true
		}
	}
	return r.local, 0, false
}

// NetDBReplyPath supplies the shared confirmed-publication reply path.
func (r daemonReplyRoute) NetDBReplyPath() (ivnp.Hash, uint32, bool) {
	gateway, tunnelID, tunnel := r.DatabaseLookupReplyRoute()
	if gateway == (ivnp.Hash{}) {
		return ivnp.Hash{}, 0, false
	}
	if !tunnel {
		return gateway, 0, true
	}
	return gateway, tunnelID, true
}

type inboundLeaseSource struct{ pool *tunnel.Pool }

func (s inboundLeaseSource) CurrentInboundLeases(now uint64) []netdb.Lease {
	if s.pool == nil {
		return nil
	}
	entries := s.pool.Snapshot(now)
	leases := make([]netdb.Lease, 0, len(entries))
	for _, entry := range entries {
		if entry.Direction == tunnel.Inbound && entry.Gateway != (ivnp.Hash{}) && entry.GatewayTunnelID != 0 && entry.Expires > now {
			leases = append(leases, netdb.Lease{Gateway: entry.Gateway, TunnelID: entry.GatewayTunnelID, EndDate: entry.Expires})
		}
	}
	return leases
}

// daemonReplySender is the single production reply route for NetDB control
// messages. It sends direct replies synchronously and encapsulates tunneled
// replies through a live outbound circuit; it never downgrades a tunnel route.
type daemonReplySender struct {
	sender  tunnel.Sender
	tunnels *tunnel.Runtime
	pool    *tunnel.Pool
	now     func() uint64
}

func (s daemonReplySender) SendNetDBReply(ctx context.Context, gateway ivnp.Hash, tunnelID uint32, message i2np.Message) error {
	if s.sender == nil || gateway == (ivnp.Hash{}) || s.now == nil {
		return router.ErrDataPlaneConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if tunnelID == 0 {
		return s.sender.Send(ctx, gateway, message)
	}
	if s.tunnels == nil || s.pool == nil {
		return router.ErrDataPlaneConfig
	}
	outbound, ok := s.pool.Select(tunnel.Outbound, s.now())
	if !ok {
		return tunnel.ErrCircuitNotFound
	}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		return err
	}
	return s.tunnels.SendBlock(ctx, outbound.ID, tunnel.Block{Delivery: tunnel.DeliveryTunnel, Gateway: gateway, TunnelID: tunnelID, Data: frame})
}

func (s daemonReplySender) SendStatus(gateway ivnp.Hash, tunnelID uint32, status i2np.DeliveryStatusMessage) error {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[:4], status.MessageID)
	binary.BigEndian.PutUint64(payload[4:], status.Timestamp)
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: randomNonZeroID(), Expiration: s.now() + 60_000}, Payload: payload}
	return s.SendNetDBReply(context.Background(), gateway, tunnelID, message)
}

func nowFromClock(clock router.Clock) func() uint64 {
	return func() uint64 { return uint64(clock.Now().UnixMilli()) }
}

func buildReplyRouterInfoSeeder(database *netdb.Database, sender tunnel.Sender, now func() uint64) tunnel.ReplyRouterInfoSeeder {
	return func(ctx context.Context, endpoint, replyRouter ivnp.Hash) error {
		ref, ok := database.Routers().Get(replyRouter)
		if !ok {
			return fmt.Errorf("daemon: reply-gateway RouterInfo unavailable")
		}
		compressed, err := netdb.CompressRouterInfo(ref.Info.Bytes())
		if err != nil {
			return err
		}
		payload, err := netdb.MarshalDatabaseStore(replyRouter, i2np.StoreRouterInfo, compressed, 0, ivnp.Hash{}, 0)
		if err != nil {
			return err
		}
		messageID, err := randomMessageID()
		if err != nil {
			return err
		}
		return sender.Send(ctx, endpoint, i2np.Message{
			Header:  i2np.Header{Type: i2np.DatabaseStore, ID: messageID, Expiration: now() + 60_000},
			Payload: payload,
		})
	}
}

func randomNonZeroID() uint32 {
	var raw [4]byte
	for {
		if _, err := cryptorand.Read(raw[:]); err != nil {
			return 1
		}
		if id := binary.BigEndian.Uint32(raw[:]); id != 0 {
			return id
		}
	}
}

func randomMessageID() (uint32, error) {
	var raw [4]byte
	for {
		if _, err := cryptorand.Read(raw[:]); err != nil {
			return 0, err
		}
		if id := binary.BigEndian.Uint32(raw[:]); id != 0 {
			return id, nil
		}
	}
}

func destinationPrivate(destination *ivnp.LocalDestination) ([]byte, error) {
	if destination == nil {
		return nil, ivnp.ErrInvalidIdentity
	}
	private := make([]byte, destination.PrivateEncodedLen())
	n, err := destination.MarshalPrivateTo(private)
	if err != nil {
		clear(private)
		return nil, err
	}
	return private[:n], nil
}

func newStaticAddressPublisher(cfg config.Operating, bundle state.Bundle) (staticAddressPublisher, error) {
	addresses := make([]router.PublishedAddress, 0, 2)
	if cfg.NTCP2.Enabled {
		private, err := ecdh.X25519().NewPrivateKey(bundle.NTCP2StaticPrivate)
		if err != nil {
			return nil, err
		}
		options := []router.MappingOption{{Key: "i", Value: ivnp.EncodeI2PBase64(bundle.NTCP2StaticIV)}, {Key: "s", Value: ivnp.EncodeI2PBase64(private.PublicKey().Bytes())}, {Key: "v", Value: "2"}}
		if cfg.NTCP2.Advertised.Host != "" && cfg.NTCP2.Advertised.Port != 0 {
			options = append(options,
				router.MappingOption{Key: "host", Value: cfg.NTCP2.Advertised.Host},
				router.MappingOption{Key: "port", Value: fmt.Sprint(cfg.NTCP2.Advertised.Port)},
			)
		}
		addresses = append(addresses, router.PublishedAddress{Transport: "NTCP2", Options: options})
	}
	if cfg.SSU2.Enabled {
		private, err := ecdh.X25519().NewPrivateKey(bundle.SSU2StaticPrivate)
		if err != nil {
			return nil, err
		}
		options := []router.MappingOption{{Key: "i", Value: ivnp.EncodeI2PBase64(bundle.SSU2IntroKey)}, {Key: "s", Value: ivnp.EncodeI2PBase64(private.PublicKey().Bytes())}, {Key: "v", Value: "2"}}
		if cfg.SSU2.Advertised.Host != "" && cfg.SSU2.Advertised.Port != 0 {
			options = append(options, router.MappingOption{Key: "host", Value: cfg.SSU2.Advertised.Host}, router.MappingOption{Key: "port", Value: fmt.Sprint(cfg.SSU2.Advertised.Port)})
		}
		addresses = append(addresses, router.PublishedAddress{Transport: "SSU", Options: options})
	}
	return staticAddressPublisher(addresses), nil
}

func automaticTransportConfig(transport config.Transport) autoTransportConfig {
	var publicHint netip.Addr
	if transport.Advertised.Host != "" {
		if address, err := netip.ParseAddr(transport.Advertised.Host); err == nil {
			publicHint = address.Unmap()
		}
	}
	return autoTransportConfig{
		enabled: transport.Enabled,
		automatic: transport.Enabled && transport.Advertised.Port == 0 &&
			!loopbackEndpoint(transport.Bind),
		publicHint: publicHint,
	}
}

type staticAddressPublisher []router.PublishedAddress

func (p staticAddressPublisher) Addresses(context.Context) ([]router.PublishedAddress, error) {
	return append([]router.PublishedAddress(nil), p...), nil
}

var _ clientapi.StatusProvider = (*Daemon)(nil)
var _ clientapi.DestinationCatalog = (*Daemon)(nil)
