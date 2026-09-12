// Package noderuntime owns router control state, policy, and maintenance.
package noderuntime

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/reseed"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

var (
	ErrStarted                = errors.New("daemon: already started")
	ErrProxyWithoutTunnels    = errors.New("daemon: proxies require enabled tunnels")
	ErrTooManyDestinations    = errors.New("daemon: too many destinations")
	ErrDuplicateDestination   = errors.New("daemon: duplicate destination identity")
	ErrReseedUnavailable      = errors.New("daemon: reseed is unavailable")
	ErrTunnelProbeUnavailable = errors.New("daemon: tunnel probe is unavailable")
	ErrExplorationUnavailable = errors.New("daemon: exploration is unavailable")
	ErrStateConflict          = errors.New("router: persistent state conflicts with embedded ownership")
)

const (
	daemonHealthProbeTimeoutMillis            = uint64(time.Minute / time.Millisecond)
	daemonNetDBLookupTimeoutMillis            = uint64((30 * time.Second) / time.Millisecond)
	daemonDestinationNetDBLookupTimeoutMillis = uint64((2 * time.Minute) / time.Millisecond)
	daemonNetDBLookupCandidates               = 32
	daemonTunnelBuildCandidates               = 512
	daemonNetDBExplorationBootstrapDelay      = time.Second
	daemonNetDBExplorationSteadyDelay         = 5 * time.Second
	daemonMaxDestinations                     = 256
)

func daemonReplyKeyCapacity(buildPending, maxDestinations int) int {
	maxInt := int(^uint(0) >> 1)
	if maxDestinations >= maxInt {
		return maxInt
	}
	managerCount := max(1, maxDestinations+1)
	perManager := tunnel.BuildReplyKeyCapacity(buildPending)
	if managerCount > maxInt/perManager {
		return maxInt
	}
	return managerCount * perManager
}

func daemonCreatorBudgetCapacity(buildPending, maxDestinations int) int {
	maxInt := int(^uint(0) >> 1)
	if maxDestinations >= maxInt {
		return maxInt
	}
	managerCount := max(1, maxDestinations+1)
	perManager := max(1, buildPending)
	if managerCount > maxInt/perManager {
		return maxInt
	}
	return managerCount * perManager
}

// NATRuntime provides NAT-PMP and UPnP port mapping discovery interfaces.
type NATRuntime interface {
	NewNATPMP(netip.AddrPort) natPMPClient
	UPnP() upnpClient
	Prefixes() ([]netip.Prefix, error)
	Route(context.Context, string, uint16) (netip.Addr, error)
	RetryInterval() time.Duration
	Wait(context.Context, time.Duration) bool
}

// ControllerOptions supplies the core router's host-owned dependencies.
type ControllerOptions struct {
	Embedded             bool
	TaintedCopy          bool
	PromoteToMaster      *bool
	LockRetryInterval    time.Duration
	BootstrapRouterInfos [][]byte
	Exploratory          *destination.TunnelPoolConfig
	// SocketRuntime provides low-level network socket creation.
	SocketRuntime dataplane.RouterSocketRuntime
	// Transport overrides the default NTCP2/SSU2 transport manager.
	Transport     dataplane.RouterTransportManager
	HTTPClient    *http.Client
	Clock         dataplane.RouterClock
	Logger        *slog.Logger
	Registry      *observability.Registry
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

// Status represents the overall operational status of the daemon and router.
type Status struct {
	Running bool
	Error   error
	Router  router.Status
}

// TunnelRuntimeSnapshot represents an active tunnel without exposing secret keys.
type TunnelRuntimeSnapshot struct {
	DestinationName string
	Entry           tunnel.Entry
}

// destinationRuntime is the complete client-side ownership boundary. Router
// exploratory/transit components are intentionally not retained here.
type destinationRuntime struct {
	name                    string
	local                   *foundation.LocalDestination
	ratchet                 *dataplane.GarlicRatchetManager
	pool                    *tunnel.Pool
	profiles                *tunnel.PeerProfiles
	build                   *tunnel.BuildManager
	maintainer              *tunnel.PairedPoolMaintainer
	health                  *tunnel.Health
	requests                *netdb.RequestManager
	publisher               *destinationPublisher
	tunnels                 *dataplane.TunnelRuntime
	sender                  *router.StreamingTunnelSender
	bandwidth               *dataplane.RouterDestinationBandwidthLimiter
	session                 *dataplane.RouterDestinationSession
	unregister              []func()
	once                    sync.Once
	maintenanceMu           sync.Mutex
	released                atomic.Bool
	onRelease               func(*destinationRuntime)
	now                     func() uint64
	maintenanceQueued       atomic.Bool
	tunnelMaintenanceDirty  atomic.Bool
	tunnelMaintenanceQueued atomic.Bool
	changeMu                sync.Mutex
	changed                 chan struct{}
	requestPath             destinationRequestPath
}

func (r *destinationRuntime) release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.maintenanceMu.Lock()
		r.released.Store(true)
		r.notifyChanged()
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
		if r.publisher != nil {
			r.publisher.Close()
		}
		for _, v := range slices.Backward(r.unregister) {
			v()
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

func (r *destinationRuntime) changes() <-chan struct{} {
	r.changeMu.Lock()
	defer r.changeMu.Unlock()
	if r.changed == nil {
		r.changed = make(chan struct{})
	}
	return r.changed
}

func (r *destinationRuntime) notifyChanged() {
	r.changeMu.Lock()
	defer r.changeMu.Unlock()
	if r.changed != nil {
		close(r.changed)
		r.changed = nil
	}
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
	if r.sender != nil {
		r.sender.MaintainScratch()
	}
	if r.requests != nil {
		r.requests.Expire(now)
	}
	if r.health != nil {
		_, err := r.health.Expire(ctx)
		result = errors.Join(result, err)
		if err == nil && r.maintainer != nil {
			if pair, ok := r.maintainer.Pair(now); ok && pair.PeerCount != 0 {
				_, err = r.health.Probe(ctx, pair, foundation.Hash{})
				if !errors.Is(err, tunnel.ErrProbePending) && !errors.Is(err, tunnel.ErrProbeNotReady) {
					result = errors.Join(result, err)
				}
			}
		}
	}
	return result
}

func (r *destinationRuntime) maintainTunnels(ctx context.Context) (int, error) {
	if r == nil {
		return 0, nil
	}
	r.maintenanceMu.Lock()
	defer r.maintenanceMu.Unlock()
	defer r.notifyChanged()
	if r.released.Load() || r.maintainer == nil {
		return 0, nil
	}
	return r.maintainer.Maintain(ctx)
}

// Controller manages the lifecycle of an embedded IVNP router and its associated local services.
type Controller struct {
	config            state.ConfigurationOperating
	stateMu           sync.Mutex
	store             *state.SecureStateStore
	stateLock         *state.SecureStateLock
	taintedDir        string
	masterStatePath   string
	masterKeyPath     string
	masterNetdbDir    string
	promoteToMaster   bool
	lockRetryInterval time.Duration
	promoted          atomic.Bool
	bundle            state.SecureStateBundle
	database          *netdb.Database
	netdbStore        *netdb.RouterInfoStore
	responderStore    *netdb.ResponderProfileStore
	responders        *netdb.ResponderProfiles
	explorer          *netdb.Explorer
	localInfo         *router.LocalRouterInfo
	router            *router.Router
	registry          *observability.Registry
	logger            *slog.Logger
	clock             dataplane.RouterClock

	service                *dataplane.RouterService
	tunnels                *dataplane.TunnelRuntime
	pool                   *tunnel.Pool
	profiles               *tunnel.PeerProfiles
	tunnelHealth           *tunnel.Health
	replyKeys              *dataplane.GarlicReplyKeyRegistry
	buildManager           *tunnel.BuildManager
	maintainer             *tunnel.PairedPoolMaintainer
	requests               *netdb.RequestManager
	destinations           *dataplane.RouterDestinationManager
	garlicSessions         []*dataplane.GarlicSessionManager
	garlicReceiver         *dataplane.RouterGarlicReceiver
	statusMux              *router.DeliveryStatusMux
	publication            *router.PublicationMaintenance
	destinationFactory     *destinationRuntimeFactory
	releaseRouterInfoSeeds func()
	closeNativeTransports  func() error
	maintenanceWG          sync.WaitGroup
	buildReplies           *destinationBuildReplyRegistry
	requestHandlers        *destinationRequestRegistry
	destinationPublishers  *destinationPublisherRegistry
	clientRuntimes         []*destinationRuntime
	clientRuntimesMu       sync.RWMutex
	destinationMu          sync.Mutex
	maintenanceDone        chan struct{}
	explorationDone        chan struct{}
	publicationWake        chan struct{}
	destinationWake        chan *destinationRuntime
	destinationTunnelWake  chan *destinationRuntime
	bootstrapPoolsStarted  atomic.Bool
	tunnelWake             chan struct{}
	netdbSaveWake          chan struct{}
	startReady             chan struct{}

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

// NewController initializes a Daemon with the given configuration and optional runtime overrides.
func NewController(cfg state.ConfigurationOperating, options ControllerOptions) (_ *Controller, resultErr error) {
	if options.Embedded && (cfg.StatePath == "") != (cfg.KeyPath == "") {
		return nil, fmt.Errorf("%w: both state and key paths are required", ErrStateConflict)
	}
	exploratoryHops := 2
	if cfg.Tunnel.Hops > 0 {
		exploratoryHops = min(2, cfg.Tunnel.Hops)
	}
	exploratory := destination.TunnelPoolConfig{
		Inbound:     destination.TunnelDirectionConfig{Hops: exploratoryHops, Count: cfg.Tunnel.ExploratoryInboundTarget},
		Outbound:    destination.TunnelDirectionConfig{Hops: exploratoryHops, Count: cfg.Tunnel.ExploratoryOutboundTarget},
		RenewBefore: cfg.Tunnel.RenewBefore,
	}
	if options.Exploratory != nil {
		exploratory = *options.Exploratory
	}
	if cfg.Tunnel.Enabled && options.Embedded {
		if err := validateEmbeddedPool(exploratory); err != nil {
			return nil, err
		}
		cfg.Tunnel.ExploratoryPoolCapacity = 2 * (exploratory.Inbound.Count + exploratory.Inbound.Backup + exploratory.Outbound.Count + exploratory.Outbound.Backup)
	}
	if cfg.State.MaxDestinations < 1 {
		return nil, fmt.Errorf("%w: state max_destinations must be at least 1", state.ConfigurationErrInvalidOperating)
	}
	if cfg.Network.ID > 255 {
		return nil, fmt.Errorf("daemon: network id %d cannot be used by native transports", cfg.Network.ID)
	}
	if cfg.Tunnel.Enabled && cfg.Tunnel.Lifetime != 10*time.Minute {
		return nil, fmt.Errorf("%w: enabled tunnel lifetime must be exactly 10m", state.ConfigurationErrInvalidOperating)
	}
	if (cfg.HTTPProxy.Enabled || cfg.SOCKS5.Enabled) && !cfg.Tunnel.Enabled {
		return nil, ErrProxyWithoutTunnels
	}
	clock := options.Clock
	if clock == nil {
		clock = dataplane.RouterWallClock{}
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}

	registry := options.Registry
	if registry == nil {
		registry = observability.NewRegistry()
	}
	registry.SetBootstrapStage(1)
	sockets := options.SocketRuntime
	if sockets ==
		nil {
		sockets = &dataplane.RouterNativeSocketRuntime{}
	}

	var store *state.SecureStateStore
	var err error
	var taintedDir string
	keepTaintedDir := false
	masterStatePath := cfg.StatePath
	masterKeyPath := cfg.KeyPath
	masterNetdbDir := cfg.StateDir
	if masterNetdbDir == "" && cfg.StatePath != "" {
		masterNetdbDir = filepath.Dir(cfg.StatePath)
	}

	workingStatePath := masterStatePath
	workingKeyPath := masterKeyPath
	workingNetdbDir := masterNetdbDir

	promoteToMaster := cfg.State.PromoteToMaster
	if options.PromoteToMaster != nil {
		promoteToMaster = *options.PromoteToMaster
	}
	lockRetryInterval := cfg.State.LockRetryInterval
	if options.LockRetryInterval > 0 {
		lockRetryInterval = options.LockRetryInterval
	}
	if lockRetryInterval <= 0 {
		lockRetryInterval = 15 * time.Second
	}

	if (options.TaintedCopy || cfg.State.TaintedCopy) && cfg.StatePath != "" {
		tempBase := cmp.Or(cfg.TempDir, os.TempDir())
		if err := os.MkdirAll(tempBase, 0o700); err != nil {
			return nil, fmt.Errorf("daemon: failed to create temp directory base: %w", err)
		}
		td, err := os.MkdirTemp(tempBase, "ivnp-tainted-*")
		if err != nil {
			return nil, fmt.Errorf("daemon: failed to create tainted state directory: %w", err)
		}
		_ = os.Chmod(td, 0o700)
		taintedDir = td
		defer func() {
			if !keepTaintedDir && taintedDir != "" {
				_ = os.RemoveAll(taintedDir)
			}
		}()

		stateBase := filepath.Base(cfg.StatePath)
		workingStatePath = filepath.Join(taintedDir, stateBase)
		if err := copyFileIfExists(cfg.StatePath, workingStatePath); err != nil {
			return nil, fmt.Errorf("daemon: failed to copy state file for tainted mode: %w", err)
		}

		if cfg.KeyPath != "" {
			keyBase := filepath.Base(cfg.KeyPath)
			workingKeyPath = filepath.Join(taintedDir, keyBase)
			if err := copyFileIfExists(cfg.KeyPath, workingKeyPath); err != nil {
				return nil, fmt.Errorf("daemon: failed to copy keys file for tainted mode: %w", err)
			}
		}

		if workingNetdbDir != "" {
			_ = copyFileIfExists(filepath.Join(workingNetdbDir, "netdb.routers"), filepath.Join(taintedDir, "netdb.routers"))
			_ = copyFileIfExists(filepath.Join(workingNetdbDir, "netdb.responders"), filepath.Join(taintedDir, "netdb.responders"))
		}
		if cfg.AddressBook.StatePath != "" {
			_ = copyFileIfExists(cfg.AddressBook.StatePath, filepath.Join(taintedDir, filepath.Base(cfg.AddressBook.StatePath)))
		}
		workingNetdbDir = taintedDir
	}

	if options.Embedded && workingStatePath == "" {
		if cfg.StateDir != "" || cfg.DataDir != "" || len(cfg.NetDB.BootstrapRouterInfoPaths) != 0 {
			return nil, fmt.Errorf("%w: memory state cannot use filesystem paths", ErrStateConflict)
		}
		store = state.SecureStateNewMemoryStore()
	} else {
		store, err = state.SecureStateNewStore(workingStatePath, workingKeyPath)
	}
	reporter := options.PanicReporter
	if reporter == nil {
		reporter = slogPanicReporter{logger: logger}
	}

	reporter = metricPanicReporter{metrics: registry, next: reporter}
	if err != nil {
		if options.Embedded && workingStatePath != "" {
			return nil, errors.Join(ErrStateConflict, err)
		}
		return nil, err
	}
	store.MaxStateBytes = int(cfg.State.MaxBytes)
	store.MaxDestinations = cfg.State.MaxDestinations
	store.MaxNameBytes = cfg.State.MaxNameBytes
	keepStore := false
	defer func() {
		if !keepStore {
			resultErr = errors.Join(resultErr, store.Close())
		}
	}()
	stateLock, err := store.AcquireLock()
	if err != nil {
		if options.Embedded && workingStatePath != "" {
			return nil, errors.Join(ErrStateConflict, err)
		}
		return nil, err
	}
	keepStateLock := false
	defer func() {
		if !keepStateLock {
			resultErr = errors.Join(resultErr, stateLock.Close())
		}
	}()
	bundle, err := store.LoadOrCreate()
	if err != nil {
		if options.Embedded && workingStatePath != "" {
			return nil, errors.Join(ErrStateConflict, err)
		}
		return nil, err
	}
	keepBundle := false
	defer func() {
		if !keepBundle {
			bundle.ReleaseSensitive()
		}
	}()
	hasIdentities := len(bundle.Destinations) != 0 || len(bundle.DestinationPrivate) != 0
	hasPolicies := len(bundle.EncryptedLeaseSetPolicies) != 0 || len(bundle.DestinationAddressPolicies) != 0
	if options.Embedded && (hasIdentities || hasPolicies) {
		return nil, fmt.Errorf("%w: named application state requires the daemon", ErrStateConflict)
	}
	if cfg.Tunnel.Enabled && len(bundle.Destinations)+len(bundle.DestinationPrivate) > cfg.State.MaxDestinations {
		return nil, ErrTooManyDestinations
	}
	if cfg.Tunnel.Enabled && !options.Embedded {
		if bundle.DestinationPrivate == nil {
			bundle.DestinationPrivate = make(map[string][]byte)
		}
		migrated := false
		for name, encoded := range bundle.DestinationPrivate {
			if _, encrypted := bundle.EncryptedLeaseSetPolicies[name]; encrypted {
				continue
			}
			local, importErr := foundation.ImportLocalDestination(encoded)
			if importErr != nil {
				return nil, importErr
			}
			identity, identityErr := local.Identity()
			oldHash := local.Hash()
			local.ReleaseSensitive()
			if identityErr != nil {
				return nil, identityErr
			}
			if identity.CryptoKeyType() == foundation.CryptoElGamal {
				continue
			}
			replacement, generateErr := foundation.GenerateLegacyLocalDestination()
			if generateErr != nil {
				return nil, generateErr
			}
			private, privateErr := destinationPrivate(replacement)
			newHash := replacement.Hash()
			replacement.ReleaseSensitive()
			if privateErr != nil {
				return nil, privateErr
			}
			clear(encoded)
			bundle.DestinationPrivate[name] = private
			migrated = true
			logger.Warn("rotated incompatible public destination identity", "destination", name,
				"old_hash", foundation.EncodeI2PBase64(oldHash[:]), "new_hash", foundation.EncodeI2PBase64(newHash[:]))
		}
		legacyHashes := make(map[foundation.Hash]string, len(bundle.Destinations))
		for name, address := range bundle.Destinations {
			if previous, exists := legacyHashes[address.Hash]; exists {
				return nil, fmt.Errorf("%w: %q and %q", ErrDuplicateDestination, previous, name)
			}
			legacyHashes[address.Hash] = name
		}
		for name := range bundle.Destinations {
			local, localErr := foundation.GenerateLegacyLocalDestination()
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
			local, localErr := foundation.GenerateLegacyLocalDestination()
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
	if options.Embedded {
		database.Routers().SetRouterLimit(netdb.BucketCount * cfg.NetDB.BucketCapacity)
	}
	database.SetMetrics(registry)
	registry.SetNetDBRouters(uint64(database.Routers().Len()))
	var netdbStore *netdb.RouterInfoStore
	var responderStore *netdb.ResponderProfileStore
	netdbStateDir := workingNetdbDir
	if netdbStateDir != "" {
		store, err := netdb.NewRouterInfoStore(netdb.RouterInfoStoreConfig{
			Path: filepath.Join(netdbStateDir, "netdb.routers"), Database: database, NetworkID: cfg.Network.ID,
		})
		if err != nil {
			return nil, err
		}
		netdbStore = store
		if _, loadErr := netdbStore.Load(uint64(clock.Now().UnixMilli())); loadErr != nil {
			logger.Warn("ignoring invalid NetDB router snapshot", "path", netdbStore.Path(), "error", loadErr)
		}
	}
	var bootstrapPeers []foundation.Hash
	for index, wire := range options.BootstrapRouterInfos {
		info, loadErr := validateBootstrapRouterInfo(wire, cfg, uint64(clock.Now().UnixMilli()))
		if loadErr != nil {
			return nil, fmt.Errorf("bootstrap RouterInfo %d: %w", index, loadErr)
		}
		if loadErr = database.AdmitRouterInfo(info, false, uint64(clock.Now().UnixMilli())); loadErr != nil {
			return nil, fmt.Errorf("bootstrap RouterInfo %d: %w", index, loadErr)
		}
		bootstrapPeers = append(bootstrapPeers, info.Hash())
	}
	if len(cfg.NetDB.BootstrapRouterInfoPaths) != 0 {
		loadedPeers, loadErr := netdb.LoadStaticRouterInfos(cfg.NetDB.BootstrapRouterInfoPaths, database, uint64(clock.Now().UnixMilli()))
		if loadErr != nil {
			return nil, loadErr
		}
		bootstrapPeers = append(bootstrapPeers, loadedPeers...)
		logger.Info("loaded verified static bootstrap RouterInfos", "count", len(bootstrapPeers))
	}
	localInfo, err := router.NewLocalRouterInfo(router.LocalRouterInfoConfig{
		Local: bundle.Router, Database: database, Clock: clock, NetworkID: cfg.Network.ID, Floodfill: cfg.Router.Floodfill,
		BandwidthRateBytesPerSecond: cfg.Tunnel.BandwidthRateBytesPerSecond, Metrics: registry,
		RouterVersion: cfg.Router.Version,
		Options:       routerFamilyOption(cfg.Router.Family),
	})
	if err != nil {
		return nil, err
	}
	staticAddresses, err := newStaticAddressPublisher(cfg, bundle)
	defer func() {
		if !keepBundle {
			localInfo.ReleaseSensitive()
		}
	}()
	if err != nil {
		return nil, err
	}
	var addresses router.AddressPublisher = staticAddresses
	if !options.Embedded {
		addresses = newNATMappingPublisher(
			staticAddresses,
			automaticTransportConfig(cfg.NTCP2),
			automaticTransportConfig(cfg.SSU2),
			cfg.NAT.NATPMPEndpoint,
			cfg.NAT.UPnPEndpoint,
			localInfo,
			logger,
		)
	}
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
	var ntcp dataplane.RouterTransportManager
	var ssu dataplane.RouterTransportManager
	closeNativeTransports := func() error {
		var result error
		if ntcp != nil {
			result = errors.Join(result, ntcp.Close())
		}
		if ssu != nil {
			result = errors.Join(result, ssu.Close())
		}
		if ntcp != nil {
			result = errors.Join(result, ntcp.Wait())
		}
		if ssu != nil {
			result = errors.Join(result, ssu.Wait())
		}
		return result
	}
	defer func() {
		if !keepBundle {
			resultErr = errors.Join(resultErr, closeNativeTransports())
		}
	}()
	if cfg.NTCP2.Enabled {
		ntcp, err = dataplane.RouterNewNTCP2Manager(dataplane.RouterNTCP2ManagerConfig{
			Peers: router.NewTransportPeerSource(database), StaticPrivate: bundle.NTCP2StaticPrivate, StaticIV: bundle.NTCP2StaticIV,
			NetworkID: uint8(cfg.Network.ID), MaxSessions: cfg.NTCP2.MaxSessions, PanicReporter: reporter, Metrics: registry, Logger: logger,
			IdleTimeout: cfg.NTCP2.IdleTimeout,
		})
		if err != nil {
			return nil, err
		}
	}
	if cfg.SSU2.Enabled {
		ssu, err = dataplane.RouterNewSSU2Manager(dataplane.RouterSSU2ManagerConfig{
			Peers: router.NewTransportPeerSource(database), StaticPrivate: bundle.SSU2StaticPrivate, IntroKey: bundle.SSU2IntroKey,
			NetworkID: uint8(cfg.Network.ID), IdleTimeout: cfg.SSU2.IdleTimeout, MaxSessions: cfg.SSU2.MaxSessions, PanicReporter: reporter, Metrics: registry, Logger: logger,
			SignControl: func(message []byte) ([]byte, error) { return ed25519.Sign(bundle.Router.SigningPrivate, message), nil },
			PublishPeerTestResult: func(ctx context.Context, result dataplane.RouterPeerTestResult) {
				if err := router.PublishPeerTestResult(ctx, localInfo, result); err != nil && ctx.Err() == nil {
					logger.Warn("publish peer test result", "error", err)
				}
			},
		})
		if err != nil {
			return nil, err
		}
	}
	allowUnknownTransports := options.Transport != nil
	var mux dataplane.RouterTransportManager
	var dataSender dataplane.TunnelSender
	if options.Transport != nil {
		mux = options.Transport
		dataSender = options.Transport
	} else {
		nativeMux, muxErr := router.NewTransportMux(router.TransportMuxConfig{
			Database: database, NTCP2: ntcp, SSU2: ssu, Metrics: registry,
		})
		if muxErr != nil {
			return nil, muxErr
		}
		mux = nativeMux
		dataSender = nativeMux.DataSender()
	}
	prepareSession := func(ctx context.Context, peer foundation.Hash) error {
		if sessions, ok := mux.(interface {
			EnsureSession(context.Context, foundation.Hash) error
		}); ok {
			return sessions.EnsureSession(ctx, peer)
		}
		return nil
	}
	now := nowFromClock(clock)
	publicationTokens := netdb.NewPublicationTokenRegistry(now, randomNonZeroID)
	var lookupResponder *netdb.LookupResponder
	var storeFlooder *netdb.StoreFlooder
	if cfg.Router.Floodfill {
		lookupResponder, err = netdb.NewLookupResponder(netdb.LookupResponderConfig{
			Database: database,
			Sender:   daemonReplySender{sender: mux, now: now},
			Local:    bundle.Router.Hash,
			Now:      now,
			Random:   randomNonZeroID,
			Wrapper:  dataplane.GarlicDatabaseLookupReplyWrapper{MessageID: randomNonZeroID},
		})
		if err != nil {
			return nil, err
		}
		storeFlooder, err = netdb.NewStoreFlooder(netdb.StoreFlooderConfig{
			Database: database, Sender: directStoreFloodSender{sender: mux}, Local: bundle.Router.Hash,
			Now: now, Random: randomNonZeroID, Logger: logger,
		})
		if err != nil {
			return nil, err
		}
	}
	routerPublisher, err := netdb.NewRouterInfoPublisher(netdb.RouterInfoPublisherConfig{
		Local: localInfo, Database: database, Sender: muxLeaseSetSender{sender: mux},
		ReplyPath: daemonReplyRoute{local: bundle.Router.Hash, now: now}, Registry: publicationTokens, Now: now, Random: randomNonZeroID, PreferredTargets: bootstrapPeers,
		FloodfillLimit: netdb.RouterInfoPublicationFloodfillK, Logger: logger,
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
			NetworkID:       uint8(cfg.Network.ID),
			MaxArchiveBytes: cfg.Reseed.MaxArchiveBytes, MaxRouterInfos: cfg.Reseed.MaxRouterInfos, MaxTotalRouterBytes: cfg.Reseed.MaxTotalBytes,
		}
		reseedRunner = client
	}
	service := dataplane.RouterNewService(dataplane.RouterSinks{})
	var (
		tunnels               *dataplane.TunnelRuntime
		pool                  *tunnel.Pool
		profiles              *tunnel.PeerProfiles
		replyKeys             *dataplane.GarlicReplyKeyRegistry
		buildManager          *tunnel.BuildManager
		maintainer            *tunnel.PairedPoolMaintainer
		requests              *netdb.RequestManager
		responders            *netdb.ResponderProfiles
		destinations          *dataplane.RouterDestinationManager
		garlicSessions        []*dataplane.GarlicSessionManager
		garlicReceiver        *dataplane.RouterGarlicReceiver
		health                *tunnel.Health
		explorer              *netdb.Explorer
		statusMux             *router.DeliveryStatusMux
		buildReplies          *destinationBuildReplyRegistry
		requestHandlers       *destinationRequestRegistry
		destinationPublishers *destinationPublisherRegistry
		destinationFactory    *destinationRuntimeFactory
		publication           *router.PublicationMaintenance
		clientRuntimes        []*destinationRuntime
		d                     *Controller
	)
	statusMux = router.NewDeliveryStatusMux(routerPublisher)
	newOK := false
	seedRouterInfo, releaseRouterInfoSeeds := buildReplyRouterInfoSeeder(database, mux, now)
	defer func() {
		if !keepBundle {
			if maintainer != nil {
				resultErr = errors.Join(resultErr, maintainer.Close())
			}
			if health != nil {
				resultErr = errors.Join(resultErr, health.Close())
			}
			if requests != nil {
				resultErr = errors.Join(resultErr, requests.Close())
			}
			if tunnels != nil {
				tunnels.Expire(^uint64(0))
			}
		}
	}()
	defer func() {
		if !newOK {
			if destinations != nil {
				resultErr = errors.Join(resultErr, destinations.Close())
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
			releaseRouterInfoSeeds()
		}
	}()
	if cfg.Tunnel.Enabled {
		seenDestinations := make(map[foundation.Hash]string, len(bundle.DestinationPrivate))
		for name, encoded := range bundle.DestinationPrivate {
			destination, importErr := foundation.ImportLocalDestination(encoded)
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
		tunnels = dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: dataSender, Now: now})
		pool = tunnel.NewPool(cfg.Tunnel.ExploratoryPoolCapacity)
		profiles = tunnel.NewPeerProfiles(tunnel.PeerProfilesConfig{})
		responders = netdb.NewResponderProfiles(netdb.ResponderProfilesConfig{Now: now})
		if netdbStateDir != "" {
			responderStore, err = netdb.NewResponderProfileStore(netdb.ResponderProfileStoreConfig{
				Path: filepath.Join(netdbStateDir, "netdb.responders"), Profiles: responders,
				Database: database, NetworkID: cfg.Network.ID, Now: now,
			})
			if err != nil {
				return nil, err
			}
			if err := responderStore.Load(); err != nil {
				logger.Warn("ignoring invalid NetDB responder history", "error", err)
			}
		}
		eligible := transportPeerEligibility(mux)
		connected := transportPeerConnection(mux)
		for _, peer := range bootstrapPeers {
			responders.Seed(peer)
		}
		replyKeys = dataplane.GarlicNewReplyKeyRegistry(daemonReplyKeyCapacity(cfg.Tunnel.BuildPendingCapacity, cfg.State.MaxDestinations))
		replySender, replyErr := router.NewBuildReplySender(router.BuildReplySenderConfig{Sender: mux, Service: service, LocalRouter: bundle.Router.Hash, Now: now, NextID: randomMessageID, Logger: logger})
		if replyErr != nil {
			return nil, replyErr
		}
		creatorBudget := tunnel.NewCreatorBudget(daemonCreatorBudgetCapacity(cfg.Tunnel.BuildPendingCapacity, cfg.State.MaxDestinations), cfg.State.MaxDestinations+1)
		buildManager, err = tunnel.NewBuildManager(tunnel.BuildManagerConfig{
			Runtime: tunnels, Pool: pool, Sender: mux, ReplyKeys: replyKeys, ReplySender: replySender,
			LocalRouter: bundle.Router.Hash, StaticPrivate: bundle.Router.X25519Private[:],
			StaticKeyLookup: tunnel.NewNetDBBuildStaticKeyLookup(database.Routers()),
			Bandwidth: func(tunnel.ShortBuildRequest) uint32 {
				return uint32(cfg.Tunnel.BandwidthRateBytesPerSecond / 1024)
			},
			LocalDelivery: func(message foundation.I2NPMessage) error { return service.HandleI2NP(message, now(), false) },
			Now:           now, MaxPending: cfg.Tunnel.BuildPendingCapacity, Profiles: profiles, Logger: logger, Metrics: registry,
			CreatorBudget: creatorBudget, Stats: tunnel.NewBuildStatistics(),
			OnBuildEvent: func() {
				if d != nil {
					d.requestExploratoryMaintenance()
				}
			},
		})
		if err != nil {
			return nil, err
		}
		inboundSource, sourceErr := tunnel.NewNetDBInboundBuildSource(tunnel.NetDBInboundBuildSourceConfig{
			Table: database.Routers(), Profiles: profiles, LocalRouter: bundle.Router.Hash, Hops: exploratory.Inbound.Hops,
			Lifetime:  uint64(cfg.Tunnel.Lifetime / time.Millisecond),
			CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
			Eligible: eligible, Connected: connected, Exploratory: true, AllowUnknownTransports: allowUnknownTransports,
		})
		if sourceErr != nil {
			return nil, fmt.Errorf("create exploratory inbound build source: %w", sourceErr)
		}
		outboundSource, sourceErr := tunnel.NewNetDBOutboundBuildSource(tunnel.NetDBOutboundBuildSourceConfig{
			Table: database.Routers(), Profiles: profiles, LocalRouter: bundle.Router.Hash, Hops: exploratory.Outbound.Hops,
			Lifetime:  uint64(cfg.Tunnel.Lifetime / time.Millisecond),
			CircuitID: randomNonZeroID, TunnelID: randomNonZeroID,
			Eligible: eligible, Connected: connected, Exploratory: true, AllowUnknownTransports: allowUnknownTransports,
		})
		if sourceErr != nil {
			return nil, fmt.Errorf("create exploratory outbound build source: %w", sourceErr)
		}
		maintainer, err = tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{
			Pool: pool, Runtime: tunnels, Builder: buildManager, InboundSource: inboundSource, OutboundSource: outboundSource,
			Now: now, InboundTarget: exploratory.Inbound.Count, OutboundTarget: exploratory.Outbound.Count,
			InboundBackup: exploratory.Inbound.Backup, OutboundBackup: exploratory.Outbound.Backup,
			RenewBefore:            uint64(exploratory.RenewBefore / time.Millisecond),
			BootstrapParallelLimit: buildManager.ParallelLimit(tunnel.Inbound, min(3, exploratory.Inbound.Count)),
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
			seedReplyRouterInfo: seedRouterInfo,
		}, replyRoute, netdb.RequestManagerConfig{
			Capacity: cfg.NetDB.LookupCapacity, MaxCandidates: daemonNetDBLookupCandidates, MaxWaiters: 64,
			TimeoutMillis: daemonNetDBLookupTimeoutMillis, Now: now, Metrics: registry, Responders: responders, Logger: logger,
		})
		if err != nil {
			return nil, err
		}
		explorer, err = netdb.NewExplorer(netdb.ExplorerConfig{
			Table: database.Routers(), Requests: requests, Now: now,
			Aggressive: func() bool { return registry.Snapshot().Bootstrap.Stage < 3 },
		})
		if err != nil {
			return nil, err
		}
		destinations = dataplane.RouterNewDestinationManager()
		garlicReceiver, err = dataplane.RouterNewGarlicReceiver(dataplane.RouterGarlicReceiverConfig{
			Service: service, Destinations: nil, ReplyKeys: replyKeys, Now: now, Metrics: registry, Logger: logger,
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
			creatorBudget: creatorBudget, stats: buildManager.Statistics(),
			localRouter: bundle.Router.Hash, staticPrivate: bundle.Router.X25519Private[:],
			profiles: profiles, eligible: eligible, connected: connected, allowUnknownTransports: allowUnknownTransports,
			now: now, clockNow: clock.Now, garlicReceiver: garlicReceiver, status: statusMux,
			buildReplies: buildReplies, requests: requestHandlers, publishers: destinationPublishers,
			publicationTokens: publicationTokens,
			preferredPeers:    append([]foundation.Hash(nil), bootstrapPeers...),
			responders:        responders,
			metrics:           registry,
			logger:            logger,
			prepareTunnel:     prepareSession,
			seedRouterInfo:    seedRouterInfo,
			awaitControl: func(ctx context.Context) error {
				if d == nil {
					return net.ErrClosed
				}
				return d.router.WaitControl(ctx)
			},
		}
		for name, encoded := range bundle.DestinationPrivate {
			destination, importErr := foundation.ImportLocalDestination(encoded)
			if importErr != nil {
				return nil, importErr
			}
			var policy *state.SecureStateEncryptedLeaseSetPolicy
			if encrypted, ok := bundle.EncryptedLeaseSetPolicies[name]; ok {
				policy = &encrypted
			}
			clientRuntime, createErr := destinationFactory.create(name, destination, policy, bundle.DestinationAddressPolicies[name], nil, nil)
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

	publicationRefresh = cmp.Or(publicationRefresh, uint64(time.Minute/time.Millisecond))

	publication, err = router.NewPublicationMaintenance(router.PublicationMaintenanceConfig{
		RouterInfo: localInfo, NetworkRouterInfo: routerPublisher, LeaseSet: destinationPublishers,
		Now: now, RouterInfoRefresh: publicationRefresh,
	})

	if err != nil {
		return nil, err
	}
	forwarder, err := dataplane.RouterNewDeliveryForwarder(dataplane.RouterDeliveryForwarderConfig{
		Local: bundle.Router.Hash, Sender: dataSender, Tunnels: tunnels, NextID: randomNonZeroID,
	})
	if err != nil {
		return nil, err
	}
	runtime, err := router.New(router.Config{
		NTCP2: ntcp2Endpoint(cfg.NTCP2), SSU2: transportEndpoint(cfg.SSU2, "udp"),
		ReseedEndpoints: append([]string(nil), cfg.Reseed.Endpoints...), RequireReseed: cfg.Reseed.Required,
	}, router.Dependencies{
		Database: database, Service: service, LocalInfo: localInfo, Transport: mux, Sockets: sockets, Addresses: addresses, Reseed: reseedRunner, Clock: clock,
		ReseedOutcome: func(err error) { d.recordReseedOutcome(err) },
		StreamBackend: destinations, Destinations: destinations, Tunnels: tunnels, BuildManager: buildManager,
		ClientBuildReplies: buildReplies, RequestHandler: requestHandlers,
		LookupResponder: lookupResponder, StoreFlooder: storeFlooder, DeliveryStatusMux: statusMux, TunnelTest: tunnelTest, GarlicReceiver: garlicReceiver,
		RouterDelivery:     forwarder.ForwardRouter,
		TunnelDelivery:     forwarder.ForwardTunnel,
		DatabaseStoreReply: daemonReplySender{sender: mux, tunnels: tunnels, pool: pool, now: now}.SendStatus,
	})
	if err != nil {
		return nil, err
	}
	d = &Controller{
		taintedDir:        taintedDir,
		masterStatePath:   masterStatePath,
		masterKeyPath:     masterKeyPath,
		masterNetdbDir:    masterNetdbDir,
		promoteToMaster:   promoteToMaster,
		lockRetryInterval: lockRetryInterval,
		config:            cfg, store: store, stateLock: stateLock, bundle: bundle, database: database, netdbStore: netdbStore, explorer: explorer, localInfo: localInfo, router: runtime, registry: registry, logger: logger, clock: clock,
		service: service, tunnels: tunnels, pool: pool, profiles: profiles, tunnelHealth: health, replyKeys: replyKeys, buildManager: buildManager, maintainer: maintainer, requests: requests, destinations: destinations, garlicSessions: garlicSessions, garlicReceiver: garlicReceiver, statusMux: statusMux, publication: publication,
		destinationFactory: destinationFactory, buildReplies: buildReplies, requestHandlers: requestHandlers, destinationPublishers: destinationPublishers, clientRuntimes: clientRuntimes,
		responderStore:         responderStore,
		responders:             responders,
		closeNativeTransports:  closeNativeTransports,
		releaseRouterInfoSeeds: releaseRouterInfoSeeds,
		startReady:             make(chan struct{}),
		destinationWake:        make(chan *destinationRuntime, max(1, cfg.State.MaxDestinations)),
		destinationTunnelWake:  make(chan *destinationRuntime, max(1, cfg.State.MaxDestinations)),
		tunnelWake:             make(chan struct{}, 1),
		netdbSaveWake:          make(chan struct{}, 1),
	}
	for _, clientRuntime := range d.clientRuntimes {
		clientRuntime.onRelease = d.removeClientRuntime
	}
	if destinationFactory != nil {
		destinationFactory.requestTunnelMaintenance = func(runtime *destinationRuntime) {
			d.requestDestinationTunnelMaintenance(runtime)
			d.requestExploratoryMaintenance()
		}
	}
	newOK = true
	keepStateLock = true
	keepStore = true
	keepBundle = true
	keepTaintedDir = true
	return d, nil
}

func routerFamilyOption(family string) []router.MappingOption {
	if family == "" {
		return nil
	}
	return []router.MappingOption{{Key: "family", Value: family}}
}

func transportEndpoint(transport state.ConfigurationTransport, network string) dataplane.RouterEndpoint {
	if !transport.Enabled {
		return dataplane.RouterEndpoint{}
	}
	return dataplane.RouterEndpoint{Network: network, Address: transport.Bind.String()}
}

func ntcp2Endpoint(transport state.ConfigurationTransport) dataplane.RouterEndpoint {
	if transport.Advertised.Port == 0 && loopbackEndpoint(transport.Bind) {
		return dataplane.RouterEndpoint{}
	}
	return transportEndpoint(transport, "tcp")
}

func loopbackEndpoint(endpoint state.ConfigurationEndpoint) bool {
	if endpoint.Host == "localhost" {
		return true
	}
	address := net.ParseIP(endpoint.Host)
	return address != nil && address.IsLoopback()
}

// Start starts transports and the control-plane maintenance owners.
func (d *Controller) Start(parent context.Context) error {
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
	d.registry.IncLifecycleStarts()
	d.registry.SetLifecycleRunning(1)
	d.registry.SetBootstrapStage(2)
	d.refreshObservability()
	d.startMaintenance()
	select {
	case d.publicationWake <- struct{}{}:
	default:
	}
	d.wg.Go(func() { ; d.recordError(d.router.Wait()); _ = d.Close() })
	return nil
}

func (d *Controller) startAllowed() error {
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

func (d *Controller) failStart(err error) {
	d.recordError(err)
	d.beginClose()
	_ = d.teardown()
}

func (d *Controller) startMaintenance() {
	interval := d.config.Tunnel.MaintenanceInterval
	if interval <= 0 {
		interval = time.Minute
	}
	interval = min(interval, time.Second)
	d.maintenanceDone = make(chan struct{})
	d.publicationWake = make(chan struct{}, 1)
	destinationWorkers := parallelism.Workers(max(1, d.config.State.MaxDestinations))
	d.maintenanceWG.Add(5 + destinationWorkers)
	go d.publicationMaintenanceLoop()
	go d.observabilityLoop()
	go d.netdbSaveLoop()
	go d.tunnelMaintenanceLoop()
	if d.explorer != nil {
		d.explorationDone = make(chan struct{})
		d.maintenanceWG.Go(d.explorationLoop)
	}
	for range destinationWorkers {
		go d.destinationMaintenanceLoop()
	}
	go d.periodicMaintenanceLoop(interval)
	for _, runtime := range d.clientRuntimeSnapshot() {
		d.requestDestinationMaintenance(runtime)
	}
	if d.taintedDir != "" && d.promoteToMaster && d.masterStatePath != "" {
		d.maintenanceWG.Add(1)
		go d.masterLockRetryLoop()
	}
}

func (d *Controller) requestExploratoryMaintenance() {
	if d == nil || d.maintainer == nil || d.tunnelWake == nil {
		return
	}
	select {
	case d.tunnelWake <- struct{}{}:
	default:
	}
}

func (d *Controller) requestAllTunnelMaintenance() {
	if d == nil {
		return
	}
	d.requestExploratoryMaintenance()
	for _, runtime := range d.clientRuntimeSnapshot() {
		d.requestDestinationTunnelMaintenance(runtime)
	}
}

func (d *Controller) tunnelMaintenanceLoop() {
	defer d.maintenanceWG.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.tunnelWake:
			maintenanceContext, cancel := context.WithTimeout(d.ctx, 30*time.Second)
			_, err := d.maintainer.Maintain(maintenanceContext)
			cancel()
			d.recordMaintenanceError(err)
		}
	}
}

func (d *Controller) publicationMaintenanceLoop() {
	defer d.maintenanceWG.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.publicationWake:
			d.maintainPublication()
		}
	}
}

func (d *Controller) maintainPublication() {
	publicationContext, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()
	var err error
	if d.publication != nil {
		_, err = d.publication.Maintain(publicationContext)
	} else {
		err = d.localInfo.Publish(publicationContext)
	}
	d.recordMaintenanceError(err)
}

func (d *Controller) observabilityLoop() {
	defer d.maintenanceWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.refreshObservability()
			now := uint64(d.clock.Now().UnixMilli())
			for _, runtime := range d.clientRuntimeSnapshot() {
				if runtime.active() && runtime.requests != nil {
					runtime.requests.Expire(now)
				}
			}
		}
	}
}

func (d *Controller) netdbSaveLoop() {
	defer d.maintenanceWG.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.netdbSaveWake:
			d.stateMu.Lock()
			if d.netdbStore != nil {
				if err := d.netdbStore.Save(); err != nil && d.ctx.Err() == nil {
					d.recordMaintenanceError(err)
				}
			}
			if d.responderStore != nil {
				if err := d.responderStore.Save(); err != nil && d.ctx.Err() == nil {
					d.recordMaintenanceError(err)
				}
			}
			d.stateMu.Unlock()
		}
	}
}

func (d *Controller) maintainDestinationTunnels(runtime *destinationRuntime) {
	var result error
	if runtime.active() {
		runtime.tunnelMaintenanceDirty.Store(false)
		maintenanceContext, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		_, err := runtime.maintainTunnels(maintenanceContext)
		cancel()
		result = errors.Join(result, err)
	}
	runtime.tunnelMaintenanceQueued.Store(false)
	if runtime.tunnelMaintenanceDirty.Load() {
		d.requestDestinationTunnelMaintenance(runtime)
	}
	d.recordMaintenanceError(result)
}

func (d *Controller) explorationLoop() {
	defer close(d.explorationDone)
	for {
		now := uint64(d.clock.Now().UnixMilli())
		if d.requests != nil {
			d.requests.Expire(now)
		}
		d.recordMaintenanceError(d.explorer.Maintain(d.ctx))
		delay := daemonNetDBExplorationSteadyDelay
		if d.registry.Snapshot().Bootstrap.Stage < 3 {
			delay = daemonNetDBExplorationBootstrapDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-d.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (d *Controller) destinationMaintenanceLoop() {
	defer d.maintenanceWG.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case runtime := <-d.destinationWake:
			if runtime != nil {
				d.maintainDestination(runtime)
			}
		case runtime := <-d.destinationTunnelWake:
			if runtime != nil {
				d.maintainDestinationTunnels(runtime)
			}
		}
	}
}

func (d *Controller) maintainDestination(runtime *destinationRuntime) {
	var maintenanceErr, publicationErr error
	var publicationTask sync.WaitGroup
	if runtime.publisher != nil {
		publicationTask.Go(func() {
			publicationContext, publicationCancel := context.WithTimeout(d.ctx, 30*time.Second)
			_, publicationErr = runtime.publisher.Maintain(publicationContext)
			publicationCancel()
		})
	}
	maintenanceContext, maintenanceCancel := context.WithTimeout(d.ctx, 30*time.Second)
	maintenanceErr = runtime.maintain(maintenanceContext, uint64(d.clock.Now().UnixMilli()))
	maintenanceCancel()
	publicationTask.Wait()
	err := errors.Join(maintenanceErr, publicationErr)
	runtime.maintenanceQueued.Store(destinationMaintenanceIdle)
	d.recordMaintenanceError(err)
}

func (d *Controller) periodicMaintenanceLoop(interval time.Duration) {
	defer d.maintenanceWG.Done()
	defer close(d.maintenanceDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.maintainOnce(uint64(d.clock.Now().UnixMilli()))
		}
	}
}

func (d *Controller) maintainOnce(now uint64) {
	d.database.ExpireLeases(now)
	if now > netdb.ReseedRouterInfoMaxAgeMillis {
		d.database.Routers().Expire(now - netdb.ReseedRouterInfoMaxAgeMillis)
	}
	d.router.MaintainReseed(d.ctx)
	for _, runtime := range d.clientRuntimeSnapshot() {
		d.requestDestinationMaintenance(runtime)
	}
	if d.maintainer != nil {
		d.requestExploratoryMaintenance()
	}
	d.maintainTunnelHealth(now)
	if d.replyKeys != nil {
		d.replyKeys.Expire(now)
	}
	d.expireGarlicSessions(now)
	select {
	case d.publicationWake <- struct{}{}:
	default:
	}
	if d.netdbStore != nil || d.responderStore != nil {
		select {
		case d.netdbSaveWake <- struct{}{}:
		default:
		}
	}
}

func (d *Controller) maintainTunnelHealth(now uint64) {
	if d.tunnelHealth == nil {
		return
	}
	if _, err := d.tunnelHealth.Expire(d.ctx); err != nil && d.ctx.Err() == nil {
		d.recordMaintenanceError(err)
	}
	if d.maintainer == nil {
		return
	}
	pair, ok := d.maintainer.Pair(now)
	if !ok || pair.PeerCount == 0 {
		return
	}
	if _, err := d.tunnelHealth.Probe(d.ctx, pair, foundation.Hash{}); err != nil && !errors.Is(err, tunnel.ErrProbePending) && !errors.Is(err, tunnel.ErrProbeNotReady) && d.ctx.Err() == nil {
		d.recordMaintenanceError(err)
	}
}

func (d *Controller) requestDestinationTunnelMaintenance(runtime *destinationRuntime) {
	if d == nil || runtime == nil || !runtime.active() || d.destinationTunnelWake == nil {
		return
	}
	runtime.tunnelMaintenanceDirty.Store(true)
	if !runtime.tunnelMaintenanceQueued.CompareAndSwap(destinationMaintenanceIdle, destinationMaintenanceQueued) {
		return
	}
	select {
	case d.destinationTunnelWake <- runtime:
	default:
		runtime.tunnelMaintenanceQueued.Store(false)
	}
}

func (d *Controller) expireGarlicSessions(now uint64) {
	expireWorkers := parallelism.Workers(len(d.garlicSessions))
	expireJobs := make(chan *dataplane.GarlicSessionManager)
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
}

const (
	destinationMaintenanceIdle   = false
	destinationMaintenanceQueued = true
	bootstrapPoolsIdle           = false
	bootstrapPoolsStarted        = true
)

func (d *Controller) requestDestinationMaintenance(runtime *destinationRuntime) {
	if d == nil || runtime == nil || !runtime.active() || d.destinationWake == nil || !runtime.maintenanceQueued.CompareAndSwap(destinationMaintenanceIdle, destinationMaintenanceQueued) {
		return
	}
	select {
	case d.destinationWake <- runtime:
	default:
		runtime.maintenanceQueued.Store(destinationMaintenanceIdle)
	}
}

func (d *Controller) refreshObservability() {
	if d == nil || d.registry == nil {
		return
	}
	_, routerRefs := d.database.Routers().Snapshot()
	routers := uint64(len(routerRefs))
	floodfills := uint64(0)
	for _, router := range routerRefs {
		if router.Floodfill {
			floodfills++
		}
	}
	d.registry.SetNetDBRouters(routers)
	d.registry.SetNetDBFloodfills(floodfills)
	if d.registry.Snapshot().Bootstrap.Stage < 3 && routers >= 50 && d.bootstrapPoolsStarted.CompareAndSwap(bootstrapPoolsIdle, bootstrapPoolsStarted) {
		d.requestAllTunnelMaintenance()
	}
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
	operational := dataPlaneReady(ReadinessDetails{
		NetDBRouters:               snapshot.NetDB.Routers,
		RouterInfoPublications:     snapshot.Publication.RouterInfoSuccesses,
		LeaseSet2Publications:      snapshot.Publication.LeaseSet2Successes,
		ExploratoryInboundTunnels:  snapshot.Tunnel.ExploratoryInboundActive,
		ExploratoryOutboundTunnels: snapshot.Tunnel.ExploratoryOutboundActive,
		ClientInboundTunnels:       snapshot.Tunnel.ClientInboundActive,
		ClientOutboundTunnels:      snapshot.Tunnel.ClientOutboundActive,
		FloodfillConfigured:        d.config.Router.Floodfill,
		FloodfillAdvertised:        foundation.NetworkDatabaseIsFloodfill(d.localInfo.Snapshot()),
	})
	if stage < 3 && operational {
		stage = 3
	}
	if stage == 3 && operational && snapshot.Bootstrap.RouterReachable != 0 {
		stage = 4
	}
	d.registry.SetBootstrapStage(stage)
}

func dataPlaneReady(readiness ReadinessDetails) bool {
	return readiness.NetDBRouters >= 50 &&
		readiness.RouterInfoPublications != 0 &&
		readiness.LeaseSet2Publications != 0 &&
		readiness.ExploratoryInboundTunnels != 0 &&
		readiness.ExploratoryOutboundTunnels != 0 &&
		readiness.ClientInboundTunnels != 0 &&
		readiness.ClientOutboundTunnels != 0 &&
		(!readiness.FloodfillConfigured || readiness.FloodfillAdvertised)
}

func outproxyWarmupReady(readiness ReadinessDetails, inboundTarget, outboundTarget uint64) bool {
	return readiness.NetDBRouters >= 50 &&
		readiness.RouterInfoPublications != 0 &&
		readiness.ExploratoryInboundTunnels >= inboundTarget &&
		readiness.ExploratoryOutboundTunnels >= outboundTarget
}

func (d *Controller) OutproxyReady() bool {
	if d == nil {
		return false
	}
	status, err := d.ClientStatus(context.Background())
	return err == nil && d.Status().Running && outproxyWarmupReady(status.Readiness,
		uint64(d.config.Tunnel.ExploratoryInboundTarget), uint64(d.config.Tunnel.ExploratoryOutboundTarget))
}

func (d *Controller) recordMaintenanceError(err error) {
	if err == nil || (d.ctx != nil && d.ctx.Err() != nil) {
		return
	}
	if !d.expectedMaintenanceError(err) {
		// Keep the complete diagnostic tree, including wrappers around joins.
		d.recordLifecycleFailure(err)
	}
}

func (d *Controller) expectedMaintenanceError(err error) bool {
	// Classify independent causes before errors.Is/As can match a sibling.
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if joined, ok := cause.(interface{ Unwrap() []error }); ok {
			expected := true
			for _, child := range joined.Unwrap() {
				if !d.expectedMaintenanceError(child) {
					expected = false
				}
			}
			return expected
		}
	}
	switch {
	case err == nil, errors.Is(err, tunnel.ErrBuildPending), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, net.ErrClosed):
		return true
	case errors.Is(err, tunnel.ErrNoEligiblePeers):
		d.logger.Debug("tunnel bootstrap waiting for eligible peers", "error", err)
		return true
	case router.IsRetryableTransportError(err):
		d.logger.Debug("tunnel bootstrap transport attempt failed", "error", err)
		return true
	case errors.Is(err, netdb.ErrNoFloodfill):
		d.registry.IncNetDBLookupFailures()
		d.logger.Debug("netdb publication waiting for floodfill", "error", err)
		return true
	default:
		return false
	}
}

func (d *Controller) recordReseedOutcome(err error) {
	d.registry.IncReseedAttempts()
	if err == nil {
		d.registry.IncReseedSuccesses()
		d.requestAllTunnelMaintenance()
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
func (d *Controller) Close() error {
	if d == nil {
		return nil
	}
	started, ready := d.beginClose()
	if started {
		<-ready
	}
	return d.teardown()
}

func (d *Controller) beginClose() (bool, <-chan struct{}) {
	// A policy transaction can be draining a transport send. Cancel that
	// transport before waiting for the transaction's persistence barrier.
	d.mu.Lock()
	d.closed = true
	if d.cancel != nil {
		d.cancel()
	}
	started, ready := d.started, d.startReady
	d.mu.Unlock()
	d.destinationMu.Lock()
	d.destinationMu.Unlock()
	return started, ready
}

func (d *Controller) teardown() error {
	d.teardownOnce.Do(func() {
		var result error
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
		d.maintenanceWG.Wait()
		if d.maintainer != nil {
			result = errors.Join(result, d.maintainer.Close())
		}
		if d.tunnelHealth != nil {
			result = errors.Join(result, d.tunnelHealth.Close())
		}
		if d.tunnels != nil {
			d.tunnels.Expire(^uint64(0))
		}
		if d.pool != nil {
			d.pool.Clear()
		}
		if d.closeNativeTransports != nil {
			result = errors.Join(result, d.closeNativeTransports())
		}
		d.localInfo.ReleaseSensitive()
		if d.garlicReceiver != nil {
			d.garlicReceiver.ReleaseSensitive()
		}
		if d.buildManager != nil {
			d.buildManager.ReleaseSensitive()
		}
		if d.explorer != nil {
			d.explorer.Close()
		}
		if d.releaseRouterInfoSeeds != nil {
			d.releaseRouterInfoSeeds()
			d.releaseRouterInfoSeeds = nil
		}
		d.stateMu.Lock()
		if d.netdbStore != nil {
			result = errors.Join(result, d.netdbStore.Save())
		}
		if d.responderStore != nil {
			result = errors.Join(result, d.responderStore.Save())
		}
		if d.store != nil {
			result = errors.Join(result, d.store.Save(d.bundle))
			result = errors.Join(result, d.store.Close())
		}
		if d.destinationFactory != nil {
			clear(d.destinationFactory.staticPrivate)
		}
		d.bundle.ReleaseSensitive()
		if d.stateLock != nil {
			result = errors.Join(result, d.stateLock.Close())
		}
		if d.taintedDir != "" {
			_ = os.RemoveAll(d.taintedDir)
		}
		d.stateMu.Unlock()
		d.registry.IncLifecycleStops()
		d.registry.SetLifecycleRunning(0)
		d.teardownErr = result
	})
	return d.teardownErr
}

// Wait blocks for every daemon-owned worker and reports the first error.
func (d *Controller) Wait() error {
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
	d.maintenanceWG.Wait()
	d.mu.Lock()
	err := d.err
	d.mu.Unlock()
	return err
}

func (d *Controller) recordError(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	d.recordLifecycleFailure(err)
}

func (d *Controller) recordLifecycleFailure(err error) {
	d.mu.Lock()
	if d.err == nil {
		d.err = err
		d.registry.IncLifecycleFailures()
		d.logger.Error("daemon lifecycle error", "error", err)
	}
	d.mu.Unlock()
}

// Status returns the daemon and router lifecycle state.
func (d *Controller) Status() Status {
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
func (d *Controller) ClientStatus(context.Context) (ManagementStatus, error) {
	status := d.Status()
	d.refreshObservability()
	snapshot := d.registry.Snapshot()
	routerHash := d.localInfo.Hash()
	readiness := ReadinessDetails{
		BootstrapStage:             snapshot.Bootstrap.Stage,
		NetDBRouters:               snapshot.NetDB.Routers,
		RouterInfoPublications:     snapshot.Publication.RouterInfoSuccesses,
		LeaseSet2Publications:      snapshot.Publication.LeaseSet2Successes,
		ExploratoryInboundTunnels:  snapshot.Tunnel.ExploratoryInboundActive,
		ExploratoryOutboundTunnels: snapshot.Tunnel.ExploratoryOutboundActive,
		ClientInboundTunnels:       snapshot.Tunnel.ClientInboundActive,
		ClientOutboundTunnels:      snapshot.Tunnel.ClientOutboundActive,
		FloodfillConfigured:        d.config.Router.Floodfill,
		FloodfillAdvertised:        foundation.NetworkDatabaseIsFloodfill(d.localInfo.Snapshot()),
		RouterReachable:            snapshot.Bootstrap.RouterReachable != 0,
		SSU2VectorIO:               snapshot.SSU2.VectorIOEnabled != 0,
		SSU2KernelDropAccounting:   snapshot.SSU2.KernelDropAccounting != 0,
		ProcessGoroutines:          snapshot.Process.Goroutines,
		ProcessHeapInuseBytes:      snapshot.Process.HeapInuseBytes,
		ProcessHeapObjects:         snapshot.Process.HeapObjects,
	}
	return ManagementStatus{
		Ready:      status.Running && dataPlaneReady(readiness),
		State:      routerStateString(status.Router.State),
		RouterHash: foundation.EncodeI2PBase64(routerHash[:]),
		Readiness:  readiness,
	}, status.Error
}

// Config returns an independent operating configuration snapshot.
func (d *Controller) Config() state.ConfigurationOperating {
	if d == nil {
		return state.ConfigurationOperating{}
	}
	d.mu.Lock()
	config := d.config
	d.mu.Unlock()
	config.NetDB.BootstrapRouterInfoPaths = slices.Clone(config.NetDB.BootstrapRouterInfoPaths)
	config.Reseed.Endpoints = slices.Clone(config.Reseed.Endpoints)
	config.AddressBook.Subscriptions = slices.Clone(config.AddressBook.Subscriptions)
	return config
}

// RegistrySnapshot returns current non-sensitive process and router counters.
func (d *Controller) RegistrySnapshot() observability.Snapshot {
	if d == nil || d.registry == nil {
		return observability.Snapshot{}
	}
	d.refreshObservability()
	return d.registry.Snapshot()
}

// TunnelEntriesSnapshot returns every live router and destination creator
// tunnel using one clock sample.
func (d *Controller) TunnelEntriesSnapshot() []TunnelRuntimeSnapshot {
	if d == nil {
		return nil
	}
	now := uint64(d.clock.Now().UnixMilli())
	entries := d.pool.Snapshot(now)
	snapshot := make([]TunnelRuntimeSnapshot, 0, len(entries))
	for _, entry := range entries {
		snapshot = append(snapshot, TunnelRuntimeSnapshot{Entry: entry})
	}
	for _, runtime := range d.clientRuntimeSnapshot() {
		if !runtime.active() || runtime.pool == nil {
			continue
		}
		for _, entry := range runtime.pool.Snapshot(now) {
			snapshot = append(snapshot, TunnelRuntimeSnapshot{
				DestinationName: runtime.name,
				Entry:           entry,
			})
		}
	}
	return snapshot
}

// NetDBRoutersSnapshot returns borrowed immutable RouterInfo views.
func (d *Controller) NetDBRoutersSnapshot() []netdb.RouterRef {
	if d == nil || d.database == nil {
		return nil
	}
	_, routers := d.database.Routers().Snapshot()
	return routers
}

// TriggerReseed starts one bounded reseed attempt when reseed is enabled.
func (d *Controller) TriggerReseed(ctx context.Context) (<-chan struct{}, error) {
	if d == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.config.Reseed.Enabled && d.router != nil
	router := d.router
	d.mu.Unlock()
	if !available {
		return nil, ErrReseedUnavailable
	}
	return router.MaintainReseed(ctx), nil
}

// TriggerTunnelProbe tests the current exploratory pair.
func (d *Controller) TriggerTunnelProbe(ctx context.Context) error {
	if d == nil {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.maintainer != nil && d.tunnelHealth != nil
	maintainer, health := d.maintainer, d.tunnelHealth
	d.mu.Unlock()
	if !available {
		return ErrTunnelProbeUnavailable
	}
	pair, ok := maintainer.Pair(uint64(d.clock.Now().UnixMilli()))
	if !ok || pair.PeerCount == 0 {
		return ErrTunnelProbeUnavailable
	}
	_, err := health.Probe(ctx, pair, foundation.Hash{})
	return err
}

// TriggerExplore starts one bounded exploratory DHT lookup for target.
func (d *Controller) TriggerExplore(ctx context.Context, target foundation.Hash) error {
	if d == nil {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.requests != nil
	requests := d.requests
	d.mu.Unlock()
	if !available {
		return ErrExplorationUnavailable
	}
	_, err := requests.Explore(ctx, target)
	return err
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
func (d *Controller) ListDestinations(context.Context) ([]DestinationSummary, error) {
	if d == nil {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	private := make(map[string][]byte, len(d.bundle.DestinationPrivate))
	for name, encoded := range d.bundle.DestinationPrivate {
		private[name] = append([]byte(nil), encoded...)
	}
	d.mu.Unlock()
	items := make([]DestinationSummary, 0, len(private))
	for name, encoded := range private {
		destination, err := foundation.ImportLocalDestination(encoded)
		clear(encoded)
		if err != nil {
			return nil, err
		}
		items = append(items, DestinationSummary{Name: name, Address: destination.B32(), Default: name == "default"})
		destination.ReleaseSensitive()
	}
	return items, nil
}

// UpdateDestinationAddressPolicies persists one local destination's remote
// ELS2 authorization policies and atomically applies them to its sender. An
// empty set removes all encrypted-only remote address policies for that local
// destination.
func (d *Controller) UpdateDestinationAddressPolicies(name string, policies []state.SecureStateRemoteELSAuthorization) error {
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
		return dataplane.RouterErrDestinationNotFound
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
	var previousContexts map[foundation.Hash]router.RemoteELSContext
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

	d.stateMu.Lock()
	err = d.store.Save(next)
	d.stateMu.Unlock()
	if err != nil {
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

func remoteELSContexts(policies []state.SecureStateRemoteELSAuthorization) (map[foundation.Hash]router.RemoteELSContext, error) {
	contexts := make(map[foundation.Hash]router.RemoteELSContext, len(policies))
	for _, policy := range policies {
		identity, consumed, err := foundation.ParseIdentity(policy.Identity)
		if err != nil || consumed != len(policy.Identity) {
			releaseRemoteELSContexts(contexts)
			return nil, dataplane.RouterErrDataPlaneConfig
		}
		context := router.RemoteELSContext{Identity: identity, Secret: append([]byte(nil), policy.Secret...)}
		switch policy.Kind {
		case state.SecureStateRemoteELSAuthorizationNone:
		case state.SecureStateRemoteELSAuthorizationDH:
			context.Authorization = netdb.ELSClientAuthorization{UseDH: true, DHPrivate: policy.DHPrivate, DHPublic: policy.DHPublic}
		case state.SecureStateRemoteELSAuthorizationPSK:
			context.Authorization = netdb.ELSClientAuthorization{UsePSK: true, PSK: policy.PSK}
		default:
			releaseRemoteELSContext(&context)
			releaseRemoteELSContexts(contexts)
			return nil, dataplane.RouterErrDataPlaneConfig
		}
		hash := identity.Hash()
		if _, exists := contexts[hash]; exists {
			releaseRemoteELSContext(&context)
			releaseRemoteELSContexts(contexts)
			return nil, dataplane.RouterErrDataPlaneConfig
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

func releaseRemoteELSContexts(contexts map[foundation.Hash]router.RemoteELSContext) {
	for hash, context := range contexts {
		releaseRemoteELSContext(&context)
		contexts[hash] = context
		delete(contexts, hash)
	}
}

func cloneDestinationAddressPolicies(source map[string][]state.SecureStateRemoteELSAuthorization) map[string][]state.SecureStateRemoteELSAuthorization {
	cloned := make(map[string][]state.SecureStateRemoteELSAuthorization, len(source))
	for name, policies := range source {
		cloned[name] = cloneRemoteELSAuthorizations(policies)
	}
	return cloned
}

func cloneRemoteELSAuthorizations(source []state.SecureStateRemoteELSAuthorization) []state.SecureStateRemoteELSAuthorization {
	cloned := make([]state.SecureStateRemoteELSAuthorization, len(source))
	for index, policy := range source {
		cloned[index] = policy
		cloned[index].Identity = append([]byte(nil), policy.Identity...)
		cloned[index].Secret = append([]byte(nil), policy.Secret...)
	}
	return cloned
}

func releaseRemoteELSAuthorizations(policies []state.SecureStateRemoteELSAuthorization) {
	for index := range policies {
		clear(policies[index].Identity)
		clear(policies[index].Secret)
		clear(policies[index].DHPrivate[:])
		clear(policies[index].DHPublic[:])
		clear(policies[index].PSK[:])
		policies[index] = state.SecureStateRemoteELSAuthorization{}
	}
	clear(policies)
}

func releaseDestinationAddressPolicies(policies map[string][]state.SecureStateRemoteELSAuthorization) {
	for name, entries := range policies {
		releaseRemoteELSAuthorizations(entries)
		delete(policies, name)
	}
}

// DestinationBandwidthSnapshot returns non-sensitive pacing counters for one
// active local destination.
func (d *Controller) DestinationBandwidthSnapshot(name string) (dataplane.RouterDestinationBandwidthSnapshot, bool) {
	if d == nil || name == "" {
		return dataplane.RouterDestinationBandwidthSnapshot{}, false
	}
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.name == name && runtime.active() && runtime.bandwidth != nil {
			return runtime.bandwidth.Snapshot(), true
		}
	}
	return dataplane.RouterDestinationBandwidthSnapshot{}, false
}

func (d *Controller) clientRuntimeCount() int {
	d.clientRuntimesMu.RLock()
	count := len(d.clientRuntimes)
	d.clientRuntimesMu.RUnlock()
	return count
}

func (d *Controller) clientRuntimeSnapshot() []*destinationRuntime {
	d.clientRuntimesMu.RLock()
	snapshot := append([]*destinationRuntime(nil), d.clientRuntimes...)
	d.clientRuntimesMu.RUnlock()
	return snapshot
}

func (d *Controller) removeClientRuntime(target *destinationRuntime) {
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
	SendBlock(context.Context, uint32, dataplane.TunnelBlock) error
}

type requestPairSource interface {
	Pair(uint64) (tunnel.CircuitPair, bool)
}

type muxRequestSender struct {
	sender              dataplane.TunnelSender
	tunnels             requestTunnelSender
	pairs               requestPairSource
	now                 func() uint64
	replyKeys           *dataplane.GarlicReplyKeyRegistry
	staticKeyLookup     tunnel.BuildStaticKeyLookup
	seedReplyRouterInfo tunnel.RouterInfoSeeder
	private             bool
}

func (s muxRequestSender) Send(ctx context.Context, peer netdb.RouterRef, message foundation.I2NPMessage) error {
	if s.private && message.Header.Type != foundation.I2NPDatabaseLookup {
		return dataplane.TunnelErrCircuitNotFound
	}
	if message.Header.Type != foundation.I2NPDatabaseLookup {
		return s.sender.Send(ctx, peer.Hash, message)
	}
	lookup, err := foundation.I2NPParseDatabaseLookup(message.Payload)
	if err != nil {
		return err
	}
	if s.private && !lookup.ReplyThroughTunnel() {
		return dataplane.TunnelErrCircuitNotFound
	}
	if s.seedReplyRouterInfo != nil && lookup.ReplyThroughTunnel() {
		if err = s.seedReplyRouterInfo(ctx, peer.Hash, lookup.From); err != nil {
			return err
		}
	}
	var replyTag [8]byte
	registered := false
	if lookup.LookupType() == uint8(netdb.LeaseSetLookup) && lookup.ReplyThroughTunnel() && !lookup.ReplyEncrypted() && lookup.ExcludedCount() == 0 && s.replyKeys != nil {
		var replyKey dataplane.GarlicReplyKey
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
	direct := s.sender
	if s.private {
		direct = nil
	}
	err = sendNetDBThroughPair(ctx, peer, message, direct, s.tunnels, s.pairs, s.now, s.staticKeyLookup, s.seedReplyRouterInfo)
	if err != nil && registered {
		s.replyKeys.RemoveGarlicReplyKey(replyTag)
	}
	return err
}

func (s muxRequestSender) Eligible(peer netdb.RouterRef) bool {
	if s.seedReplyRouterInfo != nil && !canSeedNetDBTarget(peer, s.pairs, s.now) {
		return false
	}
	return transportPeerEligibility(s.sender)(peer.Hash)
}

type directStoreFloodSender struct{ sender dataplane.TunnelSender }

func (s directStoreFloodSender) Send(ctx context.Context, peer netdb.RouterRef, message foundation.I2NPMessage) error {
	return s.sender.Send(ctx, peer.Hash, message)
}
func (s directStoreFloodSender) Eligible(peer netdb.RouterRef) bool {
	eligible := transportPeerEligibility(s.sender)
	return eligible == nil || eligible(peer.Hash)
}

type muxLeaseSetSender struct {
	sender              dataplane.TunnelSender
	tunnels             requestTunnelSender
	pairs               requestPairSource
	now                 func() uint64
	staticKeyLookup     tunnel.BuildStaticKeyLookup
	seedReplyRouterInfo tunnel.RouterInfoSeeder
}

func (s muxLeaseSetSender) Send(ctx context.Context, peer netdb.RouterRef, message foundation.I2NPMessage) error {
	store, err := foundation.I2NPParseDatabaseStore(message.Payload)
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
	if s.seedReplyRouterInfo != nil && !canSeedNetDBTarget(peer, s.pairs, s.now) {
		return false
	}
	eligible := transportPeerEligibility(s.sender)
	return eligible == nil || eligible(peer.Hash)
}

func canSeedNetDBTarget(peer netdb.RouterRef, pairs requestPairSource, now func() uint64) bool {
	if pairs == nil || now == nil {
		return true
	}
	current := now()
	pair, ready := pairs.Pair(current)
	if !ready || pair.OutboundEndpoint == (foundation.Hash{}) {
		return true
	}
	// A seed rejected as stale must not consume a lookup's transport budget.
	return netdb.RouterInfoFresh(peer.Info, current) == nil
}

func sendNetDBThroughPair(ctx context.Context, peer netdb.RouterRef, message foundation.I2NPMessage, sender dataplane.TunnelSender, tunnels requestTunnelSender, pairs requestPairSource, now func() uint64, staticKeyLookup tunnel.BuildStaticKeyLookup, seedReplyRouterInfo tunnel.RouterInfoSeeder) error {
	if tunnels == nil || pairs == nil || now == nil {
		if sender == nil {
			return dataplane.TunnelErrCircuitNotFound
		}
		return sender.Send(ctx, peer.Hash, message)
	}
	pair, ok := pairs.Pair(now())
	if !ok {
		if sender == nil {
			return dataplane.TunnelErrCircuitNotFound
		}
		return sender.Send(ctx, peer.Hash, message)
	}
	if seedReplyRouterInfo != nil && pair.OutboundEndpoint != (foundation.Hash{}) {
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
		sealed, err := dataplane.GarlicECIESSealRouterMessage(encrypted, staticKey[:], message, now(), cryptorand.Reader)
		if err != nil {
			return err
		}
		garlicPayload := make([]byte, 4+len(sealed))
		binary.BigEndian.PutUint32(garlicPayload[:4], uint32(len(sealed)))
		copy(garlicPayload[4:], sealed)
		frameMessage = foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: randomNonZeroID(), Expiration: message.Header.Expiration},
			Payload: garlicPayload,
		}
	}
	frame := make([]byte, frameMessage.EncodedLen())
	if _, err := frameMessage.MarshalTo(frame); err != nil {
		return err
	}
	return tunnels.SendBlock(ctx, pair.OutboundID, dataplane.TunnelBlock{
		Delivery: dataplane.TunnelDeliveryRouter, Gateway: peer.Hash, Last: true, Data: frame,
	})
}

func transportPeerEligibility(sender dataplane.TunnelSender) func(foundation.Hash) bool {
	if selector, ok := sender.(interface{ CanBuildTunnel(foundation.Hash) bool }); ok {
		return selector.CanBuildTunnel
	}
	if selector, ok := sender.(interface{ CanSend(foundation.Hash) bool }); ok {
		return selector.CanSend
	}
	return transportAcceptsAnyPeer
}

func transportPeerConnection(sender dataplane.TunnelSender) func(foundation.Hash) bool {
	if sessions, ok := sender.(interface{ HasSession(foundation.Hash) bool }); ok {
		return sessions.HasSession
	}
	return nil
}

func transportAcceptsAnyPeer(foundation.Hash) bool { return true }

type daemonReplyRoute struct {
	local      foundation.Hash
	maintainer requestPairSource
	now        func() uint64
}

func (r daemonReplyRoute) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	if r.maintainer != nil {
		if pair, ok := r.maintainer.Pair(r.now()); ok {
			return pair.ReplyRouter, pair.InboundID, true
		}
	}
	return r.local, 0, false
}

// NetDBReplyPath supplies the shared confirmed-publication reply path.
func (r daemonReplyRoute) NetDBReplyPath() (foundation.Hash, uint32, bool) {
	gateway, tunnelID, tunnel := r.DatabaseLookupReplyRoute()
	if gateway == (foundation.Hash{}) {
		return foundation.Hash{}, 0, false
	}
	if !tunnel {
		return gateway, 0, true
	}
	return gateway, tunnelID, true
}

type inboundLeaseSource struct{ pool *tunnel.Pool }

func (s inboundLeaseSource) CurrentInboundLeases(now uint64) []foundation.NetworkDatabaseLease {
	if s.pool == nil {
		return nil
	}
	entries := s.pool.PublishableInbound(now)
	leases := make([]foundation.NetworkDatabaseLease, 0, len(entries))
	for _, entry := range entries {
		if entry.Direction == tunnel.Inbound && entry.Gateway != (foundation.Hash{}) && entry.GatewayTunnelID != 0 && entry.Expires > now {
			leases = append(leases, foundation.NetworkDatabaseLease{Gateway: entry.Gateway, TunnelID: entry.GatewayTunnelID, EndDate: entry.Expires})
			if len(leases) == 16 {
				break
			}
		}
	}
	return leases
}

// daemonReplySender is the single production reply route for NetDB control
// messages. It sends direct replies synchronously and encapsulates tunneled
// replies through a live outbound circuit; it never downgrades a tunnel route.
type daemonReplySender struct {
	sender  dataplane.TunnelSender
	tunnels *dataplane.TunnelRuntime
	pool    *tunnel.Pool
	now     func() uint64
}

func (s daemonReplySender) SendNetDBReply(ctx context.Context, gateway foundation.Hash, tunnelID uint32, message foundation.I2NPMessage) error {
	if s.sender == nil || gateway == (foundation.Hash{}) || s.now == nil {
		return dataplane.RouterErrDataPlaneConfig
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if tunnelID == 0 {
		return s.sender.Send(ctx, gateway, message)
	}
	if s.tunnels == nil || s.pool == nil {
		return dataplane.RouterErrDataPlaneConfig
	}
	outbound, ok := s.pool.Select(tunnel.Outbound, s.now())
	if !ok {
		return dataplane.TunnelErrCircuitNotFound
	}
	frame := make([]byte, message.EncodedLen())
	if _, err := message.MarshalTo(frame); err != nil {
		return err
	}
	return s.tunnels.SendBlock(ctx, outbound.ID, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryTunnel, Gateway: gateway, TunnelID: tunnelID, Data: frame})
}

func (s daemonReplySender) SendStatus(ctx context.Context, gateway foundation.Hash, tunnelID uint32, status foundation.I2NPDeliveryStatusMessage) error {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[:4], status.MessageID)
	binary.BigEndian.PutUint64(payload[4:], status.Timestamp)
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: randomNonZeroID(), Expiration: s.now() + 60_000}, Payload: payload}
	return s.SendNetDBReply(ctx, gateway, tunnelID, message)
}

func nowFromClock(clock dataplane.RouterClock) func() uint64 {
	return func() uint64 { return uint64(clock.Now().UnixMilli()) }
}

func buildReplyRouterInfoSeeder(database *netdb.Database, sender dataplane.TunnelSender, now func() uint64) (tunnel.RouterInfoSeeder, func()) {
	var seeds replyRouterInfoSeeds
	return func(ctx context.Context, endpoint, replyRouter foundation.Hash) error {
		return seeds.seed(ctx, database, sender, now, endpoint, replyRouter)
	}, seeds.close
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

func destinationPrivate(destination *foundation.LocalDestination) ([]byte, error) {
	if destination == nil {
		return nil, foundation.ErrInvalidIdentity
	}
	private := make([]byte, destination.PrivateEncodedLen())
	n, err := destination.MarshalPrivateTo(private)
	if err != nil {
		clear(private)
		return nil, err
	}
	return private[:n], nil
}

func newStaticAddressPublisher(cfg state.ConfigurationOperating, bundle state.SecureStateBundle) (staticAddressPublisher, error) {
	addresses := make([]router.PublishedAddress, 0, 2)
	if cfg.NTCP2.Enabled {
		private, err := ecdh.X25519().NewPrivateKey(bundle.NTCP2StaticPrivate)
		if err != nil {
			return nil, err
		}
		options := []router.MappingOption{{Key: "i", Value: foundation.EncodeI2PBase64(bundle.NTCP2StaticIV)}, {Key: "s", Value: foundation.EncodeI2PBase64(private.PublicKey().Bytes())}, {Key: "v", Value: "2"}}
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
		options := []router.MappingOption{{Key: "i", Value: foundation.EncodeI2PBase64(bundle.SSU2IntroKey)}, {Key: "s", Value: foundation.EncodeI2PBase64(private.PublicKey().Bytes())}, {Key: "v", Value: "2"}}
		if cfg.SSU2.Advertised.Host != "" && cfg.SSU2.Advertised.Port != 0 {
			options = append(options, router.MappingOption{Key: "host", Value: cfg.SSU2.Advertised.Host}, router.MappingOption{Key: "port", Value: fmt.Sprint(cfg.SSU2.Advertised.Port)})
		}
		addresses = append(addresses, router.PublishedAddress{Transport: "SSU", Options: options})
	}
	return staticAddressPublisher(addresses), nil
}

func automaticTransportConfig(transport state.ConfigurationTransport) autoTransportConfig {
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

func (d *Controller) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	if d == nil || d.destinations == nil {
		return nil, dataplane.RouterErrDefaultDestination
	}
	return d.destinations.DialI2P(ctx, address)
}

func (d *Controller) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	if d == nil || d.destinations == nil {
		return nil, dataplane.RouterErrDefaultDestination
	}
	return d.destinations.ListenI2P(ctx, address)
}

func (d *Controller) ActiveDestinationCount() int {
	if d == nil {
		return 0
	}
	d.clientRuntimesMu.RLock()
	defer d.clientRuntimesMu.RUnlock()
	return len(d.clientRuntimes)
}

// TaintedDir returns the temporary directory used for tainted copy state, or empty if tainted mode is inactive or promoted.
func (d *Controller) TaintedDir() string {
	if d == nil {
		return ""
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.taintedDir
}

// IsPromoted reports whether a tainted copy router has successfully acquired the master lock and promoted itself.
func (d *Controller) IsPromoted() bool {
	if d == nil {
		return false
	}
	return d.promoted.Load()
}

// TryPromoteToMaster attempts to acquire the master state lock immediately.
// If the lock is acquired, the router merges and promotes its working state to master ownership.
func (d *Controller) TryPromoteToMaster() (bool, error) {
	if d == nil {
		return false, net.ErrClosed
	}
	return d.tryPromoteToMaster()
}

func (d *Controller) masterLockRetryLoop() {
	defer d.maintenanceWG.Done()
	interval := d.lockRetryInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			promoted, err := d.tryPromoteToMaster()
			if err != nil && !errors.Is(err, state.SecureStateErrStateLocked) {
				d.logger.Debug("master state lock retry", "path", d.masterStatePath, "error", err)
			}
			if promoted {
				d.logger.Info("promoted router to master state ownership",
					"state_path", d.masterStatePath,
					"state_dir", d.masterNetdbDir,
				)
				return
			}
		}
	}
}

func (d *Controller) tryPromoteToMaster() (bool, error) {
	d.mu.Lock()
	if d.closed || !d.started {
		d.mu.Unlock()
		return false, nil
	}
	d.mu.Unlock()

	d.stateMu.Lock()
	defer d.stateMu.Unlock()

	if d.promoted.Load() || d.taintedDir == "" || d.masterStatePath == "" {
		return false, nil
	}

	masterStore, err := state.SecureStateNewStore(d.masterStatePath, d.masterKeyPath)
	if err != nil {
		return false, err
	}
	masterStore.MaxStateBytes = int(d.config.State.MaxBytes)
	masterStore.MaxDestinations = d.config.State.MaxDestinations
	masterStore.MaxNameBytes = d.config.State.MaxNameBytes

	masterLock, err := masterStore.AcquireLock()
	if err != nil {
		_ = masterStore.Close()
		return false, err
	}

	var masterNetDBStore *netdb.RouterInfoStore
	if d.masterNetdbDir != "" {
		netdbPath := filepath.Join(d.masterNetdbDir, "netdb.routers")
		store, storeErr := netdb.NewRouterInfoStore(netdb.RouterInfoStoreConfig{
			Path: netdbPath, Database: d.database, NetworkID: d.config.Network.ID,
		})
		if storeErr == nil {
			masterNetDBStore = store
			if _, loadErr := masterNetDBStore.Load(uint64(d.clock.Now().UnixMilli())); loadErr != nil {
				d.logger.Debug("master NetDB snapshot load during promotion", "error", loadErr)
			}
			if saveErr := masterNetDBStore.Save(); saveErr != nil {
				d.logger.Warn("failed to persist NetDB snapshot during promotion", "error", saveErr)
			}
		}
	}

	var masterResponderStore *netdb.ResponderProfileStore
	if d.masterNetdbDir != "" && d.responders != nil {
		now := func() uint64 { return uint64(d.clock.Now().UnixMilli()) }
		respPath := filepath.Join(d.masterNetdbDir, "netdb.responders")
		store, storeErr := netdb.NewResponderProfileStore(netdb.ResponderProfileStoreConfig{
			Path: respPath, Profiles: d.responders, Database: d.database, NetworkID: d.config.Network.ID, Now: now,
		})
		if storeErr == nil {
			masterResponderStore = store
			_ = masterResponderStore.Load()
			_ = masterResponderStore.Save()
		}
	}

	if err := masterStore.Save(d.bundle); err != nil {
		_ = masterLock.Close()
		_ = masterStore.Close()
		return false, err
	}

	if d.config.AddressBook.StatePath != "" && d.taintedDir != "" {
		taintedAB := filepath.Join(d.taintedDir, filepath.Base(d.config.AddressBook.StatePath))
		_ = copyFileIfExists(taintedAB, d.config.AddressBook.StatePath)
	}

	if d.stateLock != nil {
		_ = d.stateLock.Close()
	}
	d.stateLock = masterLock

	if d.store != nil {
		_ = d.store.Close()
	}
	d.store = masterStore

	if masterNetDBStore != nil {
		d.netdbStore = masterNetDBStore
	}
	if masterResponderStore != nil {
		d.responderStore = masterResponderStore
	}

	oldTainted := d.taintedDir
	d.taintedDir = ""
	d.promoted.Store(true)

	if oldTainted != "" {
		_ = os.RemoveAll(oldTainted)
	}

	return true, nil
}

func copyFileIfExists(srcPath, dstPath string) (err error) {
	src, err := os.Open(srcPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dst.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if _, err = io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Sync()
}
