package router

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

const (
	streamingSeedCacheCapacity  = 64
	streamingSeedFailureBackoff = 10_000
)

type StreamingTunnelSenderConfig struct {
	Owner    foundation.Hash
	Database *controlplanenetdb.Database
	Requests *controlplanenetdb.RequestManager
	// Garlic is retained solely for explicitly stored legacy remote LeaseSets.
	// Local destinations use Ratchet and LS2/ELS2 by default.
	Garlic  *dataplane.GarlicSessionManager
	Ratchet *dataplane.GarlicRatchetManager
	// RemoteELS authorizes ELS2 lookup and decryption for an unblinded remote
	// destination. Presence forbids plaintext LS2 or legacy downgrade.
	RemoteELS           map[foundation.Hash]RemoteELSContext
	Tunnels             *dataplane.TunnelRuntime
	Pool                *controlplanetunnel.Pool
	SeedRouterInfo      controlplanetunnel.RouterInfoSeeder
	PrepareTunnel       func(context.Context, foundation.Hash) error
	AwaitControl        func(context.Context) error
	Now                 func() uint64
	NextID              dataplane.RouterMessageIDSource
	Limiter             *dataplane.RouterDestinationBandwidthLimiter
	Metrics             *observability.Registry
	Logger              *slog.Logger
	RouteCapacity       int
	PreparationCapacity int
	WaiterCapacity      int
	PreparationTimeout  time.Duration
}

// RemoteELSContext supplies the unblinded identity, blinding secret, and
// optional DH or PSK credential for one remote encrypted LeaseSet.
type RemoteELSContext struct {
	Identity      foundation.Identity
	Secret        []byte
	Authorization controlplanenetdb.ELSClientAuthorization
}

type StreamingTunnelSender struct {
	execution            *dataplane.RouterPreparedRouteSender
	owner                foundation.Hash
	database             *controlplanenetdb.Database
	requests             *controlplanenetdb.RequestManager
	pool                 *controlplanetunnel.Pool
	seedRouterInfo       controlplanetunnel.RouterInfoSeeder
	prepareTunnel        func(context.Context, foundation.Hash) error
	awaitControl         func(context.Context) error
	tunnels              *dataplane.TunnelRuntime
	replySlots           chan struct{}
	replies              sync.WaitGroup
	replyGates           map[foundation.Hash]*ratchetReplyGate
	replyGateCapacity    int
	logger               *slog.Logger
	now                  func() uint64
	lifecycleMu          sync.RWMutex
	released             bool
	remoteMu             sync.RWMutex
	replyPolicyMu        sync.RWMutex
	remoteELS            map[foundation.Hash]RemoteELSContext
	generation           uint64
	policyGeneration     uint64
	localPublication     foundation.Hash
	localPublicationType foundation.I2NPStoreType
	pending              map[routePreparationKey]*routePreparation
	pendingCapacity      int
	waiterCapacity       int
	waiters              int
	preparationTimeout   time.Duration
	preparationCtx       context.Context
	cancelPreparation    context.CancelFunc
	preparing            sync.WaitGroup
	seedMu               sync.Mutex
	seedCache            [streamingSeedCacheCapacity]streamingSeedCacheEntry
	seedNext             uint8
	leaseNext            atomic.Uint64
	failedRoutes         map[failedRoutePath]uint64
	failedRouteCapacity  int
}

type routePreparationKey struct {
	remote     foundation.Hash
	generation uint64
}
type routePreparation struct {
	done    chan struct{}
	err     error
	cancel  context.CancelFunc
	waiters int
}

type failedRoutePath struct {
	remote   foundation.Hash
	circuit  dataplane.TunnelCircuitToken
	gateway  foundation.Hash
	tunnelID uint32
}

type streamingHandshakeFeedback struct {
	sender  *StreamingTunnelSender
	receipt dataplane.RouterPreparedRouteReceipt
}

func (s *StreamingTunnelSender) PrepareHandshake(ctx context.Context, remote foundation.Hash) (dataplane.StreamingTunnelHandshakeFeedback, error) {
	if err := s.PrepareDestination(ctx, remote); err != nil {
		return nil, err
	}
	receipt, ok := s.execution.RouteReceipt(remote)
	if !ok {
		return nil, dataplane.RouterErrPreparedRouteMissing
	}
	return &streamingHandshakeFeedback{sender: s, receipt: receipt}, nil
}

func (f *streamingHandshakeFeedback) SendTunnel(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
	s := f.sender
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return dataplane.RouterErrDataPlaneConfig
	}
	if err := s.waitForRatchetReply(ctx, delivery.To); err != nil {
		return err
	}
	return s.execution.SendTunnelOnRoute(ctx, delivery, f.receipt)
}

func (f *streamingHandshakeFeedback) Established() {
	f.sender.execution.MarkRouteResponsive(f.receipt)
}

func (f *streamingHandshakeFeedback) NoResponse() {
	s := f.sender
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return
	}
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if !s.execution.RetireUnresponsiveRoute(f.receipt) {
		return
	}
	now := s.now()
	var oldest failedRoutePath
	var earliest uint64
	for path, expires := range s.failedRoutes {
		if expires <= now {
			delete(s.failedRoutes, path)
			continue
		}
		if earliest == 0 || expires < earliest {
			oldest, earliest = path, expires
		}
	}
	if len(s.failedRoutes) >= s.failedRouteCapacity {
		delete(s.failedRoutes, oldest)
	}
	s.failedRoutes[failedRoutePath{remote: f.receipt.Remote, circuit: f.receipt.Circuit, gateway: f.receipt.Gateway, tunnelID: f.receipt.TunnelID}] = f.receipt.Expires
}

func NewStreamingTunnelSender(config StreamingTunnelSenderConfig) (*StreamingTunnelSender, error) {
	missingResolution := config.Database == nil || config.Requests == nil
	missingTunnels := config.Tunnels == nil || config.Pool == nil
	invalidBounds := config.PreparationCapacity < 0 || config.WaiterCapacity < 0 || config.PreparationTimeout < 0
	if missingResolution || missingTunnels || invalidBounds {
		return nil, dataplane.RouterErrDataPlaneConfig
	}
	policies, err := cloneValidatedRemoteELS(config.RemoteELS)
	if err != nil {
		return nil, err
	}
	execution, err := dataplane.RouterNewPreparedRouteSender(dataplane.RouterPreparedRouteSenderConfig{
		Owner: config.Owner, Garlic: config.Garlic, Ratchet: config.Ratchet, Tunnels: config.Tunnels,
		Now: config.Now, NextID: config.NextID, Limiter: config.Limiter, Metrics: config.Metrics, Logger: config.Logger, RouteCapacity: config.RouteCapacity,
	})
	if err != nil {
		releaseRemoteELSPolicies(policies)
		return nil, err
	}
	if config.PreparationCapacity == 0 {
		config.PreparationCapacity = 16
	}
	if config.RouteCapacity == 0 {
		config.RouteCapacity = 64
	}
	if config.WaiterCapacity == 0 {
		config.WaiterCapacity = 256
	}
	if config.PreparationTimeout == 0 {
		config.PreparationTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	publication, publicationType := localPublicationFingerprint(config.Database, config.Owner)
	return &StreamingTunnelSender{
		execution: execution, owner: config.Owner, database: config.Database, requests: config.Requests, pool: config.Pool,
		tunnels: config.Tunnels, prepareTunnel: config.PrepareTunnel, replySlots: make(chan struct{}, config.PreparationCapacity), logger: config.Logger,
		awaitControl: config.AwaitControl,
		replyGates:   make(map[foundation.Hash]*ratchetReplyGate), replyGateCapacity: config.RouteCapacity,
		failedRoutes: make(map[failedRoutePath]uint64), failedRouteCapacity: config.RouteCapacity,
		seedRouterInfo: config.SeedRouterInfo, now: config.Now, remoteELS: policies, generation: 1, policyGeneration: 1,
		localPublication: publication, localPublicationType: publicationType,
		pending: make(map[routePreparationKey]*routePreparation), pendingCapacity: config.PreparationCapacity,
		waiterCapacity: config.WaiterCapacity, preparationTimeout: config.PreparationTimeout, preparationCtx: ctx, cancelPreparation: cancel,
	}, nil
}

func (s *StreamingTunnelSender) BandwidthSnapshot() dataplane.RouterDestinationBandwidthSnapshot {
	if s == nil {
		return dataplane.RouterDestinationBandwidthSnapshot{}
	}
	return s.execution.BandwidthSnapshot()
}

// MaintainScratch shrinks this destination's pooled send-scratch buffers that
// grew for a large message but have gone unused at that size since the last
// periodic maintenance pass. See PreparedRouteSender.MaintainScratch.
func (s *StreamingTunnelSender) MaintainScratch() {
	if s == nil {
		return
	}
	s.execution.MaintainScratch()
}

func (s *StreamingTunnelSender) UpdateRemoteELS(policies map[foundation.Hash]RemoteELSContext) error {
	if s == nil {
		return dataplane.RouterErrDataPlaneConfig
	}
	updated, err := cloneValidatedRemoteELS(policies)
	if err != nil {
		return err
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		releaseRemoteELSPolicies(updated)
		return dataplane.RouterErrDataPlaneConfig
	}
	s.replyPolicyMu.Lock()
	defer s.replyPolicyMu.Unlock()
	s.remoteMu.Lock()
	previous := s.remoteELS
	s.remoteELS = updated
	s.policyGeneration++
	s.generation++
	generation := s.generation
	releaseRemoteELSPolicies(previous)
	s.remoteMu.Unlock()
	s.execution.InvalidateRoutes(generation)
	return nil
}

// RefreshLocalLeaseSet invalidates bundled publication and circuit snapshots.
// Call after replacing this destination's advertised inbound leases.
func (s *StreamingTunnelSender) RefreshLocalLeaseSet() error {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return dataplane.RouterErrDataPlaneConfig
	}
	s.remoteMu.Lock()
	publication, kind := localPublicationFingerprint(s.database, s.owner)
	if publication == s.localPublication && kind == s.localPublicationType {
		s.remoteMu.Unlock()
		return nil
	}
	s.localPublication, s.localPublicationType = publication, kind
	s.generation++
	generation := s.generation
	s.remoteMu.Unlock()
	s.execution.InvalidateRoutes(generation)
	return nil
}

func localPublicationFingerprint(database *controlplanenetdb.Database, owner foundation.Hash) (foundation.Hash, foundation.I2NPStoreType) {
	kind, raw, ok := database.StoredLeaseSet(owner)
	if !ok {
		return foundation.Hash{}, 0
	}
	return foundation.Sum(raw), kind
}

func (s *StreamingTunnelSender) ReleaseSensitive() {
	if s == nil {
		return
	}
	if s.cancelPreparation != nil {
		s.cancelPreparation()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.released {
		return
	}
	s.released = true
	s.releaseReplyReservations()
	s.replies.Wait()
	s.preparing.Wait()
	s.execution.ReleaseSensitive()
	s.remoteMu.Lock()
	releaseRemoteELSPolicies(s.remoteELS)
	s.remoteELS = nil
	clear(s.replyGates)
	clear(s.failedRoutes)
	s.remoteMu.Unlock()
	s.seedMu.Lock()
	clear(s.seedCache[:])
	s.seedMu.Unlock()
}

func (s *StreamingTunnelSender) SendTunnel(ctx context.Context, delivery dataplane.StreamingTunnelDelivery) error {
	if s == nil || delivery.Protocol == 0 {
		return dataplane.StreamingTunnelErrTunnelProtocol
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return dataplane.RouterErrDataPlaneConfig
	}
	if delivery.From != s.owner {
		return dataplane.RouterErrGarlicDestination
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.waitForRatchetReply(ctx, delivery.To); err != nil {
			return err
		}
		err := s.execution.SendTunnel(ctx, delivery)
		if !errors.Is(err, dataplane.RouterErrPreparedRouteMissing) {
			return s.retireFailedRoute(delivery.To, err)
		}
		// A missing or superseded route has not transmitted this payload.
		// Publication renewal may replace it while preparation is in flight.
		if err = s.prepare(ctx, delivery.To); err != nil && !errors.Is(err, dataplane.RouterErrRouteGeneration) {
			return err
		}
	}
}

func (s *StreamingTunnelSender) retireFailedRoute(remote foundation.Hash, err error) error {
	if errors.Is(err, dataplane.TunnelErrCircuitNotFound) || errors.Is(err, dataplane.RouterErrSessionUnavailable) {
		s.execution.RetireRoute(remote)
	}
	return err
}

// PrepareDestination resolves and caches a route without sending application data.
// The last departing waiter cancels and joins its coalesced preparation worker.
func (s *StreamingTunnelSender) PrepareDestination(ctx context.Context, remote foundation.Hash) error {
	if s == nil {
		return dataplane.RouterErrDataPlaneConfig
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return dataplane.RouterErrDataPlaneConfig
	}
	for {
		err := s.prepare(ctx, remote)
		if !errors.Is(err, dataplane.RouterErrRouteGeneration) {
			return err
		}
	}
}

func (s *StreamingTunnelSender) prepare(ctx context.Context, remote foundation.Hash) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.remoteMu.Lock()
	if s.waiters >= s.waiterCapacity {
		s.remoteMu.Unlock()
		return dataplane.RouterErrRoutePreparationBusy
	}
	s.waiters++
	s.remoteMu.Unlock()
	defer func() { s.remoteMu.Lock(); s.waiters--; s.remoteMu.Unlock() }()
	pending, err := s.startPreparation(remote)
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}
	defer func() {
		s.remoteMu.Lock()
		pending.waiters--
		last := pending.waiters == 0
		if last {
			pending.cancel()
		}
		s.remoteMu.Unlock()
		if last {
			<-pending.done
		}
	}()
	select {
	case <-pending.done:
		return pending.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *StreamingTunnelSender) startPreparation(remote foundation.Hash) (*routePreparation, error) {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	key := routePreparationKey{remote: remote, generation: s.generation}
	if pending, ok := s.pending[key]; ok {
		pending.waiters++
		return pending, nil
	}
	if s.execution.HasRoute(remote, s.generation) {
		return nil, nil
	}
	if len(s.pending) >= s.pendingCapacity {
		return nil, dataplane.RouterErrRoutePreparationBusy
	}
	policy, encrypted := s.remoteELS[remote]
	if encrypted {
		policy.Secret = append([]byte(nil), policy.Secret...)
	}
	ctx, cancel := context.WithTimeout(s.preparationCtx, s.preparationTimeout)
	pending := &routePreparation{done: make(chan struct{}), cancel: cancel, waiters: 1}
	s.pending[key] = pending
	s.preparing.Add(1)
	go func() {
		defer close(pending.done)
		defer s.preparing.Done()
		defer clear(policy.Secret)
		defer clear(policy.Authorization.DHPrivate[:])
		defer clear(policy.Authorization.PSK[:])
		defer cancel()
		route, err := s.resolveRoute(ctx, remote, key.generation, policy, encrypted)
		if err == nil {
			s.remoteMu.RLock()
			if s.generation != key.generation {
				err = dataplane.RouterErrRouteGeneration
			}
			s.remoteMu.RUnlock()
			if err == nil {
				err = s.execution.InstallRoute(route)
			}
		}
		clear(route.KeyData)
		clear(route.LegacyKey[:])
		clear(route.LocalLeaseSet)
		s.remoteMu.Lock()
		pending.err = err
		delete(s.pending, key)
		s.remoteMu.Unlock()
	}()
	return pending, nil
}

func (s *StreamingTunnelSender) resolveRoute(ctx context.Context, remote foundation.Hash, generation uint64, policy RemoteELSContext, encrypted bool) (dataplane.RouterPreparedRoute, error) {
	route := dataplane.RouterPreparedRoute{Owner: s.owner, Remote: remote, Generation: generation}
	var set2 *foundation.NetworkDatabaseLeaseSet2
	var legacy *foundation.NetworkDatabaseLeaseSet
	var err error
	var encryptedExpires uint64
	if encrypted {
		set2, encryptedExpires, err = s.resolveEncryptedLeaseSet(ctx, policy)
	} else {
		set2, legacy, err = s.resolveLeaseSet(ctx, remote)
	}
	if err != nil {
		return route, err
	}
	if encrypted {
		defer clear(set2.Bytes())
	}
	now := s.now()
	var lease foundation.NetworkDatabaseLease
	pick := s.leaseNext.Add(1) - 1
	leaseCount := 0
	if set2 != nil {
		key, keyErr := set2.SelectUsableEncryptionKey(now, foundation.CryptoX25519, foundation.CryptoMLKEM1024X25519, foundation.CryptoMLKEM768X25519)
		if keyErr != nil {
			return route, keyErr
		}
		route.KeyType, route.KeyData = key.Type, append([]byte(nil), key.Data...)
		lease, err = selectLease2(*set2, now, pick)
		leaseCount = set2.LeaseCount()
		route.Expires = leaseSet2Deadline(*set2)
		if encrypted {
			route.Expires = min(route.Expires, encryptedExpires)
		}
	} else {
		route.Legacy = true
		lease, route.LegacyKey, err = selectLegacyLease(*legacy, now, pick)
		leaseCount = legacy.LeaseCount()
		route.Expires = lease.EndDate
	}
	if err != nil {
		return route, err
	}
	var outbound controlplanetunnel.Entry
	var circuit dataplane.TunnelCircuitInfo
	found := false
	entries := s.pool.Snapshot(now)
	for attempt := 0; attempt < leaseCount && !found; attempt++ {
		if attempt != 0 {
			if set2 != nil {
				lease, err = selectLease2(*set2, now, pick+uint64(attempt))
			} else {
				lease, _, err = selectLegacyLease(*legacy, now, pick+uint64(attempt))
			}
			if err != nil {
				return route, err
			}
		}
		for _, entry := range entries {
			if entry.Direction != controlplanetunnel.Outbound || entry.Owner != s.owner {
				continue
			}
			candidate, ok := s.tunnels.InspectCircuit(entry.ID)
			if !ok || candidate.Token != entry.Circuit || candidate.Owner != s.owner {
				continue
			}
			if candidate.ExpiresAt != 0 && candidate.ExpiresAt <= now {
				continue
			}
			s.remoteMu.RLock()
			failedUntil := s.failedRoutes[failedRoutePath{remote: remote, circuit: entry.Circuit, gateway: lease.Gateway, tunnelID: lease.TunnelID}]
			s.remoteMu.RUnlock()
			if failedUntil > now || (found && entry.Expires <= outbound.Expires) {
				continue
			}
			outbound, circuit, found = entry, candidate, true
		}
	}
	if !found {
		return route, dataplane.TunnelErrCircuitNotFound
	}
	if route.Legacy {
		route.Expires = lease.EndDate
	}
	if circuit.ExpiresAt != 0 {
		route.Expires = min(route.Expires, circuit.ExpiresAt)
	}
	route.Gateway, route.TunnelID, route.Circuit = lease.Gateway, lease.TunnelID, outbound.Circuit
	route.Expires = min(route.Expires, lease.EndDate, outbound.Expires)
	if storeType, stored, ok := s.database.StoredLeaseSet(s.owner); ok {
		if route.Legacy || storeType == foundation.I2NPStoreLeaseSet2 {
			localExpires, deadlineErr := localLeaseSetDeadline(storeType, stored, now)
			if deadlineErr != nil {
				return route, deadlineErr
			}
			route.Expires = min(route.Expires, localExpires)
			route.LocalLeaseSet, err = foundation.NetworkDatabaseMarshalDatabaseStore(s.owner, storeType, stored, 0, foundation.Hash{}, 0)
			if err != nil {
				return route, err
			}
			route.LocalLeaseSet2 = storeType == foundation.I2NPStoreLeaseSet2
		}
	}
	if route.Expires <= now {
		return route, dataplane.RouterErrLeaseSetExpired
	}
	if s.prepareTunnel != nil {
		if err := s.prepareTunnel(ctx, circuit.FirstHop); err != nil {
			return route, err
		}
	}
	s.seedLeaseGateway(ctx, outbound, lease.Gateway)
	return route, nil
}

func leaseSet2Deadline(set foundation.NetworkDatabaseLeaseSet2) uint64 {
	expires := (uint64(set.Header.Published) + uint64(set.Header.Expires)) * 1000
	if set.Header.Offline.Present() {
		expires = min(expires, uint64(set.Header.Offline.Expires)*1000)
	}
	return expires
}

func localLeaseSetDeadline(kind foundation.I2NPStoreType, raw []byte, now uint64) (uint64, error) {
	if kind == foundation.I2NPStoreLeaseSet2 {
		set, err := foundation.NetworkDatabaseParseLeaseSet2(raw)
		if err != nil {
			return 0, err
		}
		var latest uint64
		leases := set.Leases()
		for {
			lease, ok, err := leases.Next()
			if err != nil {
				return 0, err
			}
			if !ok {
				break
			}
			latest = max(latest, uint64(lease.EndDate)*1000)
		}
		expires := min(leaseSet2Deadline(set), latest)
		if expires <= now {
			return 0, dataplane.RouterErrLeaseSetExpired
		}
		return expires, nil
	}
	set, err := foundation.NetworkDatabaseParseLeaseSet(raw)
	if err != nil {
		return 0, err
	}
	var expires uint64
	leases := set.Leases()
	for {
		lease, ok, err := leases.Next()
		if err != nil {
			return 0, err
		}
		if !ok {
			break
		}
		expires = max(expires, lease.EndDate)
	}
	if expires <= now {
		return 0, dataplane.RouterErrLeaseSetExpired
	}
	return expires, nil
}

type streamingSeedCacheEntry struct {
	endpoint   foundation.Hash
	gateway    foundation.Hash
	expires    uint64
	retryAfter uint64
}

func ValidateRemoteELSContexts(policies map[foundation.Hash]RemoteELSContext) error {
	validated, err := cloneValidatedRemoteELS(policies)
	releaseRemoteELSPolicies(validated)
	return err
}

func cloneValidatedRemoteELS(policies map[foundation.Hash]RemoteELSContext) (map[foundation.Hash]RemoteELSContext, error) {
	updated := make(map[foundation.Hash]RemoteELSContext, len(policies))
	for hash, policy := range policies {
		cloneValidatedRemoteELSSelected := hash == (foundation.Hash{}) || policy.Identity.Hash() != hash || len(policy.Identity.Bytes()) == 0 || len(policy.Secret) > 0xffff
		if !cloneValidatedRemoteELSSelected {
			cloneValidatedRemoteELSSelected = (policy.Authorization.UseDH && policy.Authorization.UsePSK)
		}
		if cloneValidatedRemoteELSSelected {
			releaseRemoteELSPolicies(updated)
			return nil, dataplane.RouterErrDataPlaneConfig
		}
		if policy.Authorization.UseDH {
			private, privateErr := ecdh.X25519().NewPrivateKey(policy.Authorization.DHPrivate[:])
			public, publicErr := ecdh.X25519().NewPublicKey(policy.Authorization.DHPublic[:])
			if privateErr != nil || publicErr != nil || !bytes.Equal(private.PublicKey().Bytes(), public.Bytes()) {
				releaseRemoteELSPolicies(updated)
				return nil, dataplane.RouterErrDataPlaneConfig
			}
		}
		policy.Secret = append([]byte(nil), policy.Secret...)
		updated[hash] = policy
	}
	return updated, nil
}

func releaseRemoteELSPolicies(policies map[foundation.Hash]RemoteELSContext) {
	for hash, policy := range policies {
		clear(policy.Secret)
		clear(policy.Authorization.DHPrivate[:])
		clear(policy.Authorization.DHPublic[:])
		clear(policy.Authorization.PSK[:])
		policies[hash] = policy
		delete(policies, hash)
	}
}
func (s *StreamingTunnelSender) seedLeaseGateway(ctx context.Context, outbound controlplanetunnel.Entry, gateway foundation.Hash) {
	if s.seedRouterInfo == nil || outbound.HopCount == 0 || gateway == (foundation.Hash{}) {
		return
	}
	endpoint := outbound.Hops[outbound.HopCount-1]
	if endpoint == (foundation.Hash{}) {
		return
	}
	now := s.now()
	s.seedMu.Lock()
	slot := -1
	for index := range s.seedCache {
		entry := s.seedCache[index]
		if entry.endpoint == endpoint && entry.gateway == gateway {
			if entry.expires > now || entry.retryAfter > now {
				s.seedMu.Unlock()
				return
			}
			slot = index
			break
		}
		if slot == -1 && entry.expires <= now && entry.retryAfter <= now {
			slot = index
		}
	}
	if slot == -1 {
		slot = int(s.seedNext) % len(s.seedCache)
		s.seedNext = uint8((slot + 1) % len(s.seedCache))
	}
	entry := streamingSeedCacheEntry{endpoint: endpoint, gateway: gateway}
	if err := s.seedRouterInfo(ctx, endpoint, gateway); err != nil {
		entry.retryAfter = routeDeadline(now, streamingSeedFailureBackoff)
	} else {
		entry.expires = outbound.Expires
		if entry.expires <= now {
			entry.expires = routeDeadline(now, streamingSeedFailureBackoff)
		}
	}
	s.seedCache[slot] = entry
	s.seedMu.Unlock()
}
func (s *StreamingTunnelSender) resolveLeaseSet(ctx context.Context, target foundation.Hash) (*foundation.NetworkDatabaseLeaseSet2, *foundation.NetworkDatabaseLeaseSet, error) {
	if err := s.lookupLeaseSet(ctx, target); err != nil {
		return nil, nil, err
	}
	if set, ok := s.database.LeaseSet2(target); ok {
		return &set, nil, nil
	}
	if set, ok := s.database.LeaseSet(target); ok {
		return nil, &set, nil
	}
	return nil, nil, dataplane.RouterErrLeaseSetUnavailable
}

func (s *StreamingTunnelSender) resolveEncryptedLeaseSet(ctx context.Context, policy RemoteELSContext) (*foundation.NetworkDatabaseLeaseSet2, uint64, error) {
	key, err := encryptedLeaseSetDHTKey(policy.Identity, policy.Secret, s.now())
	if err != nil {
		return nil, 0, err
	}
	if err := s.lookupLeaseSet(ctx, key); err != nil {
		return nil, 0, err
	}
	set, found := s.database.EncryptedLeaseSet(key)
	if !found {
		return nil, 0, dataplane.RouterErrLeaseSetUnavailable
	}
	inner, err := controlplanenetdb.DecryptEncryptedLeaseSet(set, policy.Identity, policy.Secret, policy.Authorization, s.now())
	if err != nil {
		return nil, 0, err
	}
	expires := (uint64(set.Published) + uint64(set.Expires)) * 1000
	if set.Offline.Present() {
		expires = min(expires, uint64(set.Offline.Expires)*1000)
	}
	// Blinding keys change at UTC midnight even if an outer record lives longer.
	expires = min(expires, (s.now()/86_400_000+1)*86_400_000)
	return &inner, expires, nil
}

func (s *StreamingTunnelSender) lookupLeaseSet(ctx context.Context, key foundation.Hash) error {
	result, err := s.requests.LookupLeaseSet(ctx, key)
	if err != nil {
		return err
	}
	select {
	case outcome, ok := <-result:
		if !ok {
			return dataplane.RouterErrLeaseSetUnavailable
		}
		return outcome.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func encryptedLeaseSetDHTKey(identity foundation.Identity, secret []byte, now uint64) (foundation.Hash, error) {
	kind := identity.SigningKeyType()
	public, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		return foundation.Hash{}, controlplanenetdb.ErrEncryptedLeaseSet
	}
	blinded, err := foundation.BlindEncryptedLeaseSetPublic(kind, public, time.UnixMilli(int64(now)), secret)
	if err != nil {
		return foundation.Hash{}, err
	}
	var input [34]byte
	binary.BigEndian.PutUint16(input[:2], uint16(foundation.SigningRedDSASHA512Ed25519))
	copy(input[2:], blinded[:])
	return foundation.Sum(input[:]), nil
}

func selectLease2(set foundation.NetworkDatabaseLeaseSet2, now uint64, pick uint64) (foundation.NetworkDatabaseLease, error) {
	iterator := set.Leases()
	var usable uint64
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return foundation.NetworkDatabaseLease{}, err
		}
		if !ok {
			break
		}
		if uint64(lease.EndDate)*1000 > now {
			usable++
		}
	}
	if usable == 0 {
		return foundation.NetworkDatabaseLease{}, dataplane.RouterErrLeaseSetExpired
	}

	selected := pick % usable
	iterator = set.Leases()
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return foundation.NetworkDatabaseLease{}, err
		}
		if !ok {
			return foundation.NetworkDatabaseLease{}, dataplane.RouterErrLeaseSetExpired
		}
		end := uint64(lease.EndDate) * 1000
		if end <= now {
			continue
		}
		if selected == 0 {
			return foundation.NetworkDatabaseLease{Gateway: lease.Gateway, TunnelID: lease.TunnelID, EndDate: end}, nil
		}
		selected--
	}
}

func selectLegacyLease(set foundation.NetworkDatabaseLeaseSet, now uint64, pick uint64) (foundation.NetworkDatabaseLease, cryptography.ElGamalPublicKey, error) {
	if len(set.EncryptionKey) != cryptography.ElGamalPublicKeySize {
		return foundation.NetworkDatabaseLease{}, cryptography.ElGamalPublicKey{}, dataplane.RouterErrUnsupportedEncryption
	}
	var recipient cryptography.ElGamalPublicKey
	copy(recipient[:], set.EncryptionKey)

	iterator := set.Leases()
	var usable uint64
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return foundation.NetworkDatabaseLease{}, cryptography.ElGamalPublicKey{}, err
		}
		if !ok {
			break
		}
		if lease.EndDate > now {
			usable++
		}
	}
	if usable == 0 {
		return foundation.NetworkDatabaseLease{}, cryptography.ElGamalPublicKey{}, dataplane.RouterErrLeaseSetExpired
	}

	selected := pick % usable
	iterator = set.Leases()
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return foundation.NetworkDatabaseLease{}, cryptography.ElGamalPublicKey{}, err
		}
		if !ok {
			return foundation.NetworkDatabaseLease{}, cryptography.ElGamalPublicKey{}, dataplane.RouterErrLeaseSetExpired
		}
		if lease.EndDate <= now {
			continue
		}
		if selected == 0 {
			return lease, recipient, nil
		}
		selected--
	}
}

func routeDeadline(now, lifetime uint64) uint64 {
	if ^uint64(0)-now < lifetime {
		return ^uint64(0)
	}
	return now + lifetime
}
