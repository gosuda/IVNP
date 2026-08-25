package networkdatabase

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/observability"
	"io"
	"sync"
)

var (
	// ErrRequestManagerFull means the configured bounded pending-request limit
	// has been reached.
	ErrRequestManagerFull = errors.New("netdb: request manager is full")
	// ErrConflictingLookup means a lookup for the same key is already pending
	// with a different lookup type.
	ErrConflictingLookup = errors.New("netdb: conflicting lookup is pending")
	// ErrRequestExpired is delivered to every coalesced caller when a lookup
	// reaches its deadline without receiving its requested DatabaseStore.
	ErrRequestExpired = errors.New("netdb: lookup request expired")
	// ErrNoFloodfill means no known floodfill (or searchable candidate) could
	// receive the lookup.
	ErrNoFloodfill          = errors.New("netdb: no floodfill route for lookup")
	ErrInvalidReplyRoute    = errors.New("netdb: invalid lookup reply route")
	ErrRequestManagerClosed = errors.New("netdb: request manager is closed")
)

const (
	databaseLookupEnvelopeLifetime  uint64 = 20_000
	databaseLookupAttemptTimeout    uint64 = 3_000
	javaIterativeSearchLimit               = 5
	javaIterativeSearchInitialPeers        = 5
)

// LookupType selects the I2NP DatabaseLookup object type.
type LookupType uint8

const (
	// RouterInfoLookup and LeaseSetLookup are the I2NP wire values, not an
	// internal ordinal. Zero is legacy "any" and is accepted only inbound.
	LeaseSetLookup    LookupType = 1
	RouterInfoLookup  LookupType = 2
	ExplorationLookup LookupType = 3
)

// RequestSender sends a DatabaseLookup to a directly reachable floodfill.
// Message.Payload is borrowed and may only be retained by copying it.
type RequestSender interface {
	Send(context.Context, RouterRef, i2np.Message) error
}

// ReplyRoute supplies the route advertised in a DatabaseLookup. Gateway is the
// local router hash to which the floodfill should send the answer. When Tunnel
// is true, TunnelID must identify the inbound reply tunnel at that gateway.
type ReplyRoute interface {
	DatabaseLookupReplyRoute() (gateway foundation.Hash, tunnelID uint32, tunnel bool)
}

// RequestManagerConfig controls logical request lifetime and bounded work. Now
// returns Unix milliseconds. DatabaseLookup envelopes expire after a separate,
// fixed lifetime. Rand supplies I2NP message IDs and is injectable so tests can
// be deterministic.
type RequestManagerConfig struct {
	Capacity      int
	MaxCandidates int
	MaxWaiters    int
	TimeoutMillis uint64
	Now           func() uint64
	Rand          io.Reader
	Metrics       *observability.Registry
	Responders    *ResponderProfiles
}

// LookupResult reports the terminal state of one caller's lookup. The object
// itself is retained in Database; callers fetch it from Database after Err is
// nil.
type LookupResult struct {
	Key  foundation.Hash
	Type LookupType
	Err  error
}

type requestKey struct {
	key foundation.Hash
}

type pendingRequest struct {
	key              foundation.Hash
	typeID           LookupType
	deadline         uint64
	responseDeadline uint64
	routingKey       foundation.Hash
	seed             foundation.Hash
	waiters          []chan LookupResult
	candidates       []foundation.Hash
	candidate        map[foundation.Hash]struct{}
	attempted        map[foundation.Hash]struct{}
	sent             map[foundation.Hash]struct{}
	fallbacks        []foundation.Hash
	refreshing       map[foundation.Hash]struct{}
	inFlight         bool
	wakeups          int
}

type sendWork struct {
	key        requestKey
	typeID     LookupType
	peer       RouterRef
	exclusions []foundation.Hash
}
type sendJob struct {
	work sendWork
	done chan struct{}
}

// RequestManager drives bounded, iterative DatabaseLookup requests without a
// dependency on router or tunnel implementations. DatabaseStore admission is
// intentionally upstream: call HandleDatabaseStore only after Database has
// accepted the store.
type RequestManager struct {
	database *Database
	sender   RequestSender
	route    ReplyRoute

	metrics       *observability.Registry
	capacity      int
	maxCandidates int
	maxWaiters    int
	timeoutMillis uint64
	now           func() uint64
	responders    *ResponderProfiles
	rand          io.Reader
	randMu        sync.Mutex

	mu      sync.Mutex
	pending map[requestKey]*pendingRequest
	closed  bool
	active  sync.WaitGroup
	workers sync.WaitGroup
	jobs    chan sendJob
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewRequestManager creates a bounded request manager. A clock is required so
// expiry policy remains deterministic and owned by the caller's scheduler.
func NewRequestManager(database *Database, sender RequestSender, route ReplyRoute, config RequestManagerConfig) (*RequestManager, error) {
	if database == nil || sender == nil || route == nil {
		return nil, errors.New("netdb: request manager requires database, sender, and reply route")
	}
	if config.Capacity <= 0 {
		return nil, errors.New("netdb: request manager capacity must be positive")
	}
	if config.MaxCandidates <= 0 {
		config.MaxCandidates = 16
	}
	if config.MaxCandidates > i2np.MaxDatabaseLookupExcluded {
		return nil, errors.New("netdb: request manager candidate limit exceeds lookup exclusions")
	}
	if config.MaxWaiters <= 0 {
		config.MaxWaiters = 64
	}
	if config.TimeoutMillis == 0 {
		return nil, errors.New("netdb: request manager timeout must be positive")
	}
	if config.Now == nil {
		return nil, errors.New("netdb: request manager requires a clock")
	}
	if config.Rand == nil {
		config.Rand = cryptorand.Reader
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	workerCount := parallelism.Workers(config.Capacity)
	manager := &RequestManager{
		database:      database,
		sender:        sender,
		route:         route,
		metrics:       config.Metrics,
		capacity:      config.Capacity,
		maxCandidates: config.MaxCandidates,
		maxWaiters:    config.MaxWaiters,
		timeoutMillis: config.TimeoutMillis,
		now:           config.Now,
		responders:    config.Responders,
		rand:          config.Rand,
		pending:       make(map[requestKey]*pendingRequest, config.Capacity),
		jobs:          make(chan sendJob, config.Capacity),
		ctx:           lifecycle,
		cancel:        cancel,
	}
	manager.workers.Add(workerCount)
	for range workerCount {
		go manager.worker()
	}
	return manager, nil
}

// LookupRouterInfo starts or coalesces a RouterInfo lookup.
func (m *RequestManager) LookupRouterInfo(ctx context.Context, key foundation.Hash) (<-chan LookupResult, error) {
	return m.Lookup(ctx, RouterInfoLookup, key)
}

// LookupLeaseSet starts or coalesces a LeaseSet lookup. Any LeaseSet store
// variant completes this request.
func (m *RequestManager) LookupLeaseSet(ctx context.Context, key foundation.Hash) (<-chan LookupResult, error) {
	return m.Lookup(ctx, LeaseSetLookup, key)
}

func (m *RequestManager) Lookup(ctx context.Context, typeID LookupType, key foundation.Hash) (<-chan LookupResult, error) {
	return m.lookup(ctx, typeID, key, false)
}

func (m *RequestManager) lookup(ctx context.Context, typeID LookupType, key foundation.Hash, forceRefresh bool) (<-chan LookupResult, error) {
	if typeID != RouterInfoLookup && typeID != LeaseSetLookup && typeID != ExplorationLookup {
		return nil, errors.New("netdb: unknown lookup type")
	}
	if ctx ==
		nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrRequestManagerClosed
	}
	m.mu.Unlock()
	result := make(chan LookupResult, 1)
	if !forceRefresh && m.lookupPresent(typeID, key) {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrRequestManagerClosed
		}
		m.mu.Unlock()
		result <- LookupResult{Key: key, Type: typeID}
		close(result)
		return result, nil
	}

	lookupKey := requestKey{key: key}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrRequestManagerClosed
	}
	if existing := m.pending[lookupKey]; existing != nil {
		if existing.typeID != typeID {
			m.mu.Unlock()
			return nil, ErrConflictingLookup
		}
		if len(existing.waiters) == m.maxWaiters {
			m.mu.Unlock()
			return nil, ErrRequestManagerFull
		}
		existing.waiters = append(existing.waiters, result)
		m.mu.Unlock()
		return result, nil
	}
	if len(m.pending) == m.capacity {
		m.mu.Unlock()
		return nil, ErrRequestManagerFull
	}
	now := m.now()
	allTargets := m.database.FloodTargetsAt(make([]RouterRef, m.maxCandidates), key, now)
	deadline := now + m.timeoutMillis
	if deadline < now {
		deadline = ^uint64(0)
	}
	req := &pendingRequest{
		key:        key,
		typeID:     typeID,
		routingKey: RoutingKey(key, now),
		deadline:   deadline,
		waiters:    []chan LookupResult{result},
		candidates: make([]foundation.Hash, 0, m.maxCandidates),
		candidate:  make(map[foundation.Hash]struct{}, m.maxCandidates),
		attempted:  make(map[foundation.Hash]struct{}, m.maxCandidates),
		sent:       make(map[foundation.Hash]struct{}, javaIterativeSearchLimit),
		refreshing: make(map[foundation.Hash]struct{}, m.maxCandidates),
		fallbacks:  make([]foundation.Hash, 0, len(allTargets)),
	}
	if m.responders != nil {
		responsive := m.responders.Candidates(make([]foundation.Hash, 0, 1))
		for _, candidate := range responsive {
			if ref, known := m.database.Routers().Get(candidate); known && ref.Floodfill && m.addCandidateLocked(req, candidate) {
				req.seed = candidate
			}
		}
	}
	for _, target := range allTargets {
		if _, exists := req.candidate[target.Hash]; exists {
			continue
		}
		if len(req.candidates) < javaIterativeSearchInitialPeers {
			m.addCandidateLocked(req, target.Hash)
			continue
		}
		req.fallbacks = append(req.fallbacks, target.Hash)
	}
	m.pending[lookupKey] = req
	work, terminal := m.prepareSendLocked(lookupKey, req)
	if terminal != nil {
		m.completeLocked(lookupKey, req, terminal)
	}
	m.mu.Unlock()
	if work != nil {
		m.dispatch(*work, true)
	}
	return result, nil
}

// Explore sends a type-3 DatabaseLookup through the same bounded request
// lifecycle as ordinary lookup work.
func (m *RequestManager) Explore(ctx context.Context, key foundation.Hash) (<-chan LookupResult, error) {
	return m.Lookup(ctx, ExplorationLookup, key)
}

// BuildDatabaseLookup serializes the unencrypted RouterInfo or LeaseSet lookup
// format parsed by i2np.ParseDatabaseLookup. Exclusions are copied directly as
// 32-byte hashes and must be the peers already queried by this request.
func BuildDatabaseLookup(key foundation.Hash, typeID LookupType, route ReplyRoute, exclusions []foundation.Hash) ([]byte, error) {
	if route == nil || len(exclusions) > i2np.MaxDatabaseLookupExcluded {
		return nil, ErrInvalidReplyRoute
	}
	gateway, tunnelID, tunnel := route.DatabaseLookupReplyRoute()
	if gateway == (foundation.Hash{}) || (tunnel && tunnelID == 0) {
		return nil, ErrInvalidReplyRoute
	}
	flags := byte(typeID << 2)
	switch typeID {
	case RouterInfoLookup, LeaseSetLookup, ExplorationLookup:
	default:
		return nil, errors.New("netdb: unknown lookup type")
	}
	length := 32 + 32 + 1 + 2 + len(exclusions)*foundation.HashLength
	if tunnel {
		flags |= 1
		length += 4
	}
	payload := make([]byte, length)
	copy(payload[:32], key[:])
	copy(payload[32:64], gateway[:])
	payload[64] = flags
	off := 65
	if tunnel {
		binary.BigEndian.PutUint32(payload[off:off+4], tunnelID)
		off += 4
	}
	binary.BigEndian.PutUint16(payload[off:off+2], uint16(len(exclusions)))
	off += 2
	for _, exclusion := range exclusions {
		copy(payload[off:off+foundation.HashLength], exclusion[:])
		off += foundation.HashLength
	}
	return payload, nil
}

// HandleDatabaseSearchReply incorporates reachable peers from an answer to a
// live lookup and sends the next unqueried peer. Referred RouterInfos are
// refreshed before use so a stale local entry cannot consume the query budget.
// Unsolicited replies cannot steer a request: From must be one of the peers
// already queried for its key.
func (m *RequestManager) HandleDatabaseSearchReply(reply i2np.DatabaseSearchReplyMessage) {
	lookupKey := requestKey{key: reply.Key}
	var refresh []foundation.Hash
	m.mu.Lock()
	req := m.pending[lookupKey]
	if req == nil {
		m.mu.Unlock()
		return
	}
	if _, queried := req.sent[reply.From]; !queried {
		m.mu.Unlock()
		return
	}
	if m.responders != nil {
		m.responders.Record(reply.From)
	}
	req.responseDeadline = 0
	for off := 0; off < len(reply.Peers) && len(req.candidates) < m.maxCandidates; off += foundation.HashLength {
		var peer foundation.Hash
		copy(peer[:], reply.Peers[off:off+foundation.HashLength])
		if !m.addCandidateLocked(req, peer) {
			continue
		}
		if _, known := m.database.Routers().Get(peer); !known || req.typeID == LeaseSetLookup {
			req.refreshing[peer] = struct{}{}
			refresh = append(refresh, peer)
		}
	}
	var work *sendWork
	if req.inFlight {
		m.addWakeupLocked(req)
	} else if req.typeID != LeaseSetLookup || len(req.refreshing) == 0 {
		var terminal error
		work, terminal = m.prepareSendLocked(lookupKey, req)
		if terminal != nil {
			m.completeLocked(lookupKey, req, terminal)
		} else if work == nil && req.typeID == ExplorationLookup && allCandidatesSent(req) {
			m.completeLocked(lookupKey, req, nil)
		}
	}
	m.mu.Unlock()
	var refreshFailed []foundation.Hash
	for _, peer := range refresh {
		if _, err := m.lookup(m.ctx, RouterInfoLookup, peer, true); err != nil {
			refreshFailed = append(refreshFailed, peer)
		}
	}
	if len(refreshFailed) != 0 {
		m.mu.Lock()
		req = m.pending[lookupKey]
		if req != nil {
			for _, peer := range refreshFailed {
				delete(req.refreshing, peer)
			}
			if !req.inFlight {
				var terminal error
				work, terminal = m.prepareSendLocked(lookupKey, req)
				if terminal != nil {
					m.completeLocked(lookupKey, req, terminal)
				}
			}
		}
		m.mu.Unlock()
	}
	if work != nil {
		m.dispatch(*work, true)
	}
}

// HandleDatabaseStore completes a matching request after the caller has
// verified and admitted the store into Database. A RouterInfo store also wakes
// lookups that learned its hash from a DatabaseSearchReply.
func (m *RequestManager) HandleDatabaseStore(store i2np.DatabaseStoreMessage) {
	var work []sendWork
	m.mu.Lock()
	for key, req := range m.pending {
		if req.key == store.Key && storeMatches(req.typeID, store.Type) {
			m.completeLocked(key, req, nil)
			continue
		}
		if store.Type != i2np.StoreRouterInfo {
			continue
		}
		if _, wanted := req.candidate[store.Key]; !wanted {
			continue
		}
		delete(req.refreshing, store.Key)
		if req.inFlight {
			m.addWakeupLocked(req)
			continue
		}
		if next, terminal := m.prepareSendLocked(key, req); terminal != nil {
			m.completeLocked(key, req, terminal)
		} else if next != nil {
			work = append(work, *next)
		}
	}
	m.mu.Unlock()
	for i := range work {
		m.dispatch(work[i], true)
	}
}

// Expire retries a silent floodfill after the bounded per-attempt deadline and
// completes requests whose overall deadline is no longer in the future.
func (m *RequestManager) Expire(nowMillis uint64) int {
	m.mu.Lock()
	removed := 0
	work := make([]sendWork, 0)
	for key, req := range m.pending {
		expired, next := m.expireLocked(key, req, nowMillis)
		if expired {
			removed++
		}
		if next != nil {
			work = append(work, *next)
		}
	}
	m.mu.Unlock()
	for i := range work {
		m.dispatch(work[i], true)
	}
	return removed
}

func (m *RequestManager) expireLocked(key requestKey, req *pendingRequest, nowMillis uint64) (bool, *sendWork) {
	if req.deadline <= nowMillis {
		m.completeLocked(key, req, ErrRequestExpired)
		return true, nil
	}
	if req.inFlight || req.responseDeadline == 0 || req.responseDeadline > nowMillis {
		return false, nil
	}
	req.responseDeadline = 0
	next, terminal := m.prepareSendLocked(key, req)
	if terminal != nil {
		m.completeLocked(key, req, terminal)
		return true, nil
	}
	if next != nil {
		return false, next
	}
	if !allCandidatesSent(req) {
		return false, nil
	}
	if req.typeID == ExplorationLookup {
		m.completeLocked(key, req, nil)
	} else {
		m.completeLocked(key, req, ErrRequestExpired)
	}
	return true, nil
}

// Close rejects new lookup work, completes every waiter, and joins any
// in-flight sender call before returning. It is safe to call more than once.
func (m *RequestManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	closing := false
	if !m.closed {
		if m.cancel != nil {
			m.cancel()
		}
		m.closed = true
		closing = true
		for key, req := range m.pending {
			m.completeLocked(key, req, ErrRequestManagerClosed)
		}
	}
	m.mu.Unlock()
	if closing {
		m.active.Wait()
		close(m.jobs)
	}
	m.workers.Wait()
	return nil
}

// Pending returns the number of distinct keys being looked up.
func (m *RequestManager) Pending() int {
	m.mu.Lock()
	n := len(m.pending)
	m.mu.Unlock()
	return n
}

func (m *RequestManager) lookupPresent(typeID LookupType, key foundation.Hash) bool {
	switch typeID {
	case RouterInfoLookup:
		_, ok := m.database.Routers().Get(key)
		return ok
	case LeaseSetLookup:
		if _, ok := m.database.LeaseSet(key); ok {
			return true
		}
		if _, ok := m.database.LeaseSet2(key); ok {
			return true
		}
		if _, ok := m.database.MetaLeaseSet(key); ok {
			return true
		}
		_, ok := m.database.EncryptedLeaseSet(key)
		return ok
	default:
		return false
	}
}

func (m *RequestManager) addCandidateLocked(req *pendingRequest, peer foundation.Hash) bool {
	if len(req.candidates) == m.maxCandidates {
		return false
	}
	if _, exists := req.candidate[peer]; exists {
		return false
	}
	req.candidate[peer] = struct{}{}
	req.candidates = append(req.candidates, peer)
	return true
}
func (m *RequestManager) promoteFallbackLocked(req *pendingRequest) {
	for len(req.fallbacks) != 0 && len(req.candidates) < m.maxCandidates {
		peer := req.fallbacks[0]
		req.fallbacks = req.fallbacks[1:]
		if m.addCandidateLocked(req, peer) {
			return
		}
	}
}

func (m *RequestManager) addWakeupLocked(req *pendingRequest) {
	if req.wakeups < m.maxCandidates {
		req.wakeups++
	}
}

func (m *RequestManager) prepareSendLocked(key requestKey, req *pendingRequest) (*sendWork, error) {
	if req.inFlight {
		return nil, nil
	}
	if req.deadline <= m.now() {
		return nil, ErrRequestExpired
	}
	if len(req.sent) >= min(m.maxCandidates, javaIterativeSearchLimit) {
		return nil, ErrRequestExpired
	}
	var selected foundation.Hash
	var peer RouterRef
	found := false
	if req.seed != (foundation.Hash{}) && len(req.attempted) == 0 {
		if current, known := m.database.Routers().Get(req.seed); known {
			selected, peer, found = req.seed, current, true
		}
	}
	if !found {
		for _, candidate := range req.candidates {
			if _, attempted := req.attempted[candidate]; attempted {
				continue
			}
			if _, refreshing := req.refreshing[candidate]; refreshing {
				continue
			}
			current, known := m.database.Routers().Get(candidate)
			if !known {
				continue
			}
			if !found || distanceLess(req.routingKey, candidate, selected) {
				selected, peer, found = candidate, current, true
			}
		}
	}
	if found {
		req.attempted[selected] = struct{}{}
		req.sent[selected] = struct{}{}
		req.inFlight = true
		exclusions := make([]foundation.Hash, 0, len(req.sent))
		for _, exclusion := range req.candidates {
			if _, sent := req.sent[exclusion]; sent {
				exclusions = append(exclusions, exclusion)
			}
		}
		return &sendWork{key: key, typeID: req.typeID, peer: peer, exclusions: exclusions}, nil
	}
	if len(req.sent) == 0 {
		return nil, ErrNoFloodfill
	}
	return nil, nil
}

func (m *RequestManager) dispatch(work sendWork, wait bool) {
	m.mu.Lock()
	if m.closed {
		if req := m.pending[work.key]; req != nil {
			m.completeLocked(work.key, req, ErrRequestManagerClosed)
		}
		m.mu.Unlock()
		return
	}
	m.active.Add(1)
	m.mu.Unlock()
	job := sendJob{work: work}
	if wait {
		job.done = make(chan struct{})
	}
	m.jobs <- job
	if job.done != nil {
		<-job.done
	}
}

func (m *RequestManager) worker() {
	defer m.workers.Done()
	for job := range m.jobs {
		m.send(job.work)
		m.active.Done()
		if job.done != nil {
			close(job.done)
		}
	}
}

func (m *RequestManager) send(work sendWork) {
	payload, err := BuildDatabaseLookup(work.key.key, work.typeID, m.route, work.exclusions)
	if err == nil {
		var id uint32
		if id, err = m.nextMessageID(); err == nil {
			message := i2np.Message{Header: i2np.Header{Type: i2np.DatabaseLookup, ID: id, Expiration: databaseLookupExpiration(m.now())}, Payload: payload}
			err = m.sender.Send(m.ctx, work.peer, message)
		}
	}
	if m.metrics != nil {
		if err == nil {
			m.metrics.IncNetDBLookups()
		} else {
			m.metrics.IncNetDBLookupFailures()
		}
	}
	if err == nil {
		var next *sendWork
		m.mu.Lock()
		if req := m.pending[work.key]; req != nil {
			req.inFlight = false
			req.responseDeadline = min(req.deadline, saturatingAddMillis(m.now(), databaseLookupAttemptTimeout))
			if req.wakeups > 0 {
				req.wakeups--
				req.responseDeadline = 0
				next, err = m.prepareSendLocked(work.key, req)
				if err != nil {
					m.completeLocked(work.key, req, err)
				}
			}
		}
		m.mu.Unlock()
		if next != nil {
			m.send(*next)
		}
		return
	}

	m.mu.Lock()
	req := m.pending[work.key]
	if req == nil {
		m.mu.Unlock()
		return
	}
	delete(req.sent, work.peer.Hash)
	m.promoteFallbackLocked(req)
	req.inFlight = false
	next, terminal := m.prepareSendLocked(work.key, req)
	if next == nil && terminal == nil {
		terminal = err
	}
	if terminal != nil {
		m.completeLocked(work.key, req, terminal)
	}
	m.mu.Unlock()
	if next != nil {
		m.send(*next)
	}
}

func allCandidatesSent(req *pendingRequest) bool {
	for _, candidate := range req.candidates {
		if _, attempted := req.attempted[candidate]; !attempted {
			return false
		}
	}
	return len(req.candidates) != 0
}

func saturatingAddMillis(now, delta uint64) uint64 {
	if ^uint64(0)-now < delta {
		return ^uint64(0)
	}
	return now + delta
}

func (m *RequestManager) nextMessageID() (uint32, error) {
	var bytes [4]byte
	m.randMu.Lock()
	_, err := io.ReadFull(m.rand, bytes[:])
	m.randMu.Unlock()
	return binary.BigEndian.Uint32(bytes[:]), err
}

func databaseLookupExpiration(now uint64) uint64 {
	if ^uint64(0)-now < databaseLookupEnvelopeLifetime {
		return ^uint64(0)
	}
	return now + databaseLookupEnvelopeLifetime
}

func (m *RequestManager) completeLocked(key requestKey, req *pendingRequest, err error) {
	delete(m.pending, key)
	result := LookupResult{Key: req.key, Type: req.typeID, Err: err}
	for _, waiter := range req.waiters {
		waiter <- result
		close(waiter)
	}
}

func storeMatches(typeID LookupType, storeType i2np.StoreType) bool {
	if typeID == RouterInfoLookup {
		return storeType == i2np.StoreRouterInfo
	}
	switch storeType {
	case i2np.StoreLeaseSet, i2np.StoreLeaseSet2, i2np.StoreMetaLeaseSet, i2np.StoreEncryptedLeaseSet:
		return true
	default:
		return false
	}
}
