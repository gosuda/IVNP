package netdb

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"sync"
	"testing"
	"time"
)

type requestTestRoute struct {
	gateway   ivnp.Hash
	tunnel    uint32
	viaTunnel bool
}

func (r requestTestRoute) DatabaseLookupReplyRoute() (ivnp.Hash, uint32, bool) {
	return r.gateway, r.tunnel, r.viaTunnel
}

type requestTestSender struct {
	mu       sync.Mutex
	messages []i2np.Message
	contexts []error
	err      error
}

func (s *requestTestSender) Send(ctx context.Context, _ RouterRef, message i2np.Message) error {
	s.mu.Lock()
	message.Payload = append([]byte(nil), message.Payload...)
	s.messages = append(s.messages, message)
	s.contexts = append(s.contexts, ctx.Err())
	s.mu.Unlock()
	return s.err
}

func (s *requestTestSender) snapshot() []i2np.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]i2np.Message(nil), s.messages...)
}

func (s *requestTestSender) contextErrors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.contexts...)
}

type failFirstRequestSender struct {
	mu        sync.Mutex
	failures  int
	attempted int
}

func (s *failFirstRequestSender) Send(context.Context, RouterRef, i2np.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempted++
	if s.attempted <= s.failures {
		return errors.New("transport unavailable")
	}
	return nil
}

func (s *failFirstRequestSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempted
}

type interleavingRequestTestSender struct {
	requestTestSender
	blockPeer ivnp.Hash
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (s *interleavingRequestTestSender) Send(ctx context.Context, peer RouterRef, message i2np.Message) error {
	err := s.requestTestSender.Send(ctx, peer, message)
	if peer.Hash == s.blockPeer {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return err
}

type cancelingRequestTestSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *cancelingRequestTestSender) Send(ctx context.Context, _ RouterRef, _ i2np.Message) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func requestTestHash(value byte) ivnp.Hash {
	var hash ivnp.Hash
	hash[0] = value
	return hash
}

func addRequestTestFloodfill(database *Database, hash ivnp.Hash) {
	table := database.Routers()
	table.mu.Lock()
	table.routers[hash] = routerEntry{floodfill: true}
	table.mu.Unlock()
}

func TestBuildDatabaseLookupPayloads(t *testing.T) {
	key := requestTestHash(1)
	gateway := requestTestHash(2)
	exclusion := requestTestHash(3)

	routerPayload, err := BuildDatabaseLookup(key, RouterInfoLookup, requestTestRoute{gateway: gateway}, []ivnp.Hash{exclusion})
	if err != nil {
		t.Fatal(err)
	}
	routerLookup, err := i2np.ParseDatabaseLookup(routerPayload)
	if err != nil {
		t.Fatal(err)
	}
	if routerLookup.Key != key || routerLookup.From != gateway || routerLookup.Flags != 8 || routerLookup.ExcludedCount() != 1 {
		t.Fatalf("router lookup = %#v", routerLookup)
	}

	leasePayload, err := BuildDatabaseLookup(key, LeaseSetLookup, requestTestRoute{gateway: gateway, tunnel: 7, viaTunnel: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaseLookup, err := i2np.ParseDatabaseLookup(leasePayload)
	if err != nil {
		t.Fatal(err)
	}
	if leaseLookup.Flags != 5 || leaseLookup.LookupType() != uint8(LeaseSetLookup) || leaseLookup.ReplyTunnelID != 7 || leaseLookup.ExcludedCount() != 0 {
		t.Fatalf("lease lookup = %#v", leaseLookup)
	}
}

func TestRequestManagerCoalescesFollowsSearchReplyAndCompletesStore(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	first, second, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	addRequestTestFloodfill(database, second)
	sender := &requestTestSender{}
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8), tunnel: 4, viaTunnel: true}, RequestManagerConfig{
		Capacity: 2, MaxCandidates: 4, TimeoutMillis: 100, Now: func() uint64 { return now }, Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstWaiter, err := manager.LookupRouterInfo(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	secondWaiter, err := manager.LookupRouterInfo(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	messages := sender.snapshot()
	if len(messages) != 1 || messages[0].Header.ID != 1 || messages[0].Header.Expiration != 100+databaseLookupEnvelopeLifetime {
		t.Fatalf("initial sends = %#v", messages)
	}
	initial, err := i2np.ParseDatabaseLookup(messages[0].Payload)
	if err != nil || initial.ExcludedCount() != 1 || initial.ReplyTunnelID != 4 {
		t.Fatalf("initial lookup = %#v, %v", initial, err)
	}

	peers := make([]byte, ivnp.HashLength)
	copy(peers, second[:])
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: first, Peers: peers})
	messages = sender.snapshot()
	if len(messages) != 2 || messages[1].Header.ID != 2 {
		t.Fatalf("follow-up sends = %#v", messages)
	}
	followUp, err := i2np.ParseDatabaseLookup(messages[1].Payload)
	if err != nil || followUp.ExcludedCount() != 2 {
		t.Fatalf("follow-up lookup = %#v, %v", followUp, err)
	}

	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: key, Type: i2np.StoreRouterInfo})
	for _, waiter := range []<-chan LookupResult{firstWaiter, secondWaiter} {
		result, ok := <-waiter
		if !ok || result.Err != nil || result.Key != key || result.Type != RouterInfoLookup {
			t.Fatalf("completion = %#v, open=%v", result, ok)
		}
	}
	if manager.Pending() != 0 {
		t.Fatalf("pending = %d", manager.Pending())
	}
}

func TestRequestManagerRejectsUnsolicitedSearchReplyAndExpires(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	peer, key := requestTestHash(1), requestTestHash(9)
	addRequestTestFloodfill(database, peer)
	sender := &requestTestSender{}
	now := uint64(10)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, TimeoutMillis: 10, Now: func() uint64 { return now }, Rand: &fixedReader{bytes: []byte{0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := manager.LookupLeaseSet(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: requestTestHash(7)})
	if len(sender.snapshot()) != 1 {
		t.Fatal("unsolicited search reply triggered a send")
	}
	if removed := manager.Expire(20); removed != 1 {
		t.Fatalf("expired %d requests", removed)
	}
	result := <-waiter
	if !errors.Is(result.Err, ErrRequestExpired) {
		t.Fatalf("expiry result = %v", result.Err)
	}
}

func TestRequestManagerRetriesAllInitialCandidatesAfterTransportFailures(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for value := byte(1); value <= 4; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	sender := &failFirstRequestSender{failures: 3}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 4, TimeoutMillis: 50_000, Now: func() uint64 { return 100 },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.LookupLeaseSet(context.Background(), requestTestHash(9)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != 4 {
		t.Fatalf("send attempts = %d, want all 4 candidates", got)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRequestManagerReservesCandidateCapacityForSearchReplyReferrals(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for value := byte(1); value <= 8; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	manager, err := NewRequestManager(database, new(requestTestSender), requestTestRoute{gateway: requestTestHash(20)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 8, TimeoutMillis: 50_000, Now: func() uint64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	key := requestTestHash(21)
	if _, err = manager.LookupLeaseSet(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	req := manager.pending[requestKey{key: key}]
	if len(req.candidates) != javaIterativeSearchInitialPeers || len(req.fallbacks) != 3 {
		t.Fatalf("initial candidates = %d, fallbacks = %d", len(req.candidates), len(req.fallbacks))
	}
	var responder ivnp.Hash
	for peer := range req.sent {
		responder = peer
	}
	manager.mu.Unlock()

	peers := make([]byte, 3*ivnp.HashLength)
	for index, value := range []byte{9, 10, 11} {
		peer := requestTestHash(value)
		addRequestTestFloodfill(database, peer)
		copy(peers[index*ivnp.HashLength:], peer[:])
	}
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: responder, Peers: peers})
	manager.mu.Lock()
	req = manager.pending[requestKey{key: key}]
	candidates := len(req.candidates)
	manager.mu.Unlock()
	if candidates != 8 {
		t.Fatalf("candidates after referrals = %d, want 8", candidates)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestManagerPrefersProvenResponder(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for value := byte(1); value <= 4; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	preferred := requestTestHash(4)
	responders := NewResponderProfiles(4)
	responders.Record(preferred)
	manager, err := NewRequestManager(database, new(requestTestSender), requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 4, TimeoutMillis: 50_000, Now: func() uint64 { return 100 }, Responders: responders,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := requestTestHash(9)
	if _, err = manager.LookupLeaseSet(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	req := manager.pending[requestKey{key: key}]
	_, selected := req.sent[preferred]
	manager.mu.Unlock()
	if !selected {
		t.Fatal("proven responder was not selected before unproven candidates")
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResponderProfilesEvictsOldestPeer(t *testing.T) {
	profiles := NewResponderProfiles(2)
	first, second, third := requestTestHash(1), requestTestHash(2), requestTestHash(3)
	profiles.Record(first)
	profiles.Record(second)
	profiles.Record(first)
	profiles.Record(third)
	if !profiles.Responsive(first) || profiles.Responsive(second) || !profiles.Responsive(third) {
		t.Fatal("responder profile recency eviction is incorrect")
	}
}

func TestRequestManagerTransportFailuresDoNotConsumeJavaQueryBudget(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for value := byte(1); value <= 8; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	sender := &failFirstRequestSender{failures: 6}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(9)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 8, TimeoutMillis: 50_000, Now: func() uint64 { return 100 },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.LookupLeaseSet(context.Background(), requestTestHash(10))
	if err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != 7 {
		t.Fatalf("send attempts = %d, want six local failures followed by one query", got)
	}
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: requestTestHash(10), Type: i2np.StoreLeaseSet2})
	if outcome := <-result; outcome.Err != nil {
		t.Fatalf("lookup result = %#v", outcome)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestManagerUsesJavaFiveQueryBudget(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for value := byte(1); value <= 8; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	sender := new(requestTestSender)
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(9)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 8, TimeoutMillis: 50_000, Now: func() uint64 { return now },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.LookupLeaseSet(context.Background(), requestTestHash(10))
	if err != nil {
		t.Fatal(err)
	}
	for range javaIterativeSearchLimit {
		now += databaseLookupAttemptTimeout
		manager.Expire(now)
	}
	if outcome := <-result; !errors.Is(outcome.Err, ErrRequestExpired) {
		t.Fatalf("lookup result = %#v, want Java query limit expiry", outcome)
	}
	if got := len(sender.snapshot()); got != javaIterativeSearchLimit {
		t.Fatalf("queries = %d, want %d", got, javaIterativeSearchLimit)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestManagerRetriesSilentFloodfill(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	first, second, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	addRequestTestFloodfill(database, second)
	sender := new(requestTestSender)
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 2, TimeoutMillis: 50_000, Now: func() uint64 { return now },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := manager.LookupLeaseSet(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if removed := manager.Expire(now + databaseLookupAttemptTimeout - 1); removed != 0 || len(sender.snapshot()) != 1 {
		t.Fatalf("premature retry removed=%d sends=%d", removed, len(sender.snapshot()))
	}
	now += databaseLookupAttemptTimeout
	if removed := manager.Expire(now); removed != 0 {
		t.Fatalf("retry removed %d requests", removed)
	}
	messages := sender.snapshot()
	if len(messages) != 2 {
		t.Fatalf("silent floodfill sends = %d, want 2", len(messages))
	}
	retry, err := i2np.ParseDatabaseLookup(messages[1].Payload)
	if err != nil || retry.ExcludedCount() != 2 {
		t.Fatalf("retry lookup = %#v, %v", retry, err)
	}
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: key, Type: i2np.StoreLeaseSet2})
	if result := <-waiter; result.Err != nil {
		t.Fatalf("retry completion = %v", result.Err)
	}
}

func TestRequestManagerRetryOutlivesCanceledFirstWaiter(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	first, second, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	addRequestTestFloodfill(database, second)
	sender := new(requestTestSender)
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 2, TimeoutMillis: 50_000, Now: func() uint64 { return now },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	if _, err = manager.LookupLeaseSet(firstCtx, key); err != nil {
		t.Fatal(err)
	}
	liveWaiter, err := manager.LookupLeaseSet(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	cancelFirst()
	now += databaseLookupAttemptTimeout
	if removed := manager.Expire(now); removed != 0 {
		t.Fatalf("retry removed %d requests", removed)
	}
	contextErrors := sender.contextErrors()
	if len(contextErrors) != 2 || contextErrors[1] != nil {
		t.Fatalf("retry contexts = %#v", contextErrors)
	}
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: key, Type: i2np.StoreLeaseSet2})
	if result := <-liveWaiter; result.Err != nil {
		t.Fatalf("live waiter completion = %v", result.Err)
	}
}

func TestRequestManagerCompletesLeaseSetStore(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	peer, key := requestTestHash(1), requestTestHash(9)
	addRequestTestFloodfill(database, peer)
	manager, err := NewRequestManager(database, &requestTestSender{}, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, TimeoutMillis: 10, Now: func() uint64 { return 1 }, Rand: &fixedReader{bytes: []byte{0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := manager.LookupLeaseSet(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: key, Type: i2np.StoreLeaseSet2})
	result := <-waiter
	if result.Err != nil || result.Type != LeaseSetLookup {
		t.Fatalf("lease completion = %#v", result)
	}
}

func TestRequestManagerBoundsDistinctRequests(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	addRequestTestFloodfill(database, requestTestHash(1))
	manager, err := NewRequestManager(database, &requestTestSender{}, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, TimeoutMillis: 10, Now: func() uint64 { return 1 }, Rand: &fixedReader{bytes: []byte{0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LookupRouterInfo(context.Background(), requestTestHash(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LookupRouterInfo(context.Background(), requestTestHash(3)); !errors.Is(err, ErrRequestManagerFull) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestRequestManagerFetchesUnknownCandidatesAndWakesDuringSend(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	source, firstDiscovered, secondDiscovered, next, key := requestTestHash(1), requestTestHash(2), requestTestHash(3), requestTestHash(4), requestTestHash(9)
	addRequestTestFloodfill(database, source)
	sender := &interleavingRequestTestSender{
		blockPeer: next,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 3, MaxCandidates: 4, TimeoutMillis: 1_000, Now: func() uint64 { return now },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LookupRouterInfo(context.Background(), key); err != nil {
		t.Fatal(err)
	}

	discoveredPeers := make([]byte, 2*ivnp.HashLength)
	copy(discoveredPeers, firstDiscovered[:])
	copy(discoveredPeers[ivnp.HashLength:], secondDiscovered[:])
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: source, Peers: discoveredPeers})
	messages := sender.snapshot()
	if len(messages) != 3 {
		t.Fatalf("sends after unknown candidates = %#v", messages)
	}
	for index, expected := range []ivnp.Hash{firstDiscovered, secondDiscovered} {
		lookup, err := i2np.ParseDatabaseLookup(messages[index+1].Payload)
		if err != nil || lookup.Key != expected {
			t.Fatalf("RouterInfo fetch %d = %#v, %v", index, lookup, err)
		}
	}

	addRequestTestFloodfill(database, next)
	nextPeers := make([]byte, ivnp.HashLength)
	copy(nextPeers, next[:])
	replyDone := make(chan struct{})
	go func() {
		manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: source, Peers: nextPeers})
		close(replyDone)
	}()
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("candidate lookup did not enter Send")
	}

	addRequestTestFloodfill(database, firstDiscovered)
	addRequestTestFloodfill(database, secondDiscovered)
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: firstDiscovered, Type: i2np.StoreRouterInfo})
	manager.HandleDatabaseStore(i2np.DatabaseStoreMessage{Key: secondDiscovered, Type: i2np.StoreRouterInfo})
	close(sender.release)
	select {
	case <-replyDone:
	case <-time.After(time.Second):
		t.Fatal("candidate wakeups did not dispatch after Send returned")
	}

	messages = sender.snapshot()
	if len(messages) != 6 {
		t.Fatalf("sends after candidate admission = %#v", messages)
	}
	for index, expected := range []ivnp.Hash{key, firstDiscovered, secondDiscovered, key, key, key} {
		lookup, err := i2np.ParseDatabaseLookup(messages[index].Payload)
		if err != nil || lookup.Key != expected {
			t.Fatalf("send %d lookup = %#v, %v", index, lookup, err)
		}
	}
	final, err := i2np.ParseDatabaseLookup(messages[5].Payload)
	if err != nil || final.ExcludedCount() != 4 {
		t.Fatalf("woken candidate lookup = %#v, %v", final, err)
	}
}

func TestRequestManagerBoundsWireExpirationSeparately(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	first, second, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	sender := &requestTestSender{}
	now := uint64(100)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 2, TimeoutMillis: databaseLookupEnvelopeLifetime * 10,
		Now: func() uint64 { return now }, Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LookupRouterInfo(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	messages := sender.snapshot()
	if len(messages) != 1 || messages[0].Header.Expiration != 100+databaseLookupEnvelopeLifetime {
		t.Fatalf("first wire expiration = %#v", messages)
	}

	now = 500
	addRequestTestFloodfill(database, second)
	peers := make([]byte, ivnp.HashLength)
	copy(peers, second[:])
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: first, Peers: peers})
	messages = sender.snapshot()
	if len(messages) != 2 || messages[1].Header.Expiration != 500+databaseLookupEnvelopeLifetime {
		t.Fatalf("follow-up wire expiration = %#v", messages)
	}
}

func TestRequestManagerCloseCancelsSendCompletesWaiterAndRejectsWork(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	peer, key := requestTestHash(1), requestTestHash(9)
	addRequestTestFloodfill(database, peer)
	sender := &cancelingRequestTestSender{entered: make(chan struct{})}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, TimeoutMillis: 60_000, Now: func() uint64 { return 1 },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	type lookupReturn struct {
		waiter <-chan LookupResult
		err    error
	}
	returned := make(chan lookupReturn, 1)
	go func() {
		waiter, lookupErr := manager.LookupRouterInfo(context.Background(), key)
		returned <- lookupReturn{waiter: waiter, err: lookupErr}
	}()
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("lookup sender did not enter")
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	lookup := <-returned
	if lookup.err != nil {
		t.Fatal(lookup.err)
	}
	result, ok := <-lookup.waiter
	if !ok || !errors.Is(result.Err, ErrRequestManagerClosed) {
		t.Fatalf("close result = %#v, open=%v", result, ok)
	}
	if manager.Pending() != 0 {
		t.Fatalf("pending after close = %d", manager.Pending())
	}
	if _, err = manager.LookupRouterInfo(context.Background(), requestTestHash(7)); !errors.Is(err, ErrRequestManagerClosed) {
		t.Fatalf("lookup after close = %v", err)
	}
}

type fixedReader struct {
	bytes []byte
	off   int
}

func (r *fixedReader) Read(dst []byte) (int, error) {
	if len(r.bytes)-r.off < len(dst) {
		return 0, errors.New("fixed reader exhausted")
	}
	copy(dst, r.bytes[r.off:r.off+len(dst)])
	r.off += len(dst)
	return len(dst), nil
}

func TestExplorationCompletesAfterClosestFloodfillConverges(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	peer, key := requestTestHash(1), requestTestHash(9)
	addRequestTestFloodfill(database, peer)
	sender := new(requestTestSender)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 4, TimeoutMillis: 60_000, Now: func() uint64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Explore(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	manager.HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage{Key: key, From: peer})
	if outcome := <-result; outcome.Err != nil || outcome.Type != ExplorationLookup {
		t.Fatalf("exploration outcome = %#v", outcome)
	}
}
