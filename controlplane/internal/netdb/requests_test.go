package netdb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
)

var (
	errRequestTestTransportUnavailable = errors.New("transport unavailable")
	errFixedReaderExhausted            = errors.New("fixed reader exhausted")
)

type requestTestRoute struct {
	gateway   foundation.Hash
	tunnel    uint32
	viaTunnel bool
}

func (r requestTestRoute) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return r.gateway, r.tunnel, r.viaTunnel
}

type requestTestSender struct {
	mu       sync.Mutex
	messages []foundation.I2NPMessage
	peers    []foundation.Hash
	contexts []error
	err      error
}

func (s *requestTestSender) Send(ctx context.Context, peer RouterRef, message foundation.I2NPMessage) error {
	s.mu.Lock()
	message.Payload = append([]byte(nil), message.Payload...)
	s.messages = append(s.messages, message)
	s.peers = append(s.peers, peer.Hash)
	s.contexts = append(s.contexts, ctx.Err())
	s.mu.Unlock()
	return s.err
}

func (s *requestTestSender) snapshot() []foundation.I2NPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]foundation.I2NPMessage(nil), s.messages...)
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

func (s *failFirstRequestSender) Send(context.Context, RouterRef, foundation.I2NPMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempted++
	if s.attempted <= s.failures {
		return errRequestTestTransportUnavailable
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
	blockPeer foundation.Hash
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (s *interleavingRequestTestSender) Send(ctx context.Context, peer RouterRef, message foundation.I2NPMessage) error {
	err := s.requestTestSender.Send(ctx, peer, message)
	if peer.Hash == s.blockPeer {
		s.once.Do(func() {
			close(s.entered)
			<-s.release
		})
	}
	return err
}

type blockingReferralRefreshSender struct {
	requestTestSender
	parentKey      foundation.Hash
	refreshKey     foundation.Hash
	parentSent     chan struct{}
	refreshEntered chan struct{}
	releaseRefresh chan struct{}
	parentCalls    int
	parentOnce     sync.Once
	refreshOnce    sync.Once
}

func (s *blockingReferralRefreshSender) Send(ctx context.Context, peer RouterRef, message foundation.I2NPMessage) error {
	err := s.requestTestSender.Send(ctx, peer, message)
	lookup, parseErr := foundation.I2NPParseDatabaseLookup(message.Payload)
	if parseErr != nil {
		return parseErr
	}
	switch lookup.Key {
	case s.parentKey:
		s.requestTestSender.mu.Lock()
		s.parentCalls++
		parentCalls := s.parentCalls
		s.requestTestSender.mu.Unlock()
		if parentCalls == 2 {
			s.parentOnce.Do(func() { close(s.parentSent) })
		}
	case s.refreshKey:
		s.refreshOnce.Do(func() { close(s.refreshEntered) })
		select {
		case <-s.releaseRefresh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

type cancelingRequestTestSender struct {
	entered chan struct{}
	once    sync.Once
}

func (s *cancelingRequestTestSender) Send(ctx context.Context, _ RouterRef, _ foundation.I2NPMessage) error {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	return ctx.Err()
}

type cancelingRetryRequestTestSender struct {
	requestTestSender
	entered  chan struct{}
	canceled chan struct{}
}

func (s *cancelingRetryRequestTestSender) Send(ctx context.Context, peer RouterRef, message foundation.I2NPMessage) error {
	err := s.requestTestSender.Send(ctx, peer, message)
	if len(s.snapshot()) == 1 {
		return err
	}
	close(s.entered)
	<-ctx.Done()
	close(s.canceled)
	return ctx.Err()
}

func requestTestHash(value byte) foundation.Hash {
	var hash foundation.Hash
	hash[0] = value
	return hash
}

func addRequestTestFloodfill(database *Database, hash foundation.Hash) {
	table := database.Routers()
	table.mu.Lock()
	table.routers[hash] = routerEntry{floodfill: true}
	table.mu.Unlock()
}

func TestBuildDatabaseLookupPayloads(t *testing.T) {
	key := requestTestHash(1)
	gateway := requestTestHash(2)
	exclusion := requestTestHash(3)

	routerPayload, err := BuildDatabaseLookup(key, RouterInfoLookup, requestTestRoute{gateway: gateway}, []foundation.Hash{exclusion})
	if err != nil {
		t.Fatal(err)
	}
	routerLookup, err := foundation.I2NPParseDatabaseLookup(routerPayload)
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
	leaseLookup, err := foundation.I2NPParseDatabaseLookup(leasePayload)
	if err != nil {
		t.Fatal(err)
	}
	if leaseLookup.Flags != 5 || leaseLookup.LookupType() != uint8(LeaseSetLookup) || leaseLookup.ReplyTunnelID != 7 || leaseLookup.ExcludedCount() != 0 {
		t.Fatalf("lease lookup = %#v", leaseLookup)
	}
}

func TestRequestManagerCoalescesFollowsSearchReplyAndCompletesStore(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	defer manager.Close()

	firstWaiter, err := manager.LookupRouterInfo(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	secondWaiter, err := manager.LookupRouterInfo(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 1 || messages[0].Header.ID != 1 || messages[0].Header.Expiration != 100+databaseLookupEnvelopeLifetime {
		t.Fatalf("initial sends = %#v", messages)
	}
	initial, err := foundation.I2NPParseDatabaseLookup(messages[0].Payload)
	if err != nil || initial.ExcludedCount() != 1 || initial.ReplyTunnelID != 4 {
		t.Fatalf("initial lookup = %#v, %v", initial, err)
	}

	peers := make([]byte, foundation.HashLength)
	copy(peers, second[:])
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: first, Peers: peers})
	manager.active.Wait()
	messages = sender.snapshot()
	if len(messages) != 2 || messages[1].Header.ID != 2 {
		t.Fatalf("follow-up sends = %#v", messages)
	}
	followUp, err := foundation.I2NPParseDatabaseLookup(messages[1].Payload)
	if err != nil || followUp.ExcludedCount() != 2 {
		t.Fatalf("follow-up lookup = %#v, %v", followUp, err)
	}

	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreRouterInfo})
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

func TestRequestManagerQueriesKnownLeaseSetReferralWithoutRefresh(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	first, referred, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	addRequestTestFloodfill(database, referred)
	sender := new(requestTestSender)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 2, MaxCandidates: 4, TimeoutMillis: 10_000, Now: func() uint64 { return 100 },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err = manager.LookupLeaseSet(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	peers := make([]byte, foundation.HashLength)
	copy(peers, referred[:])
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: first, Peers: peers})
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 2 {
		t.Fatalf("known LeaseSet referral sends = %d, want 2", len(messages))
	}
	followUp, err := foundation.I2NPParseDatabaseLookup(messages[1].Payload)
	if err != nil || followUp.ExcludedCount() != 2 {
		t.Fatalf("known LeaseSet referral lookup = %#v, %v", followUp, err)
	}
}

func TestRequestManagerDispatchesKnownParentBeforeBlockingUnknownReferralRefresh(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	first, second, unknown, key := requestTestHash(1), requestTestHash(2), requestTestHash(3), requestTestHash(9)
	addRequestTestFloodfill(database, first)
	addRequestTestFloodfill(database, second)
	sender := &blockingReferralRefreshSender{
		parentKey: key, refreshKey: unknown, parentSent: make(chan struct{}),
		refreshEntered: make(chan struct{}), releaseRefresh: make(chan struct{}),
	}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 3, MaxCandidates: 4, TimeoutMillis: 10_000, Now: func() uint64 { return 100 },
		Rand: &fixedReader{bytes: []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	defer close(sender.releaseRefresh)
	if _, err = manager.LookupLeaseSet(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	manager.mu.Lock()
	request := manager.pending[requestKey{key: key}]
	var initial foundation.Hash
	for peer := range request.sent {
		initial = peer
	}
	manager.mu.Unlock()
	if initial == (foundation.Hash{}) {
		t.Fatal("initial LeaseSet lookup did not send")
	}
	peers := make([]byte, foundation.HashLength)
	copy(peers, unknown[:])
	replyDone := make(chan struct{})
	go func() {
		manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: initial, Peers: peers})
		close(replyDone)
	}()
	select {
	case <-sender.parentSent:
	case <-time.After(time.Second):
		t.Fatal("known parent candidate was blocked behind unknown referral refresh")
	}
	select {
	case <-sender.refreshEntered:
	case <-time.After(time.Second):
		t.Fatal("unknown referral refresh was not dispatched")
	}
	select {
	case <-replyDone:
	case <-time.After(time.Second):
		t.Fatal("search-reply handler waited for blocking referral refresh")
	}
}

func TestRequestManagerResponseHandlersDoNotWaitForSend(t *testing.T) {
	for _, response := range []string{"search_reply", "router_info_store"} {
		t.Run(response, func(t *testing.T) {
			database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
			source, referred, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
			addRequestTestFloodfill(database, source)
			sender := &interleavingRequestTestSender{
				blockPeer: referred, entered: make(chan struct{}), release: make(chan struct{}),
			}
			manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
				Capacity: 2, MaxCandidates: 4, TimeoutMillis: 10_000, Now: func() uint64 { return 100 },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			defer close(sender.release)
			if _, err = manager.LookupLeaseSet(t.Context(), key); err != nil {
				t.Fatal(err)
			}
			manager.active.Wait()
			reply := foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: source, Peers: referred[:]}
			if response == "router_info_store" {
				manager.HandleDatabaseSearchReply(context.Background(), reply)
				manager.active.Wait()
			}
			addRequestTestFloodfill(database, referred)
			returned := make(chan struct{})
			go func() {
				if response == "search_reply" {
					manager.HandleDatabaseSearchReply(context.Background(), reply)
				} else {
					manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: referred, Type: foundation.I2NPStoreRouterInfo})
				}
				close(returned)
			}()
			t.Cleanup(func() { <-returned })
			select {
			case <-sender.entered:
			case <-time.After(time.Second):
				t.Fatal("response did not schedule the referred peer lookup")
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("response handler blocked on the referred peer send")
			}
		})
	}
}

func TestRequestManagerRejectsUnsolicitedSearchReplyAndExpires(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: requestTestHash(7)})
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	if got := sender.count(); got != 4 {
		t.Fatalf("send attempts = %d, want all 4 candidates", got)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRequestManagerReservesCandidateCapacityForSearchReplyReferrals(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	var responder foundation.Hash
	for peer := range req.sent {
		responder = peer
	}
	manager.mu.Unlock()

	peers := make([]byte, 3*foundation.HashLength)
	for index, value := range []byte{9, 10, 11} {
		peer := requestTestHash(value)
		addRequestTestFloodfill(database, peer)
		copy(peers[index*foundation.HashLength:], peer[:])
	}
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: responder, Peers: peers})
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
	synctest.Test(t, func(t *testing.T) {
		database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
		for value := byte(1); value <= 4; value++ {
			addRequestTestFloodfill(database, requestTestHash(value))
		}
		preferred := signedResponderRouter(t, 4, 100, true)
		if err := database.AdmitRouterInfo(preferred, false, 100); err != nil {
			t.Fatal(err)
		}
		responders := NewResponderProfiles(ResponderProfilesConfig{MaxPeers: 4, Now: func() uint64 { return 100 }})
		responders.Record(preferred.Hash())
		sender := new(requestTestSender)
		manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
			Capacity: 1, MaxCandidates: 4, TimeoutMillis: 50_000, Now: func() uint64 { return 100 }, Responders: responders,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer manager.Close()
		if _, err = manager.LookupLeaseSet(context.Background(), requestTestHash(9)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		sender.mu.Lock()
		defer sender.mu.Unlock()
		if len(sender.peers) != 1 || sender.peers[0] != preferred.Hash() {
			t.Fatalf("lookup peers = %v, want proven responder first", sender.peers)
		}
	})
}

func TestResponderProfilesEvictsOldestPeer(t *testing.T) {
	profiles := NewResponderProfiles(ResponderProfilesConfig{MaxPeers: 2, Now: func() uint64 { return 100 }})
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	if got := sender.count(); got != 7 {
		t.Fatalf("send attempts = %d, want six local failures followed by one query", got)
	}
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: requestTestHash(10), Type: foundation.I2NPStoreLeaseSet2})
	if outcome := <-result; outcome.Err != nil {
		t.Fatalf("lookup result = %#v", outcome)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestManagerUsesJavaFiveQueryBudget(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	for range javaIterativeSearchLimit {
		now += databaseLookupAttemptTimeout
		manager.Expire(now)
		manager.active.Wait()
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	if removed := manager.Expire(now + databaseLookupAttemptTimeout - 1); removed != 0 || len(sender.snapshot()) != 1 {
		t.Fatalf("premature retry removed=%d sends=%d", removed, len(sender.snapshot()))
	}
	now += databaseLookupAttemptTimeout
	if removed := manager.Expire(now); removed != 0 {
		t.Fatalf("retry removed %d requests", removed)
	}
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 2 {
		t.Fatalf("silent floodfill sends = %d, want 2", len(messages))
	}
	retry, err := foundation.I2NPParseDatabaseLookup(messages[1].Payload)
	if err != nil || retry.ExcludedCount() != 2 {
		t.Fatalf("retry lookup = %#v, %v", retry, err)
	}
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreLeaseSet2})
	if result := <-waiter; result.Err != nil {
		t.Fatalf("retry completion = %v", result.Err)
	}
}

func TestRequestManagerExpireDoesNotWaitAndCancelsExpiredSend(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	addRequestTestFloodfill(database, requestTestHash(1))
	addRequestTestFloodfill(database, requestTestHash(2))
	sender := &cancelingRetryRequestTestSender{entered: make(chan struct{}), canceled: make(chan struct{})}
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, TimeoutMillis: 10_000, Now: func() uint64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	waiter, err := manager.LookupLeaseSet(t.Context(), requestTestHash(9))
	if err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	returned := make(chan struct{})
	go func() {
		manager.Expire(100 + databaseLookupAttemptTimeout)
		close(returned)
	}()
	t.Cleanup(func() { <-returned })
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("expiry did not schedule the retry")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("expiry scheduler blocked on the retry send")
	}
	if removed := manager.Expire(10_100); removed != 1 {
		t.Fatalf("expired requests = %d, want 1", removed)
	}
	select {
	case <-sender.canceled:
	case <-time.After(time.Second):
		t.Fatal("request expiry did not cancel its blocked sender")
	}
	if result := <-waiter; !errors.Is(result.Err, ErrRequestExpired) {
		t.Fatalf("lookup result = %v, want ErrRequestExpired", result.Err)
	}
}

func TestRequestManagerRetryOutlivesCanceledFirstWaiter(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	cancelFirst()
	now += databaseLookupAttemptTimeout
	if removed := manager.Expire(now); removed != 0 {
		t.Fatalf("retry removed %d requests", removed)
	}
	manager.active.Wait()
	contextErrors := sender.contextErrors()
	if len(contextErrors) != 2 || contextErrors[1] != nil {
		t.Fatalf("retry contexts = %#v", contextErrors)
	}
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreLeaseSet2})
	if result := <-liveWaiter; result.Err != nil {
		t.Fatalf("live waiter completion = %v", result.Err)
	}
}

func TestRequestManagerCompletesLeaseSetStore(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreLeaseSet2})
	result := <-waiter
	if result.Err != nil || result.Type != LeaseSetLookup {
		t.Fatalf("lease completion = %#v", result)
	}
}

func TestRequestManagerBoundsDistinctRequests(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
func TestRequestManagerClassifiesExpectedDatabaseStore(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	addRequestTestFloodfill(database, requestTestHash(1))
	manager, err := NewRequestManager(database, new(requestTestSender), requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 4, TimeoutMillis: 10_000, Now: func() uint64 { return 100 },
	})
	if err != nil {
		t.Fatal(err)
	}
	key := requestTestHash(9)
	if _, err = manager.LookupLeaseSet(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreLeaseSet2}
	if !manager.ExpectsDatabaseStore(store) {
		t.Fatal("live LeaseSet lookup did not classify its DatabaseStore reply")
	}
	manager.HandleDatabaseStore(context.Background(), store)
	if manager.ExpectsDatabaseStore(store) {
		t.Fatal("completed lookup continued classifying DatabaseStore replies")
	}
	manager.Close()
}

func TestRequestManagerFetchesUnknownCandidatesAndWakesDuringSend(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()

	discoveredPeers := make([]byte, 2*foundation.HashLength)
	copy(discoveredPeers, firstDiscovered[:])
	copy(discoveredPeers[foundation.HashLength:], secondDiscovered[:])
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: source, Peers: discoveredPeers})
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 3 {
		t.Fatalf("sends after unknown candidates = %#v", messages)
	}
	discovered := make(map[foundation.Hash]bool, 2)
	for _, message := range messages[1:] {
		lookup, err := foundation.I2NPParseDatabaseLookup(message.Payload)
		if err != nil {
			t.Fatal(err)
		}
		discovered[lookup.Key] = true
	}
	for _, expected := range []foundation.Hash{firstDiscovered, secondDiscovered} {
		if !discovered[expected] {
			t.Fatalf("RouterInfo refresh missing for %x", expected)
		}
	}

	addRequestTestFloodfill(database, next)
	nextPeers := make([]byte, foundation.HashLength)
	copy(nextPeers, next[:])
	replyDone := make(chan struct{})
	go func() {
		manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: source, Peers: nextPeers})
		close(replyDone)
	}()
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("candidate lookup did not enter Send")
	}

	addRequestTestFloodfill(database, firstDiscovered)
	addRequestTestFloodfill(database, secondDiscovered)
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: firstDiscovered, Type: foundation.I2NPStoreRouterInfo})
	manager.HandleDatabaseStore(context.Background(), foundation.I2NPDatabaseStoreMessage{Key: secondDiscovered, Type: foundation.I2NPStoreRouterInfo})
	close(sender.release)
	select {
	case <-replyDone:
	case <-time.After(time.Second):
		t.Fatal("candidate wakeups did not dispatch after Send returned")
	}

	manager.active.Wait()
	messages = sender.snapshot()
	if len(messages) != 6 {
		t.Fatalf("sends after candidate admission = %#v", messages)
	}
	if first, err := foundation.I2NPParseDatabaseLookup(messages[0].Payload); err != nil || first.Key != key {
		t.Fatalf("initial lookup = %#v, %v", first, err)
	}
	for index := 3; index < len(messages); index++ {
		lookup, err := foundation.I2NPParseDatabaseLookup(messages[index].Payload)
		if err != nil || lookup.Key != key {
			t.Fatalf("parent send %d lookup = %#v, %v", index, lookup, err)
		}
	}
	final, err := foundation.I2NPParseDatabaseLookup(messages[5].Payload)
	if err != nil || final.ExcludedCount() != 4 {
		t.Fatalf("woken candidate lookup = %#v, %v", final, err)
	}
}

func TestRequestManagerBoundsWireExpirationSeparately(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	defer manager.Close()
	if _, err := manager.LookupRouterInfo(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	messages := sender.snapshot()
	if len(messages) != 1 || messages[0].Header.Expiration != 100+databaseLookupEnvelopeLifetime {
		t.Fatalf("first wire expiration = %#v", messages)
	}

	now = 500
	addRequestTestFloodfill(database, second)
	peers := make([]byte, foundation.HashLength)
	copy(peers, second[:])
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: first, Peers: peers})
	manager.active.Wait()
	messages = sender.snapshot()
	if len(messages) != 2 || messages[1].Header.Expiration != 500+databaseLookupEnvelopeLifetime {
		t.Fatalf("follow-up wire expiration = %#v", messages)
	}
}

func TestRequestManagerLookupReturnsBeforeSendAndCloseCancels(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	defer manager.Close()
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
	var lookup lookupReturn
	select {
	case lookup = <-returned:
	case <-time.After(time.Second):
		t.Fatal("initial lookup blocked on its sender")
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
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
		return 0, errFixedReaderExhausted
	}
	copy(dst, r.bytes[r.off:r.off+len(dst)])
	r.off += len(dst)
	return len(dst), nil
}

func TestExplorationCompletesAfterClosestFloodfillConverges(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	manager.active.Wait()
	manager.HandleDatabaseSearchReply(context.Background(), foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: peer})
	if outcome := <-result; outcome.Err != nil || outcome.Type != ExplorationLookup {
		t.Fatalf("exploration outcome = %#v", outcome)
	}
}

type deadlineRequestSender struct {
	initial        foundation.Hash
	holdInitial    bool
	initialStarted chan struct{}
	releaseInitial chan struct{}
	deadlines      chan time.Time
	stopped        chan error
}

func (s *deadlineRequestSender) Send(ctx context.Context, peer RouterRef, _ foundation.I2NPMessage) error {
	if peer.Hash == s.initial {
		s.initialStarted <- struct{}{}
		if s.holdInitial {
			select {
			case <-s.releaseInitial:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	deadline, _ := ctx.Deadline()
	s.deadlines <- deadline
	<-ctx.Done()
	s.stopped <- ctx.Err()
	return ctx.Err()
}

func TestSearchReplyFollowupOwnsHandlerDeadline(t *testing.T) {
	testRequestFollowupDeadline(t, "search_reply")
}

func TestRouterInfoStoreFollowupOwnsHandlerDeadline(t *testing.T) {
	testRequestFollowupDeadline(t, "router_info_store")
}

func TestInflightWakeupOwnsHandlerDeadline(t *testing.T) {
	testRequestFollowupDeadline(t, "inflight_wakeup")
}

func testRequestFollowupDeadline(t *testing.T, route string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
		initial, referred, key := requestTestHash(1), requestTestHash(2), requestTestHash(9)
		addRequestTestFloodfill(database, initial)
		sender := &deadlineRequestSender{
			initial: initial, holdInitial: route == "inflight_wakeup",
			initialStarted: make(chan struct{}, 4), releaseInitial: make(chan struct{}),
			deadlines: make(chan time.Time, 1), stopped: make(chan error, 1),
		}
		manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
			Capacity: 2, MaxCandidates: 4, TimeoutMillis: 60_000, Now: func() uint64 { return 100 },
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := manager.Close(); err != nil {
				t.Error(err)
			}
		})
		result, err := manager.LookupLeaseSet(t.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		<-sender.initialStarted
		if !sender.holdInitial {
			manager.active.Wait()
		}
		reply := foundation.I2NPDatabaseSearchReplyMessage{Key: key, From: initial, Peers: referred[:]}
		if route == "router_info_store" {
			manager.HandleDatabaseSearchReply(t.Context(), reply)
			manager.active.Wait()
		}
		addRequestTestFloodfill(database, referred)
		handlerCtx, cancel := context.WithTimeout(t.Context(), 17*time.Second)
		defer cancel()
		wantDeadline, _ := handlerCtx.Deadline()
		if route == "router_info_store" {
			manager.HandleDatabaseStore(handlerCtx, foundation.I2NPDatabaseStoreMessage{Key: referred, Type: foundation.I2NPStoreRouterInfo})
		} else {
			manager.HandleDatabaseSearchReply(handlerCtx, reply)
		}
		cancel()
		if sender.holdInitial {
			close(sender.releaseInitial)
		}
		if got := <-sender.deadlines; !got.Equal(wantDeadline) {
			t.Fatalf("follow-up deadline = %v, want %v", got, wantDeadline)
		}
		if err := <-sender.stopped; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("follow-up send canceled as %v", err)
		}
		if outcome := <-result; !errors.Is(outcome.Err, context.DeadlineExceeded) {
			t.Fatalf("lookup deadline result = %v", outcome.Err)
		}
	})
}
