package netdb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

type lookupReplyCapture struct {
	mu       sync.Mutex
	messages []i2np.Message
	ready    chan struct{}
}

func (s *lookupReplyCapture) SendNetDBReply(_ context.Context, _ foundation.Hash, _ uint32, message i2np.Message) error {
	s.mu.Lock()
	s.messages = append(s.messages, message)
	s.mu.Unlock()
	select {
	case s.ready <- struct{}{}:
	default:
	}
	return nil
}

func TestLookupResponderMissRepliesWithBoundedSearchReply(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local, from, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	responder, err := NewLookupResponder(LookupResponderConfig{Database: NewDatabase(local, DefaultBucketCapacity), Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{Key: key, From: from, Flags: uint8(RouterInfoLookup << 2)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.ready:
	case <-time.After(time.Second):
		t.Fatal("responder did not send reply")
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != i2np.DatabaseSearchReply {
		t.Fatalf("reply = %#v", capture.messages)
	}
	reply, err := i2np.ParseDatabaseSearchReply(capture.messages[0].Payload)
	if err != nil || reply.Key != key || reply.From != local || reply.PeerCount() != 0 {
		t.Fatalf("search reply = %#v, %v", reply, err)
	}
}

func TestLookupResponderExplorationReturnsOnlyRoutingKBucketNonFloodfills(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local, from, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	database := NewDatabase(local, DefaultBucketCapacity)
	floodfill, ordinary := routerWithSeed(31), routerWithSeed(32)
	database.Routers().StoreVerified(floodfill, true, 1)
	database.Routers().StoreVerified(ordinary, false, 1)
	responder, err := NewLookupResponder(LookupResponderConfig{Database: database, Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{Key: key, From: from, Flags: uint8(ExplorationLookup << 2)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.ready:
	case <-time.After(time.Second):
		t.Fatal("responder did not send exploration reply")
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != i2np.DatabaseSearchReply {
		t.Fatalf("reply = %#v", capture.messages)
	}
	reply, err := i2np.ParseDatabaseSearchReply(capture.messages[0].Payload)
	if err != nil || reply.PeerCount() != 1 {
		t.Fatalf("exploration reply = %#v, %v", reply, err)
	}
	var peer foundation.Hash
	copy(peer[:], reply.Peers)
	if peer != ordinary.Hash() || peer == floodfill.Hash() {
		t.Fatalf("exploration peer = %x, want non-floodfill %x", peer, ordinary.Hash())
	}
}

func TestLookupResponderExplorationAppliesExclusionsBeforeLimit(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local, from, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	database := NewDatabase(local, DefaultBucketCapacity)
	for seed := byte(40); seed < 57; seed++ {
		database.Routers().StoreVerified(routerWithSeed(seed), false, 1)
	}
	ordered := database.Routers().ClosestRoutingNonFloodfillsInto(make([]RouterRef, 0, 17), RoutingKey(key, 100))
	if len(ordered) != 17 {
		t.Fatalf("routing candidates = %d, want 17", len(ordered))
	}
	excluded := make([]byte, 16*foundation.HashLength)
	for index := range 16 {
		copy(excluded[index*foundation.HashLength:], ordered[index].Hash[:])
	}
	responder, err := NewLookupResponder(LookupResponderConfig{Database: database, Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{Key: key, From: from, Flags: uint8(ExplorationLookup << 2), Excluded: excluded}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.ready:
	case <-time.After(time.Second):
		t.Fatal("responder did not send exploration reply")
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	reply, err := i2np.ParseDatabaseSearchReply(capture.messages[0].Payload)
	if err != nil || reply.PeerCount() != 1 {
		t.Fatalf("exploration reply = %#v, %v", reply, err)
	}
	var peer foundation.Hash
	copy(peer[:], reply.Peers)
	if peer != ordered[16].Hash {
		t.Fatalf("exploration peer = %x, want farther eligible %x", peer, ordered[16].Hash)
	}
}

func TestLookupResponderAnswersOnlyPublishedLeaseSet(t *testing.T) {
	now := uint64(1_700_000_000_000)
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: foundation.Hash{9}, TunnelID: 10, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, MaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	key := destination.Hash()
	store := i2np.DatabaseStoreMessage{Key: key, Type: i2np.StoreLeaseSet2, Data: wire[:n]}
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	if err = database.HandleDatabaseStoreAsPublished(store, false, now, false); err != nil {
		t.Fatal(err)
	}
	capture := &lookupReplyCapture{ready: make(chan struct{}, 2)}
	responder, err := NewLookupResponder(LookupResponderConfig{
		Database: database, Sender: capture, Local: foundation.Hash{1},
		Now: func() uint64 { return now }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := i2np.DatabaseLookupMessage{Key: key, From: foundation.Hash{2}, Flags: uint8(LeaseSetLookup << 2)}
	if err = responder.respond(context.Background(), lookup); err != nil {
		t.Fatal(err)
	}
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != i2np.DatabaseSearchReply {
		t.Fatalf("lookup-derived LeaseSet reply = %#v", capture.messages)
	}
	if err = database.HandleDatabaseStoreAsPublished(store, false, now, true); err != nil {
		t.Fatal(err)
	}
	if err = responder.respond(context.Background(), lookup); err != nil {
		t.Fatal(err)
	}
	if len(capture.messages) != 2 || capture.messages[1].Header.Type != i2np.DatabaseStore {
		t.Fatalf("published LeaseSet reply = %#v", capture.messages)
	}
}

func TestLookupResponderRouterInfoFreshnessMatchesJavaHour(t *testing.T) {
	now := uint64(1_700_000_000_000)
	for _, test := range []struct {
		name      string
		published uint64
		current   bool
	}{
		{"current boundary", now - lookupResponderRouterInfoMaxAgeMillis, true},
		{"stale", now - lookupResponderRouterInfoMaxAgeMillis - 1, false},
		{"future", now + 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := routerInfoCurrentForLookup(RouterInfo{Published: test.published}, now); got != test.current {
				t.Fatalf("routerInfoCurrentForLookup() = %t, want %t", got, test.current)
			}
		})
	}
}

func TestLookupResponderRejectsEncryptedReplyWithoutWrapper(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local, from := foundation.Hash{1}, foundation.Hash{2}
	responder, err := NewLookupResponder(LookupResponderConfig{Database: NewDatabase(local, DefaultBucketCapacity), Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{Key: foundation.Hash{3}, From: from, Flags: uint8(RouterInfoLookup<<2) | 1<<1}); !errors.Is(err, ErrLookupReplyEncryptionUnsupported) {
		t.Fatalf("Enqueue() = %v, want ErrLookupReplyEncryptionUnsupported", err)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatalf("Wait() = %v, want nil", err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.messages) != 0 {
		t.Fatalf("plaintext fallback = %#v", capture.messages)
	}
}

func TestLookupResponderLeavesPreliminaryECIESPublicKeyReplyPlaintext(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local, from, key := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	responder, err := NewLookupResponder(LookupResponderConfig{Database: NewDatabase(local, DefaultBucketCapacity), Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	lookup := i2np.DatabaseLookupMessage{
		Key: key, From: from, Flags: uint8(RouterInfoLookup<<2) | 1<<1 | 1<<4, ReplyPublicKey: make([]byte, 32),
	}
	if err = responder.Enqueue(lookup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.ready:
	case <-time.After(time.Second):
		t.Fatal("responder did not send public-key lookup reply")
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != i2np.DatabaseSearchReply {
		t.Fatalf("public-key lookup reply = %#v, want plaintext DatabaseSearchReply", capture.messages)
	}
}

func TestLookupResponderDropsAllZeroSearchKey(t *testing.T) {
	capture := &lookupReplyCapture{ready: make(chan struct{}, 1)}
	local := foundation.Hash{1}
	responder, err := NewLookupResponder(LookupResponderConfig{Database: NewDatabase(local, DefaultBucketCapacity), Sender: capture, Local: local, Now: func() uint64 { return 100 }, Random: func() uint32 { return 7 }})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{From: foundation.Hash{2}}); err != nil {
		t.Fatal(err)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = responder.Wait(); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.messages) != 0 {
		t.Fatalf("all-zero lookup produced replies: %#v", capture.messages)
	}
}
