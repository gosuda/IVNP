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
	if err = responder.Enqueue(i2np.DatabaseLookupMessage{From: from, Flags: uint8(RouterInfoLookup<<2) | 1<<1}); !errors.Is(err, ErrLookupReplyEncryptionUnsupported) {
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
