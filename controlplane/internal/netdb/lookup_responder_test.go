package netdb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type lookupReplyCapture struct {
	mu       sync.Mutex
	messages []foundation.I2NPMessage
	ready    chan struct{}
}

func (s *lookupReplyCapture) SendNetDBReply(_ context.Context, _ foundation.Hash, _ uint32, message foundation.I2NPMessage) error {
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
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, foundation.I2NPDatabaseLookupMessage{Key: key, From: from, Flags: uint8(RouterInfoLookup << 2)}); err != nil {
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
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != foundation.I2NPDatabaseSearchReply {
		t.Fatalf("reply = %#v", capture.messages)
	}
	reply, err := foundation.I2NPParseDatabaseSearchReply(capture.messages[0].Payload)
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
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, foundation.I2NPDatabaseLookupMessage{Key: key, From: from, Flags: uint8(ExplorationLookup << 2)}); err != nil {
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
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != foundation.I2NPDatabaseSearchReply {
		t.Fatalf("reply = %#v", capture.messages)
	}
	reply, err := foundation.I2NPParseDatabaseSearchReply(capture.messages[0].Payload)
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
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, foundation.I2NPDatabaseLookupMessage{Key: key, From: from, Flags: uint8(ExplorationLookup << 2), Excluded: excluded}); err != nil {
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
	reply, err := foundation.I2NPParseDatabaseSearchReply(capture.messages[0].Payload)
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
	if err = local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{9}, TunnelID: 10, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	key := destination.Hash()
	store := foundation.I2NPDatabaseStoreMessage{Key: key, Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n]}
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
	lookup := foundation.I2NPDatabaseLookupMessage{Key: key, From: foundation.Hash{2}, Flags: uint8(LeaseSetLookup << 2)}
	if err = responder.respond(context.Background(), lookup); err != nil {
		t.Fatal(err)
	}
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != foundation.I2NPDatabaseSearchReply {
		t.Fatalf("lookup-derived LeaseSet reply = %#v", capture.messages)
	}
	if err = database.HandleDatabaseStoreAsPublished(store, false, now, true); err != nil {
		t.Fatal(err)
	}
	if err = responder.respond(context.Background(), lookup); err != nil {
		t.Fatal(err)
	}
	if len(capture.messages) != 2 || capture.messages[1].Header.Type != foundation.I2NPDatabaseStore {
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
			if got := routerInfoCurrentForLookup(foundation.NetworkDatabaseRouterInfo{Published: test.published}, now); got != test.current {
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
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: from, Flags: uint8(RouterInfoLookup<<2) | 1<<1}); !errors.Is(err, ErrLookupReplyEncryptionUnsupported) {
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
	lookup := foundation.I2NPDatabaseLookupMessage{
		Key: key, From: from, Flags: uint8(RouterInfoLookup<<2) | 1<<1 | 1<<4, ReplyPublicKey: make([]byte, 32),
	}
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, lookup); err != nil {
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
	if len(capture.messages) != 1 || capture.messages[0].Header.Type != foundation.I2NPDatabaseSearchReply {
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
	if err = responder.Enqueue(dataplane.RouterI2NPSource{}, foundation.I2NPDatabaseLookupMessage{From: foundation.Hash{2}}); err != nil {
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

func newBudgetedLookupResponder(t *testing.T) *LookupResponder {
	t.Helper()
	local := foundation.Hash{1}
	responder, err := NewLookupResponder(LookupResponderConfig{
		Database: NewDatabase(local, DefaultBucketCapacity),
		Sender: &lookupReplyCapture{ready: make(chan struct{}, 1)},
		Local: local,
		Now: func() uint64 { return 100 },
		Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := responder.Close(); err != nil {
			t.Error(err)
		}
	})
	return responder
}

func TestLookupResponderSourceBudgetIncludesInFlightAndFairDispatch(t *testing.T) {
	responder := newBudgetedLookupResponder(t)
	firstSource := dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true}
	secondSource := dataplane.RouterI2NPSource{Peer: foundation.Hash{3}, Direct: true}
	for i := range lookupResponderPerSource {
		lookup := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{byte(i + 10)}, From: firstSource.Peer}
		if err := responder.Enqueue(firstSource, lookup); err != nil {
			t.Fatal(err)
		}
	}
	extra := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{99}, From: firstSource.Peer}
	if err := responder.Enqueue(firstSource, extra); !errors.Is(err, ErrLookupResponderFull) {
		t.Fatalf("source quota at limit = %v, want ErrLookupResponderFull", err)
	}
	if err := responder.Enqueue(secondSource, foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{98}, From: secondSource.Peer}); err != nil {
		t.Fatalf("other peer was starved: %v", err)
	}
	first, ok := responder.take(context.Background())
	if !ok || first.source != firstSource.Peer {
		t.Fatalf("first source = %x, ready = %t", first.source, ok)
	}
	second, ok := responder.take(context.Background())
	if !ok || second.source != secondSource.Peer {
		t.Fatalf("second source = %x, ready = %t; slow peer monopolized workers", second.source, ok)
	}
	if err := responder.Enqueue(firstSource, extra); !errors.Is(err, ErrLookupResponderFull) {
		t.Fatalf("in-flight quota = %v, want ErrLookupResponderFull", err)
	}
	responder.finish(&first, nil)
	if err := responder.Enqueue(firstSource, extra); err != nil {
		t.Fatalf("completed reply did not release quota: %v", err)
	}
	responder.finish(&second, nil)
}

func TestLookupResponderGlobalBudgetIncludesAllSources(t *testing.T) {
	responder := newBudgetedLookupResponder(t)
	for i := range lookupResponderQueue {
		source := dataplane.RouterI2NPSource{Peer: foundation.Hash{byte(i + 1)}, Direct: true}
		lookup := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{byte(i + 101)}, From: source.Peer}
		if err := responder.Enqueue(source, lookup); err != nil {
			t.Fatalf("admission %d of %d = %v", i+1, lookupResponderQueue, err)
		}
	}
	source := dataplane.RouterI2NPSource{Peer: foundation.Hash{99}, Direct: true}
	if err := responder.Enqueue(source, foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{200}, From: source.Peer}); !errors.Is(err, ErrLookupResponderFull) {
		t.Fatalf("global quota above limit = %v, want ErrLookupResponderFull", err)
	}
}

func TestLookupResponderAnonymousSourcesShareBudget(t *testing.T) {
	responder := newBudgetedLookupResponder(t)
	for i := range lookupResponderPerSource {
		source := dataplane.RouterI2NPSource{Peer: foundation.Hash{byte(i + 1)}}
		lookup := foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{byte(i + 10)}, From: foundation.Hash{99}}
		if err := responder.Enqueue(source, lookup); err != nil {
			t.Fatal(err)
		}
	}
	source := dataplane.RouterI2NPSource{Peer: foundation.Hash{77}}
	if err := responder.Enqueue(source, foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{90}, From: foundation.Hash{99}}); !errors.Is(err, ErrLookupResponderFull) {
		t.Fatalf("anonymous quota bypass = %v, want ErrLookupResponderFull", err)
	}
}

func TestLookupResponderValidatesDirectReturnIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  dataplane.RouterI2NPSource
		lookup  foundation.I2NPDatabaseLookupMessage
		wantErr bool
	}{
		{name: "matched direct reply", source: dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{2}}},
		{name: "spoofed direct reply", source: dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{9}}, wantErr: true},
		{name: "missing return identity", source: dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}}, wantErr: true},
		{name: "invalid direct source", source: dataplane.RouterI2NPSource{Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{9}}, wantErr: true},
		{name: "missing return tunnel", source: dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{9}, Flags: 1}, wantErr: true},
		{name: "forwarded tunnel gateway", source: dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{9}, Flags: 1, ReplyTunnelID: 7}},
		{name: "anonymous direct reply", source: dataplane.RouterI2NPSource{},
			lookup: foundation.I2NPDatabaseLookupMessage{Key: foundation.Hash{3}, From: foundation.Hash{9}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			responder := newBudgetedLookupResponder(t)
			err := responder.Enqueue(test.source, test.lookup)
			if test.wantErr && !errors.Is(err, ErrLookupReplyRoute) {
				t.Fatalf("Enqueue = %v, want ErrLookupReplyRoute", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("valid reply route rejected: %v", err)
			}
		})
	}
}
