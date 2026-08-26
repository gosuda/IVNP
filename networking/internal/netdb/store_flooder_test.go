package netdb

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

type storeFloodCapture struct {
	mu      sync.Mutex
	targets []foundation.Hash
	stores  []i2np.DatabaseStoreMessage
}

func (s *storeFloodCapture) Send(_ context.Context, target RouterRef, message i2np.Message) error {
	store, err := i2np.ParseDatabaseStore(message.Payload)
	if err != nil {
		return err
	}
	store.Data = append([]byte(nil), store.Data...)
	s.mu.Lock()
	s.targets = append(s.targets, target.Hash)
	s.stores = append(s.stores, store)
	s.mu.Unlock()
	return nil
}

func (s *storeFloodCapture) snapshot() ([]foundation.Hash, []i2np.DatabaseStoreMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]foundation.Hash(nil), s.targets...), append([]i2np.DatabaseStoreMessage(nil), s.stores...)
}

func TestStoreFlooderPropagatesNewReplyRequestOnce(t *testing.T) {
	local, source, key := requestTestHash(1), requestTestHash(2), requestTestHash(99)
	database := NewDatabase(local, DefaultBucketCapacity)
	for value := byte(2); value <= 8; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	now := uint64(1_000)
	capture := new(storeFloodCapture)
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: capture, Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	job := storeFloodJob{source: source, store: i2np.DatabaseStoreMessage{
		Key: key, Type: i2np.StoreLeaseSet2, Data: []byte{1, 2, 3},
		ReplyToken: 9, ReplyGateway: requestTestHash(10), ReplyTunnelID: 11,
	}}
	flooder.flood(context.Background(), &job)
	targets, stores := capture.snapshot()
	if len(targets) != storeFlooderTargets || len(stores) != storeFlooderTargets {
		t.Fatalf("flooded targets/stores = %d/%d, want %d", len(targets), len(stores), storeFlooderTargets)
	}
	seen := make(map[foundation.Hash]struct{}, len(targets))
	for index, target := range targets {
		if target == local || target == source {
			t.Fatalf("store flooded to excluded peer %x", target)
		}
		if _, duplicate := seen[target]; duplicate {
			t.Fatalf("duplicate flood target %x", target)
		}
		seen[target] = struct{}{}
		store := stores[index]
		storeMismatch := store.Key != key || store.Type != i2np.StoreLeaseSet2 || string(store.Data) != string(job.store.Data)
		replyRouteRetained := store.ReplyToken != 0 || store.ReplyTunnelID != 0 || store.ReplyGateway != (foundation.Hash{})
		if storeMismatch || replyRouteRetained {
			t.Fatalf("flooded store = %#v", store)
		}
	}
	flooder.flood(context.Background(), &job)
	if targets, _ = capture.snapshot(); len(targets) != storeFlooderTargets {
		t.Fatalf("duplicate store flooded %d messages", len(targets))
	}
	job.store.Data = []byte{1, 2, 4}
	flooder.flood(context.Background(), &job)
	if targets, _ = capture.snapshot(); len(targets) != 2*storeFlooderTargets {
		t.Fatalf("new store generation total messages = %d", len(targets))
	}
	job.store.Data = []byte{1, 2, 5}
	flooder.flood(context.Background(), &job)
	if targets, _ = capture.snapshot(); len(targets) != 3*storeFlooderTargets {
		t.Fatalf("third store generation total messages = %d", len(targets))
	}
	job.store.Data = []byte{1, 2, 6}
	flooder.flood(context.Background(), &job)
	if targets, _ = capture.snapshot(); len(targets) != 3*storeFlooderTargets {
		t.Fatalf("fourth store generation bypassed Java flood throttle: %d messages", len(targets))
	}
	now += storeFlooderThrottleWindow
	job.store.Data = []byte{1, 2, 7}
	flooder.flood(context.Background(), &job)
	if targets, _ = capture.snapshot(); len(targets) != 4*storeFlooderTargets {
		t.Fatalf("post-window store generation total messages = %d", len(targets))
	}
}

func TestStoreFlooderNextRoutingKeyWindowMatchesJava(t *testing.T) {
	now := uint64(time.Date(2030, time.January, 2, 23, 55, 0, 0, time.UTC).UnixMilli())
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]Lease{{Gateway: requestTestHash(1), TunnelID: 2, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, MaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	store := i2np.DatabaseStoreMessage{Key: destination.Hash(), Type: i2np.StoreLeaseSet2, Data: wire[:n]}
	if !storeNeedsNextRoutingKey(store, now) {
		t.Fatal("LeaseSet spanning UTC midnight omitted next-day routing key")
	}
	noon := uint64(time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC).UnixMilli())
	if storeNeedsNextRoutingKey(store, noon) {
		t.Fatal("midday LeaseSet requested next-day routing key")
	}
	if !storeNeedsNextRoutingKey(i2np.DatabaseStoreMessage{Type: i2np.StoreRouterInfo}, now-20*60_000) {
		t.Fatal("RouterInfo inside Java 45-minute window omitted next-day routing key")
	}
}

func TestStoreFlooderEnqueueSkipsPropagationTrafficAndOwnsPayload(t *testing.T) {
	now := uint64(1_700_000_000_000)
	local := requestTestHash(1)
	database := NewDatabase(local, DefaultBucketCapacity)
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	localLeaseSet, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = localLeaseSet.ReplaceInboundLeases([]Lease{{Gateway: requestTestHash(4), TunnelID: 5, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, MaxLeaseSetBytes)
	n, err := localLeaseSet.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	current := i2np.DatabaseStoreMessage{Key: destination.Hash(), Type: i2np.StoreLeaseSet2, Data: wire[:n]}
	if err = database.HandleDatabaseStore(current, false, now); err != nil {
		t.Fatal(err)
	}
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: new(storeFloodCapture), Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = flooder.Enqueue(requestTestHash(2), current); err != nil || len(flooder.jobs) != 0 {
		t.Fatalf("propagation store enqueue = %v, queue=%d", err, len(flooder.jobs))
	}
	payload := append([]byte(nil), current.Data...)
	store := current
	store.Data, store.ReplyToken = payload, 1
	if err = flooder.Enqueue(requestTestHash(2), store); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	job := <-flooder.jobs
	if !bytes.Equal(job.store.Data, current.Data) || job.store.ReplyToken != 0 {
		t.Fatalf("owned queued store = %#v", job.store)
	}
	clear(job.store.Data)
	stale := store
	stale.Data = append([]byte(nil), current.Data...)
	stale.Data[len(stale.Data)-1] ^= 1
	if err = flooder.Enqueue(requestTestHash(2), stale); err != nil || len(flooder.jobs) != 0 {
		t.Fatalf("stale store enqueue = %v, queue=%d", err, len(flooder.jobs))
	}
	if err = flooder.Close(); err != nil {
		t.Fatal(err)
	}
	store.Data = current.Data
	if err = flooder.Enqueue(requestTestHash(2), store); !errors.Is(err, ErrStoreFlooderClosed) {
		t.Fatalf("closed enqueue error = %v", err)
	}
}
