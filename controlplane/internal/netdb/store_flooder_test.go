package netdb

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

type storeFloodCapture struct {
	mu      sync.Mutex
	targets []foundation.Hash
	stores  []foundation.I2NPDatabaseStoreMessage
}

func (s *storeFloodCapture) Send(_ context.Context, target RouterRef, message foundation.I2NPMessage) error {
	store, err := foundation.I2NPParseDatabaseStore(message.Payload)
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

func (s *storeFloodCapture) snapshot() ([]foundation.Hash, []foundation.I2NPDatabaseStoreMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]foundation.Hash(nil), s.targets...), append([]foundation.I2NPDatabaseStoreMessage(nil), s.stores...)
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
	job := storeFloodJob{source: source, store: foundation.I2NPDatabaseStoreMessage{
		Key: key, Type: foundation.I2NPStoreLeaseSet2, Data: []byte{1, 2, 3},
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
		storeMismatch := store.Key != key || store.Type != foundation.I2NPStoreLeaseSet2 || string(store.Data) != string(job.store.Data)
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
	if err = local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: requestTestHash(1), TunnelID: 2, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPDatabaseStoreMessage{Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n]}
	if !storeNeedsNextRoutingKey(store, now) {
		t.Fatal("LeaseSet spanning UTC midnight omitted next-day routing key")
	}
	noon := uint64(time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC).UnixMilli())
	if storeNeedsNextRoutingKey(store, noon) {
		t.Fatal("midday LeaseSet requested next-day routing key")
	}
	if !storeNeedsNextRoutingKey(foundation.I2NPDatabaseStoreMessage{Type: foundation.I2NPStoreRouterInfo}, now-20*60_000) {
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
	if err = localLeaseSet.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: requestTestHash(4), TunnelID: 5, EndDate: now + 10*60_000}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := localLeaseSet.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	current := foundation.I2NPDatabaseStoreMessage{Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n]}
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
	flooder.finish(&job)
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

// storeFloodTestCurrentStore builds a different valid, current LeaseSet2 for
// each call so admission limits cannot depend on duplicate suppression.
func storeFloodTestCurrentStore(t *testing.T, database *Database, now uint64) foundation.I2NPDatabaseStoreMessage {
	t.Helper()
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{
		Gateway: requestTestHash(9), TunnelID: 10, EndDate: now + 10*60_000,
	}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPDatabaseStoreMessage{
		Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n],
	}
	if err = database.HandleDatabaseStore(store, false, now); err != nil {
		t.Fatal(err)
	}
	store.ReplyToken = 7
	return store
}

type storeFloodBlockingSender struct {
	entered chan struct{}
	release chan struct{}
}

func (s *storeFloodBlockingSender) Send(ctx context.Context, _ RouterRef, _ foundation.I2NPMessage) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestStoreFlooderSourceQuotaBoundsQueuedWork(t *testing.T) {
	now := uint64(1_700_000_000_000)
	local, source, other := requestTestHash(1), requestTestHash(2), requestTestHash(3)
	database := NewDatabase(local, DefaultBucketCapacity)
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: new(storeFloodCapture), Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	stores := make([]foundation.I2NPDatabaseStoreMessage, storeFlooderSourceLimit+1)
	for index := range stores {
		stores[index] = storeFloodTestCurrentStore(t, database, now)
	}
	for index := range storeFlooderSourceLimit {
		if err := flooder.Enqueue(source, stores[index]); err != nil {
			t.Fatalf("source job %d rejected below quota: %v", index, err)
		}
	}
	if err := flooder.Enqueue(source, stores[storeFlooderSourceLimit]); !errors.Is(err, ErrStoreFlooderFull) {
		t.Fatalf("source job above quota = %v, want ErrStoreFlooderFull", err)
	}
	if len(flooder.jobs) != storeFlooderSourceLimit {
		t.Fatalf("queue length after rejected source = %d, want %d", len(flooder.jobs), storeFlooderSourceLimit)
	}
	if err := flooder.Enqueue(other, stores[storeFlooderSourceLimit]); err != nil {
		t.Fatalf("independent source rejected: %v", err)
	}
	job := <-flooder.jobs
	flooder.finish(&job)
	if err := flooder.Enqueue(source, stores[storeFlooderSourceLimit]); err != nil {
		t.Fatalf("source still throttled after completing job: %v", err)
	}
	if got := flooder.sourcePending[source]; got != storeFlooderSourceLimit {
		t.Fatalf("source reservations = %d, want %d", got, storeFlooderSourceLimit)
	}
	// Close without Start must wipe and release all outstanding queued work.
	if err := flooder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(flooder.jobs) != 0 || len(flooder.sourcePending) != 0 {
		t.Fatalf("shutdown retained %d jobs and %d source reservations", len(flooder.jobs), len(flooder.sourcePending))
	}
	if err := flooder.Enqueue(source, stores[0]); !errors.Is(err, ErrStoreFlooderClosed) {
		t.Fatalf("post-close enqueue = %v, want ErrStoreFlooderClosed", err)
	}
}

func TestStoreFlooderSourceQuotaCoversActiveSend(t *testing.T) {
	now := uint64(1_700_000_000_000)
	local, source, other := requestTestHash(1), requestTestHash(2), requestTestHash(3)
	database := NewDatabase(local, DefaultBucketCapacity)
	for seed := byte(2); seed <= 8; seed++ {
		addRequestTestFloodfill(database, requestTestHash(seed))
	}
	stores := make([]foundation.I2NPDatabaseStoreMessage, storeFlooderSourceLimit+1)
	for index := range stores {
		stores[index] = storeFloodTestCurrentStore(t, database, now)
	}
	sender := &storeFloodBlockingSender{entered: make(chan struct{}, 3), release: make(chan struct{})}
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: sender, Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := flooder.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := flooder.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := flooder.Enqueue(source, stores[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.entered: // The worker removed the job from the queue but is still sending.
	case <-time.After(5 * time.Second):
		t.Fatal("flood sender was not entered")
	}
	if err := flooder.Enqueue(source, stores[1]); err != nil {
		t.Fatalf("second source job rejected below quota: %v", err)
	}
	if err := flooder.Enqueue(source, stores[2]); !errors.Is(err, ErrStoreFlooderFull) {
		t.Fatalf("source bypassed active reservation: %v", err)
	}
	if err := flooder.Enqueue(other, stores[2]); err != nil {
		t.Fatalf("independent source starved by active job: %v", err)
	}
	close(sender.release)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		flooder.mu.Lock()
		sourcePending := flooder.sourcePending[source]
		otherPending := flooder.sourcePending[other]
		flooder.mu.Unlock()
		if sourcePending == 0 && otherPending == 0 {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("completed sends retained source reservations: %d / %d", sourcePending, otherPending)
		}
	}
	if err := flooder.Enqueue(source, stores[2]); err != nil {
		t.Fatalf("source reservation was not returned after send: %v", err)
	}
}

func TestStoreFlooderCancellationClosesAdmissionAndDrainsReservations(t *testing.T) {
	now := uint64(1_700_000_000_000)
	local, source := requestTestHash(1), requestTestHash(2)
	database := NewDatabase(local, DefaultBucketCapacity)
	for seed := byte(2); seed <= 8; seed++ {
		addRequestTestFloodfill(database, requestTestHash(seed))
	}
	first := storeFloodTestCurrentStore(t, database, now)
	second := storeFloodTestCurrentStore(t, database, now)
	sender := &storeFloodBlockingSender{entered: make(chan struct{}, 3), release: make(chan struct{})}
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: sender, Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	t.Cleanup(func() {
		if err := flooder.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := flooder.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := flooder.Enqueue(source, first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("flood sender was not entered")
	}
	if err := flooder.Enqueue(source, second); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := flooder.Wait(); err != nil {
		t.Fatal(err)
	}
	if len(flooder.jobs) != 0 || len(flooder.sourcePending) != 0 {
		t.Fatalf("cancellation retained %d jobs and %d reservations", len(flooder.jobs), len(flooder.sourcePending))
	}
	if err := flooder.Enqueue(source, first); !errors.Is(err, ErrStoreFlooderClosed) {
		t.Fatalf("canceled flooder accepted new work: %v", err)
	}
}
