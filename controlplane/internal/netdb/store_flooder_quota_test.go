package netdb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

type storeFloodBlockingSender struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (s *storeFloodBlockingSender) Send(ctx context.Context, _ RouterRef, _ foundation.I2NPMessage) error {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func storeFloodAdmissionFixture(t *testing.T, sender StoreFloodSender) (*StoreFlooder, foundation.I2NPDatabaseStoreMessage) {
	t.Helper()
	const now = uint64(1_700_000_000_000)
	local := requestTestHash(1)
	database := NewDatabase(local, DefaultBucketCapacity)
	for value := byte(2); value <= 8; value++ {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.ReleaseSensitive)
	leaseSet, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err = leaseSet.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{
		Gateway: requestTestHash(4), TunnelID: 5, EndDate: now + 10*60_000,
	}}); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := leaseSet.MarshalTo(wire, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	store := foundation.I2NPDatabaseStoreMessage{
		Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n],
	}
	if err = database.HandleDatabaseStore(store, false, now); err != nil {
		t.Fatal(err)
	}
	flooder, err := NewStoreFlooder(StoreFlooderConfig{
		Database: database, Sender: sender, Local: local,
		Now: func() uint64 { return now }, Random: func() uint32 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := flooder.Close(); err != nil {
			t.Error(err)
		}
	})
	store.ReplyToken = 9
	return flooder, store
}

func TestStoreFlooderSourceQuotaAndGlobalCapacity(t *testing.T) {
	flooder, store := storeFloodAdmissionFixture(t, new(storeFloodCapture))
	source := requestTestHash(9)
	for range storeFlooderSourceJobs {
		if err := flooder.Enqueue(source, store); err != nil {
			t.Fatal(err)
		}
	}
	if err := flooder.Enqueue(source, store); !errors.Is(err, ErrStoreFlooderSourceFull) {
		t.Fatalf("source over quota = %v, want ErrStoreFlooderSourceFull", err)
	}
	for index := range storeFlooderQueue - storeFlooderSourceJobs {
		if err := flooder.Enqueue(requestTestHash(byte(index+10)), store); err != nil {
			t.Fatalf("other source %d: %v", index, err)
		}
	}
	overflow := requestTestHash(200)
	if err := flooder.Enqueue(overflow, store); !errors.Is(err, ErrStoreFlooderFull) {
		t.Fatalf("global queue overflow = %v, want ErrStoreFlooderFull", err)
	}
	flooder.mu.Lock()
	queued, rejected := len(flooder.jobs), flooder.sourceJobs[overflow]
	flooder.mu.Unlock()
	if queued != storeFlooderQueue || rejected != 0 {
		t.Fatalf("queued = %d, rejected-source reservations = %d", queued, rejected)
	}
	if err := flooder.Close(); err != nil {
		t.Fatal(err)
	}
	flooder.mu.Lock()
	pending, queued := len(flooder.sourceJobs), len(flooder.jobs)
	flooder.mu.Unlock()
	if pending != 0 || queued != 0 {
		t.Fatalf("closed before start: pending = %d, queued = %d", pending, queued)
	}
	if err := flooder.Enqueue(source, store); !errors.Is(err, ErrStoreFlooderClosed) {
		t.Fatalf("enqueue after close = %v, want ErrStoreFlooderClosed", err)
	}
}

func TestStoreFlooderSourceQuotaIncludesActiveSends(t *testing.T) {
	sender := &storeFloodBlockingSender{started: make(chan struct{}), release: make(chan struct{})}
	flooder, store := storeFloodAdmissionFixture(t, sender)
	if err := flooder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	source, other := requestTestHash(9), requestTestHash(10)
	if err := flooder.Enqueue(source, store); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.started:
	case <-time.After(5 * time.Second):
		t.Fatal("flood send did not start")
	}
	for range storeFlooderSourceJobs - 1 {
		if err := flooder.Enqueue(source, store); err != nil {
			t.Fatal(err)
		}
	}
	if err := flooder.Enqueue(source, store); !errors.Is(err, ErrStoreFlooderSourceFull) {
		t.Fatalf("source over quota while active = %v", err)
	}
	if err := flooder.Enqueue(other, store); err != nil {
		t.Fatalf("different source denied while first source at quota: %v", err)
	}
	flooder.mu.Lock()
	activeAndQueued := flooder.sourceJobs[source]
	otherPending := flooder.sourceJobs[other]
	queued := len(flooder.jobs)
	flooder.mu.Unlock()
	if activeAndQueued != storeFlooderSourceJobs || otherPending != 1 || queued != storeFlooderSourceJobs {
		t.Fatalf("reservations = %d/%d, queued = %d", activeAndQueued, otherPending, queued)
	}
	close(sender.release)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		flooder.mu.Lock()
		pending := len(flooder.sourceJobs)
		flooder.mu.Unlock()
		if pending == 0 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("source reservations not released after send completion")
		}
	}
	if err := flooder.Enqueue(source, store); err != nil {
		t.Fatalf("source still blocked after completed sends: %v", err)
	}
}

func TestStoreFlooderSourceQuotaReleasedOnParentCancellation(t *testing.T) {
	sender := &storeFloodBlockingSender{started: make(chan struct{}), release: make(chan struct{})}
	flooder, store := storeFloodAdmissionFixture(t, sender)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := flooder.Start(ctx); err != nil {
		t.Fatal(err)
	}
	source := requestTestHash(9)
	if err := flooder.Enqueue(source, store); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.started:
	case <-time.After(5 * time.Second):
		t.Fatal("flood send did not start")
	}
	for range storeFlooderSourceJobs - 1 {
		if err := flooder.Enqueue(source, store); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case <-flooder.done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not exit after parent cancellation")
	}
	flooder.mu.Lock()
	pending, queued, closed := len(flooder.sourceJobs), len(flooder.jobs), flooder.closed
	flooder.mu.Unlock()
	if pending != 0 || queued != 0 || !closed {
		t.Fatalf("cancelled: pending = %d, queued = %d, closed = %t", pending, queued, closed)
	}
	if err := flooder.Enqueue(source, store); !errors.Is(err, ErrStoreFlooderClosed) {
		t.Fatalf("enqueue after cancellation = %v, want ErrStoreFlooderClosed", err)
	}
}
