package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func newStoreAckSenderForTest(
	t *testing.T,
	limits dataplane.RouterControlQueueLimits,
	send func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error,
) *storeAckSender {
	t.Helper()
	sender := newStoreAckSender(send, time.Minute, limits)
	if err := sender.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sender.Close(); err != nil {
			t.Error(err)
		}
	})
	return sender
}

func testStoreAckJob(peer byte, direct bool) storeAckJob {
	return storeAckJob{
		source:  dataplane.RouterI2NPSource{Peer: foundation.Hash{peer}, Direct: direct},
		gateway: foundation.Hash{9},
		status:  foundation.I2NPDeliveryStatusMessage{MessageID: 77, Timestamp: 1_000},
	}
}

func TestStoreAckSenderEnforcesSourceAndGlobalCapacity(t *testing.T) {
	release := make(chan struct{})
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: 5, SourceItems: 2},
		func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	)
	for range 2 {
		if err := sender.Enqueue(testStoreAckJob(1, true)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sender.Enqueue(testStoreAckJob(1, true)); !errors.Is(err, ErrStoreAckOverloaded) {
		t.Fatalf("per-source overflow = %v, want ErrStoreAckOverloaded", err)
	}
	for range 2 {
		if err := sender.Enqueue(testStoreAckJob(2, true)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sender.Enqueue(testStoreAckJob(3, true)); err != nil {
		t.Fatalf("independent source rejected below global limit: %v", err)
	}
	if err := sender.Enqueue(testStoreAckJob(4, true)); !errors.Is(err, ErrStoreAckOverloaded) {
		t.Fatalf("global overflow = %v, want ErrStoreAckOverloaded", err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := sender.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sender.Enqueue(testStoreAckJob(1, true)); err != nil {
		t.Fatalf("source budget was not released: %v", err)
	}
	if err := sender.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAckSenderGroupsUnauthenticatedSources(t *testing.T) {
	release := make(chan struct{})
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: 4, SourceItems: 1},
		func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	)
	if err := sender.Enqueue(testStoreAckJob(1, false)); err != nil {
		t.Fatal(err)
	}
	if err := sender.Enqueue(testStoreAckJob(2, false)); !errors.Is(err, ErrStoreAckOverloaded) {
		t.Fatalf("anonymous source bypass = %v, want ErrStoreAckOverloaded", err)
	}
	if err := sender.Enqueue(testStoreAckJob(3, true)); err != nil {
		t.Fatalf("authenticated source shared anonymous budget: %v", err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := sender.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAckSenderCloseCancelsActiveSend(t *testing.T) {
	entered := make(chan struct{})
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: 1, SourceItems: 1},
		func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		},
	)
	if err := sender.Enqueue(testStoreAckJob(1, true)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("acknowledgement sender did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- sender.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acknowledgement sender failed to cancel on close")
	}
	if err := sender.Enqueue(testStoreAckJob(1, true)); !errors.Is(err, ErrStoreAckStopped) {
		t.Fatalf("post-close admission = %v, want ErrStoreAckStopped", err)
	}
	if err := sender.WaitIdle(t.Context()); err != nil {
		t.Fatalf("cancelled send was recorded as an error: %v", err)
	}
}

func TestStoreAckSenderReportsSendFailure(t *testing.T) {
	want := errors.New("reply send failed")
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: 1, SourceItems: 1},
		func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error {
			return want
		},
	)
	if err := sender.Enqueue(testStoreAckJob(1, true)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := sender.WaitIdle(ctx); !errors.Is(err, want) {
		t.Fatalf("send failure = %v, want %v", err, want)
	}
}


func TestStoreAckSenderHardCaps(t *testing.T) {
	release := make(chan struct{})
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: 256, SourceItems: 32},
		func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	)
	for peer := byte(1); peer <= 8; peer++ {
		for range storeAckSourceCapacity {
			if err := sender.Enqueue(testStoreAckJob(peer, true)); err != nil {
				t.Fatalf("peer %d admission below source cap = %v", peer, err)
			}
		}
	}
	if err := sender.Enqueue(testStoreAckJob(1, true)); !errors.Is(err, ErrStoreAckOverloaded) {
		t.Fatalf("hard source cap bypass = %v", err)
	}
	if err := sender.Enqueue(testStoreAckJob(9, true)); !errors.Is(err, ErrStoreAckOverloaded) {
		t.Fatalf("hard global cap bypass = %v", err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := sender.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAckSenderCloseDropsQueuedReplies(t *testing.T) {
	entered := make(chan struct{}, storeAckWorkers)
	sender := newStoreAckSenderForTest(t,
		dataplane.RouterControlQueueLimits{Items: storeAckWorkers + 1, SourceItems: storeAckWorkers + 1},
		func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			entered <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		},
	)
	for range storeAckWorkers + 1 {
		if err := sender.Enqueue(testStoreAckJob(1, true)); err != nil {
			t.Fatal(err)
		}
	}
	for range storeAckWorkers {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("not all acknowledgement workers started")
		}
	}
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
		t.Fatal("queued reply was sent after shutdown")
	default:
	}
	if err := sender.WaitIdle(t.Context()); err != nil {
		t.Fatalf("queued replies remain after close: %v", err)
	}
}
