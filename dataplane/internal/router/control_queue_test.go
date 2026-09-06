package router

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
)

type testControlHandler func(context.Context, ControlMessage) error

func (testControlHandler) Accepts(foundation.I2NPMessage) bool { return true }
func (f testControlHandler) HandleControl(ctx context.Context, message ControlMessage) error {
	return f(ctx, message)
}

func newControlQueueForTest(t *testing.T, handler ControlHandler, limits ControlQueueLimits) *ControlQueue {
	t.Helper()
	queue, err := NewControlQueue(handler, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Error(err)
		}
	})
	return queue
}

func awaitControlEvent[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("control event did not complete")
		var zero T
		return zero
	}
}

func testControlMessage(peer byte) ControlMessage {
	return ControlMessage{
		Source:    I2NPSource{Peer: foundation.Hash{peer}, Direct: true},
		Message:   foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 1, Expiration: 1_000}, Payload: make([]byte, 12)},
		NowMillis: 1_000,
	}
}

func TestControlQueueBoundsIncludeActiveWork(t *testing.T) {
	cases := []struct {
		name       string
		limits     ControlQueueLimits
		secondPeer byte
		fillSecond bool
	}{
		{"global items", ControlQueueLimits{Items: 2, Bytes: 100, SourceItems: 2, SourceBytes: 100}, 2, true},
		{"global bytes", ControlQueueLimits{Items: 4, Bytes: 24, SourceItems: 4, SourceBytes: 24}, 2, true},
		{"source items", ControlQueueLimits{Items: 4, Bytes: 100, SourceItems: 1, SourceBytes: 100}, 1, false},
		{"source bytes", ControlQueueLimits{Items: 4, Bytes: 100, SourceItems: 4, SourceBytes: 12}, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}), tc.limits)
			if err := queue.Enqueue(testControlMessage(1)); err != nil {
				t.Fatal(err)
			}
			awaitControlEvent(t, started)
			if tc.fillSecond {
				if err := queue.Enqueue(testControlMessage(tc.secondPeer)); err != nil {
					t.Fatal(err)
				}
			}
			if err := queue.Enqueue(testControlMessage(tc.secondPeer)); !errors.Is(err, ErrControlOverloaded) {
				t.Fatalf("admission beyond bound = %v", err)
			}
			if !tc.fillSecond {
				if err := queue.Enqueue(testControlMessage(2)); err != nil {
					t.Fatalf("independent peer blocked: %v", err)
				}
			}
		})
	}
}

func TestControlQueueGroupsUnauthenticatedSources(t *testing.T) {
	started := make(chan struct{})
	queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), ControlQueueLimits{Items: 4, Bytes: 100, SourceItems: 1, SourceBytes: 100})
	message := testControlMessage(1)
	message.Source.Direct = false
	if err := queue.Enqueue(message); err != nil {
		t.Fatal(err)
	}
	awaitControlEvent(t, started)
	message.Source.Peer = foundation.Hash{2}
	if err := queue.Enqueue(message); !errors.Is(err, ErrControlOverloaded) {
		t.Fatalf("anonymous peer spoof bypass = %v", err)
	}
}

func TestControlQueueRetainsOwnedPayloadAndAuthenticatedSource(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	received := make(chan ControlMessage, 1)
	queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, message ControlMessage) error {
		if message.Message.Header.ID == 1 {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		received <- message
		return nil
	}), DefaultControlQueueLimits())
	if err := queue.Enqueue(testControlMessage(1)); err != nil {
		t.Fatal(err)
	}
	awaitControlEvent(t, started)
	message := testControlMessage(7)
	message.Message.Header.ID = 2
	message.Message.Payload[0] = 42
	message.FromFloodfill = true
	if err := queue.Enqueue(message); err != nil {
		t.Fatal(err)
	}
	clear(message.Message.Payload)
	close(release)
	got := awaitControlEvent(t, received)
	if got.Source != (I2NPSource{Peer: foundation.Hash{7}, Direct: true}) || !got.FromFloodfill || got.NowMillis != 1_000 {
		t.Fatalf("lost authenticated metadata: %#v", got)
	}
	if !bytes.Equal(got.Message.Payload, append([]byte{42}, make([]byte, 11)...)) {
		t.Fatalf("retained payload = %x", got.Message.Payload)
	}
}

func TestControlQueueCloseCancelsActiveHandlerAndDiscardsPending(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), DefaultControlQueueLimits())
	if err := queue.Enqueue(testControlMessage(1)); err != nil {
		t.Fatal(err)
	}
	awaitControlEvent(t, started)
	if err := queue.Enqueue(testControlMessage(2)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- queue.Close() }()
	if err := awaitControlEvent(t, closed); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("executed pending work during shutdown: %d calls", got)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(testControlMessage(3)); !errors.Is(err, ErrControlStopped) {
		t.Fatalf("post-shutdown admission = %v", err)
	}
}

func TestControlQueueSelfInjectionRejectsWithoutWaiting(t *testing.T) {
	result := make(chan error, 1)
	var queue *ControlQueue
	queue = newControlQueueForTest(t, testControlHandler(func(context.Context, ControlMessage) error {
		result <- queue.Enqueue(testControlMessage(2))
		return nil
	}), ControlQueueLimits{Items: 1, Bytes: 100, SourceItems: 1, SourceBytes: 100})
	if err := queue.Enqueue(testControlMessage(1)); err != nil {
		t.Fatal(err)
	}
	if err := awaitControlEvent(t, result); !errors.Is(err, ErrControlOverloaded) {
		t.Fatalf("nested admission = %v", err)
	}
}

func TestServiceDispatchesDataWhileControlHandlerIsBlocked(t *testing.T) {
	started := make(chan struct{})
	queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), ControlQueueLimits{Items: 1, Bytes: 100, SourceItems: 1, SourceBytes: 100})
	calls := 0
	service := NewService(Sinks{Control: queue, TunnelData: func(foundation.I2NPMessage) error { calls++; return nil }})
	control := testControlMessage(1)
	if err := service.HandleI2NPFrom(control.Source.Peer, control.Message, control.NowMillis, false); err != nil {
		t.Fatal(err)
	}
	awaitControlEvent(t, started)
	control.Message.Header.ID = 3
	if err := service.HandleI2NP(control.Message, 1_000, false); !errors.Is(err, ErrControlOverloaded) {
		t.Fatalf("control overload = %v", err)
	}
	data := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 2, Expiration: 1_000}, Payload: testTunnelDataPayload()}
	if err := service.HandleI2NP(data, 1_000, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("data did not pass blocked control work: %d deliveries", calls)
	}
	if err := service.HandleI2NP(control.Message, 1_000, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("control replay = %v", err)
	}
}

func TestControlQueueCanceledStartCanBeClosed(t *testing.T) {
	queue, err := NewControlQueue(testControlHandler(func(context.Context, ControlMessage) error {
		t.Error("handler ran after canceled startup")
		return nil
	}), DefaultControlQueueLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = queue.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Start = %v", err)
	}
	if err = queue.Close(); err != nil {
		t.Fatal(err)
	}
	if err = queue.Enqueue(testControlMessage(1)); !errors.Is(err, ErrControlStopped) {
		t.Fatalf("closed admission = %v", err)
	}
}

func TestGarlicDestinationDeliveryContinuesAfterControlOverload(t *testing.T) {
	started := make(chan struct{})
	queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}), ControlQueueLimits{Items: 1, Bytes: 100, SourceItems: 1, SourceBytes: 100})
	control := testControlMessage(1)
	if err := queue.Enqueue(control); err != nil {
		t.Fatal(err)
	}
	awaitControlEvent(t, started)
	var delivered uint32
	service := NewService(Sinks{Control: queue, Destination: func(_, _ foundation.Hash, message foundation.I2NPMessage) error {
		delivered = message.Header.ID
		return nil
	}})
	local := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, 2, 12, 1_000)
	destination := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: foundation.Hash{7}}, 3, 13, 1_000)
	destination.Message.Header.Type = foundation.I2NPData
	destination.Message.Payload = make([]byte, 4)
	set := testCloveSet(t, []dataplanegarlic.Clove{local, destination}, 4, 1_000)
	if err := service.HandleGarlicCloveSet(set, 1_000, false); !errors.Is(err, ErrControlOverloaded) {
		t.Fatalf("control admission = %v", err)
	}
	if delivered != 3 {
		t.Fatalf("local destination data waited for control handler: message %d", delivered)
	}
}

func TestControlBarrierDoesNotWaitForLaterAdmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		firstStarted := make(chan struct{})
		releaseFirst := make(chan struct{})
		laterStarted := make(chan struct{})
		queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, message ControlMessage) error {
			if message.Message.Header.ID == 1 {
				close(firstStarted)
				select {
				case <-releaseFirst:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			close(laterStarted)
			<-ctx.Done()
			return ctx.Err()
		}), DefaultControlQueueLimits())
		if err := queue.Enqueue(testControlMessage(1)); err != nil {
			t.Fatal(err)
		}
		<-firstStarted
		barrier := make(chan error, 1)
		go func() { barrier <- queue.Barrier(t.Context()) }()
		synctest.Wait()
		later := testControlMessage(2)
		later.Message.Header.ID = 2
		if err := queue.Enqueue(later); err != nil {
			t.Fatal(err)
		}
		close(releaseFirst)
		<-laterStarted
		synctest.Wait()
		select {
		case err := <-barrier:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("barrier waited beyond its admission watermark")
		}
	})
}

func TestControlBarrierCancellation(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "caller cancellation"
		if shutdown {
			name = "queue shutdown"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				queue := newControlQueueForTest(t, testControlHandler(func(ctx context.Context, _ ControlMessage) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				}), DefaultControlQueueLimits())
				if err := queue.Enqueue(testControlMessage(1)); err != nil {
					t.Fatal(err)
				}
				<-started
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				barrier := make(chan error, 1)
				go func() { barrier <- queue.Barrier(ctx) }()
				synctest.Wait()
				want := error(context.Canceled)
				if shutdown {
					want = ErrControlStopped
					if err := queue.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					cancel()
				}
				if err := <-barrier; !errors.Is(err, want) {
					t.Fatalf("barrier cancellation = %v, want %v", err, want)
				}
			})
		})
	}
}

func TestControlHandlerFailureDoesNotPoisonLaterBarriers(t *testing.T) {
	rejected := errors.New("invalid control signature")
	queue := newControlQueueForTest(t, testControlHandler(func(context.Context, ControlMessage) error { return rejected }), DefaultControlQueueLimits())
	if err := queue.Enqueue(testControlMessage(1)); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); !errors.Is(err, rejected) {
		t.Fatalf("control rejection = %v", err)
	}
	if err := queue.Barrier(t.Context()); err != nil {
		t.Fatalf("historical rejection poisoned barrier: %v", err)
	}
	if err := queue.Enqueue(testControlMessage(2)); err != nil {
		t.Fatal(err)
	}
	if err := queue.Barrier(t.Context()); err != nil {
		t.Fatalf("handler rejection prevented completion: %v", err)
	}
}
