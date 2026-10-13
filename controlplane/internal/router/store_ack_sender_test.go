package router

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestDatabaseStoreAcknowledgementDoesNotBlockControlIngress(t *testing.T) {
	const now = uint64(1_000)
	payload, _ := testEncryptedDatabaseStore(t, 77, 9)
	ackStarted := make(chan struct{})
	statusHandled := make(chan struct{})
	service, control := newControlServiceForTest(t,
		controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity),
		ControlSinks{
			DatabaseStoreReply: func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
				close(ackStarted)
				<-ctx.Done()
				return ctx.Err()
			},
			DeliveryStatus: func(foundation.I2NPDeliveryStatusMessage) error {
				close(statusHandled)
				return nil
			},
		})
	store := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 1, Expiration: now},
		Payload: payload,
	}
	if err := service.HandleI2NP(store, now, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ackStarted:
	case <-time.After(time.Second):
		t.Fatal("acknowledgement send never started")
	}
	status := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 2, Expiration: now},
		Payload: make([]byte, 12),
	}
	if err := service.HandleI2NP(status, now, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := control.Barrier(ctx); err != nil {
		t.Fatalf("control ingress waited for the blocked acknowledgement: %v", err)
	}
	select {
	case <-statusHandled:
	default:
		t.Fatal("following control message was not dispatched")
	}
}

func TestDatabaseStoreAcknowledgementBudgetsIncludeRunningSends(t *testing.T) {
	var active atomic.Int32
	sender := newDatabaseStoreAckSender(func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		return ctx.Err()
	}, time.Minute)
	job := databaseStoreAck{source: dataplane.RouterI2NPSource{Peer: foundation.Hash{1}}}
	if err := sender.Enqueue(job); !errors.Is(err, dataplane.RouterErrControlStopped) {
		t.Fatalf("admission before start = %v", err)
	}
	if err := sender.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)

	for range databaseStoreAckSourceCapacity {
		if err := sender.Enqueue(job); err != nil {
			t.Fatal(err)
		}
	}
	job.source.Peer = foundation.Hash{2}
	if err := sender.Enqueue(job); !errors.Is(err, dataplane.RouterErrControlOverloaded) {
		t.Fatalf("anonymous source impersonation = %v", err)
	}
	for peer := byte(1); peer <= 7; peer++ {
		job.source = dataplane.RouterI2NPSource{Peer: foundation.Hash{peer}, Direct: true}
		for range databaseStoreAckSourceCapacity {
			if err := sender.Enqueue(job); err != nil {
				t.Fatal(err)
			}
		}
		if peer == 1 {
			if err := sender.Enqueue(job); !errors.Is(err, dataplane.RouterErrControlOverloaded) {
				t.Fatalf("authenticated source over capacity = %v", err)
			}
		}
	}
	job.source = dataplane.RouterI2NPSource{Peer: foundation.Hash{8}, Direct: true}
	if err := sender.Enqueue(job); !errors.Is(err, dataplane.RouterErrControlOverloaded) {
		t.Fatalf("global acknowledgement overflow = %v", err)
	}
	if got := active.Load(); got > databaseStoreAckWorkers {
		t.Fatalf("active sends = %d, limit %d", got, databaseStoreAckWorkers)
	}
	sender.Close()
	if err := sender.WaitIdle(t.Context()); err != nil {
		t.Fatalf("shutdown did not drain acknowledgement accounting: %v", err)
	}
	if err := sender.Enqueue(job); !errors.Is(err, dataplane.RouterErrControlStopped) {
		t.Fatalf("admission after close = %v", err)
	}
}

func TestDatabaseStoreAcknowledgementSendErrorReportedAfterDispatch(t *testing.T) {
	const now = uint64(1_000)
	failure := errors.New("reply route unavailable")
	payload, _ := testEncryptedDatabaseStore(t, 99, 7)
	service, control := newControlServiceForTest(t,
		controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity),
		ControlSinks{DatabaseStoreReply: func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error {
			return failure
		}})
	store := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 1, Expiration: now}, Payload: payload}
	if err := service.HandleI2NP(store, now, false); err != nil {
		t.Fatal(err)
	}
	if err := control.Barrier(t.Context()); err != nil {
		t.Fatalf("send failure poisoned control barrier: %v", err)
	}
	if err := control.WaitIdle(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("asynchronous acknowledgement failure = %v, want %v", err, failure)
	}
}
