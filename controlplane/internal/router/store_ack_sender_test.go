package router

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestDatabaseStoreSlowAckDoesNotBlockControlIngress(t *testing.T) {
	const now = uint64(1_000)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	payload, _ := testEncryptedDatabaseStore(t, 77, 9)
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	processed := make(chan struct{})
	service, control := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreReply: func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		DeliveryStatus: func(foundation.I2NPDeliveryStatusMessage) error {
			close(processed)
			return nil
		},
	})
	store := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 1, Expiration: now + 60_000}, Payload: payload}
	if err := service.HandleI2NP(store, now, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("acknowledgement sender was not started")
	}
	following := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 2, Expiration: now + 60_000}, Payload: make([]byte, 12)}
	if err := service.HandleI2NP(following, now, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := control.Barrier(ctx); err != nil {
		t.Fatalf("slow acknowledgement blocked control ingress: %v", err)
	}
	select {
	case <-processed:
	default:
		t.Fatal("subsequent control message was not processed")
	}
}

func TestStoreAckSenderBoundsSourcesAndGlobalCapacity(t *testing.T) {
	sender := newStoreAckSender(func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err := sender.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	status := foundation.I2NPDeliveryStatusMessage{MessageID: 1}
	enqueue := func(source dataplane.RouterI2NPSource) error {
		return sender.Enqueue(source, foundation.Hash{9}, 0, status)
	}
	peer := dataplane.RouterI2NPSource{Peer: foundation.Hash{1}, Direct: true}
	for range storeAckPerSource {
		if err := enqueue(peer); err != nil {
			t.Fatal(err)
		}
	}
	if err := enqueue(peer); !errors.Is(err, errStoreAckOverloaded) {
		t.Fatalf("same-source limit = %v, want overload", err)
	}
	other := dataplane.RouterI2NPSource{Peer: foundation.Hash{2}, Direct: true}
	if err := enqueue(other); err != nil {
		t.Fatalf("another authenticated source was denied: %v", err)
	}
	for i := range storeAckPerSource {
		anonymous := dataplane.RouterI2NPSource{Peer: foundation.Hash{byte(i + 20)}}
		if err := enqueue(anonymous); err != nil {
			t.Fatal(err)
		}
	}
	if err := enqueue(dataplane.RouterI2NPSource{Peer: foundation.Hash{99}}); !errors.Is(err, errStoreAckOverloaded) {
		t.Fatalf("spoofed anonymous source = %v, want overload", err)
	}
	for i := 3; i < storeAckCapacity-2; i++ {
		if err := enqueue(dataplane.RouterI2NPSource{Peer: foundation.Hash{byte(i)}, Direct: true}); err != nil {
			t.Fatalf("global admission %d = %v", i, err)
		}
	}
	if err := enqueue(dataplane.RouterI2NPSource{Peer: foundation.Hash{98}, Direct: true}); !errors.Is(err, errStoreAckOverloaded) {
		t.Fatalf("global limit = %v, want overload", err)
	}
}

func TestStoreAckSenderTimeoutAndShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender := newStoreAckSender(func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
			<-ctx.Done()
			return ctx.Err()
		})
		if err := sender.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer sender.Close()
		if err := sender.Enqueue(dataplane.RouterI2NPSource{Peer: foundation.Hash{1}, Direct: true}, foundation.Hash{9}, 0, foundation.I2NPDeliveryStatusMessage{}); err != nil {
			t.Fatal(err)
		}
		if err := sender.WaitIdle(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unresponsive acknowledgement = %v, want deadline exceeded", err)
		}
	})
}

func TestStoreAckSenderCloseDrainsPending(t *testing.T) {
	started := make(chan struct{}, storeAckPerSource)
	sender := newStoreAckSender(func(ctx context.Context, _ foundation.Hash, _ uint32, _ foundation.I2NPDeliveryStatusMessage) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	if err := sender.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range storeAckPerSource {
		if err := sender.Enqueue(dataplane.RouterI2NPSource{Peer: foundation.Hash{1}, Direct: true}, foundation.Hash{9}, 0, foundation.I2NPDeliveryStatusMessage{}); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	sender.Close()
	if err := sender.WaitIdle(t.Context()); err != nil {
		t.Fatalf("shutdown left pending acknowledgements: %v", err)
	}
	if err := sender.Enqueue(dataplane.RouterI2NPSource{Direct: true}, foundation.Hash{9}, 0, foundation.I2NPDeliveryStatusMessage{}); !errors.Is(err, dataplane.RouterErrControlStopped) {
		t.Fatalf("post-shutdown admission = %v, want stopped", err)
	}
}
