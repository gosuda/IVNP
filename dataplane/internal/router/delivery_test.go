package router

import (
	"context"
	"errors"
	"testing"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
)

func TestCloveDeliveryModesRouteToExplicitSinks(t *testing.T) {
	var routerCalls, destinationCalls, tunnelCalls int
	service := NewService(Sinks{
		Router:      func(foundation.Hash, foundation.I2NPMessage) error { routerCalls++; return nil },
		Destination: func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error { destinationCalls++; return nil },
		Tunnel:      func(foundation.Hash, uint32, foundation.I2NPMessage) error { tunnelCalls++; return nil },
	})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 1, Expiration: 100}, Payload: make([]byte, 12)}
	var target foundation.Hash
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter, To: target}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: target}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryTunnel, To: target, TunnelID: 7}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	if routerCalls != 1 || destinationCalls != 1 || tunnelCalls != 1 {
		t.Fatalf("calls = router %d destination %d tunnel %d", routerCalls, destinationCalls, tunnelCalls)
	}
}

func TestCloveDeliveryWithoutSinkIsRejected(t *testing.T) {
	service := NewService(Sinks{})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: 1, Expiration: 100}, Payload: make([]byte, 12)}
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("router delivery error = %v, want ErrUnhandledI2NP", err)
	}
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("destination delivery error = %v, want ErrUnhandledI2NP", err)
	}
	if err := service.dispatchClove(foundation.Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryTunnel}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("tunnel delivery error = %v, want ErrUnhandledI2NP", err)
	}
}

func TestServiceRoutesTunnelDataToConfiguredRuntime(t *testing.T) {
	calls := 0
	service := NewService(Sinks{TunnelData: func(message foundation.I2NPMessage) error {
		calls++
		if message.Header.Type != foundation.I2NPTunnelData {
			t.Fatalf("type = %v", message.Header.Type)
		}
		return nil
	}})
	payload := make([]byte, foundation.I2NPTunnelDataMessageLen)
	payload[3] = 1
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 1, Expiration: 100}, Payload: payload}
	if err := service.HandleI2NP(message, 1, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("tunnel data calls = %d, want 1", calls)
	}
}

func TestGarlicCloveSetAdmitsEveryDeliveryRouteOnce(t *testing.T) {
	const now = uint64(1_000)
	var localCalls, routerCalls, destinationCalls, tunnelCalls int
	queue := newControlQueueForTest(t, testControlHandler(func(context.Context, ControlMessage) error { localCalls++; return nil }), DefaultControlQueueLimits())
	service := NewService(Sinks{
		Control:     queue,
		Router:      func(foundation.Hash, foundation.I2NPMessage) error { routerCalls++; return nil },
		Destination: func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error { destinationCalls++; return nil },
		Tunnel:      func(foundation.Hash, uint32, foundation.I2NPMessage) error { tunnelCalls++; return nil },
	})
	cloves := []dataplanegarlic.Clove{
		testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, 10, 20, now),
		testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, 11, 21, now),
		testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination}, 12, 22, now),
		testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryTunnel, TunnelID: 1}, 13, 23, now),
	}
	set := testCloveSet(t, cloves, 1, now)
	if err := service.HandleGarlicCloveSet(set, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if localCalls != 1 || routerCalls != 1 || destinationCalls != 1 || tunnelCalls != 1 {
		t.Fatalf("calls = local %d router %d destination %d tunnel %d", localCalls, routerCalls, destinationCalls, tunnelCalls)
	}
	if err := service.HandleGarlicCloveSet(set, now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed garlic set = %v, want ErrDuplicate", err)
	}
	if localCalls != 1 || routerCalls != 1 || destinationCalls != 1 || tunnelCalls != 1 {
		t.Fatalf("replayed calls = local %d router %d destination %d tunnel %d", localCalls, routerCalls, destinationCalls, tunnelCalls)
	}
}

func TestGarlicCloveSetContinuesAfterInvalidClove(t *testing.T) {
	const now = uint64(1_000)
	destinationCalls := 0
	service := NewService(Sinks{
		Router:      func(foundation.Hash, foundation.I2NPMessage) error { t.Fatal("invalid clove was routed"); return nil },
		Destination: func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error { destinationCalls++; return nil },
	})
	invalid := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, 10, 20, now)
	invalid.Message.Payload = make([]byte, 11)
	set := testCloveSet(t, []dataplanegarlic.Clove{
		invalid,
		testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination}, 11, 21, now),
	}, 1, now)
	err := service.HandleGarlicCloveSet(set, now, false)
	if !errors.Is(err, foundation.I2NPErrMalformed) {
		t.Fatalf("clove set error = %v, want malformed payload", err)
	}
	if destinationCalls != 1 {
		t.Fatalf("destination calls = %d, want 1", destinationCalls)
	}
}

func TestGarlicCloveReplaySeparatesSetCloveAndI2NPIdentities(t *testing.T) {
	const now = uint64(1_000)
	routerCalls := 0
	service := NewService(Sinks{
		Router: func(foundation.Hash, foundation.I2NPMessage) error { routerCalls++; return nil },
	})
	first := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, 10, 20, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []dataplanegarlic.Clove{first}, 1, now), now, false); err != nil {
		t.Fatal(err)
	}
	duplicateClove := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, 11, 20, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []dataplanegarlic.Clove{duplicateClove}, 2, now), now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed clove = %v, want ErrDuplicate", err)
	}
	duplicateMessage := testClove(dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryRouter}, 10, 21, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []dataplanegarlic.Clove{duplicateMessage}, 3, now), now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed embedded I2NP message = %v, want ErrDuplicate", err)
	}
	if routerCalls != 1 {
		t.Fatalf("router calls = %d, want 1", routerCalls)
	}
}

func testClove(delivery dataplanegarlic.Delivery, messageID, cloveID uint32, expiration uint64) dataplanegarlic.Clove {
	return dataplanegarlic.Clove{
		Delivery: delivery,
		Message: foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: messageID, Expiration: expiration},
			Payload: make([]byte, 12),
		},
		ID:         cloveID,
		Expiration: expiration,
	}
}

func testCloveSet(t *testing.T, cloves []dataplanegarlic.Clove, messageID uint32, expiration uint64) dataplanegarlic.CloveSet {
	t.Helper()
	length, err := dataplanegarlic.CloveSetEncodedLen(cloves)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, length)
	if _, err = dataplanegarlic.MarshalCloveSetTo(payload, cloves, messageID, expiration); err != nil {
		t.Fatal(err)
	}
	set, err := dataplanegarlic.ParseCloveSet(payload)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
