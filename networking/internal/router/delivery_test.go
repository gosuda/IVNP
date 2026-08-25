package router

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestCloveDeliveryModesRouteToExplicitSinks(t *testing.T) {
	var routerCalls, destinationCalls, tunnelCalls int
	service := NewWithSinks(nil, Sinks{
		Router:      func(foundation.Hash, i2np.Message) error { routerCalls++; return nil },
		Destination: func(foundation.Hash, foundation.Hash, i2np.Message) error { destinationCalls++; return nil },
		Tunnel:      func(foundation.Hash, uint32, i2np.Message) error { tunnelCalls++; return nil },
	})
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: 100}, Payload: make([]byte, 12)}
	var target foundation.Hash
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryRouter, To: target}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryDestination, To: target}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	message.Header.ID++
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryTunnel, To: target, TunnelID: 7}, message, 1, false); err != nil {
		t.Fatal(err)
	}
	if routerCalls != 1 || destinationCalls != 1 || tunnelCalls != 1 {
		t.Fatalf("calls = router %d destination %d tunnel %d", routerCalls, destinationCalls, tunnelCalls)
	}
}

func TestCloveDeliveryWithoutSinkIsRejected(t *testing.T) {
	service := NewService(nil)
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: 100}, Payload: make([]byte, 12)}
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryRouter}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("router delivery error = %v, want ErrUnhandledI2NP", err)
	}
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryDestination}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("destination delivery error = %v, want ErrUnhandledI2NP", err)
	}
	if err := service.dispatchClove(foundation.Hash{}, garlic.Delivery{Type: garlic.DeliveryTunnel}, message, 1, false); err != ErrUnhandledI2NP {
		t.Fatalf("tunnel delivery error = %v, want ErrUnhandledI2NP", err)
	}
}

func TestServiceRoutesTunnelDataToConfiguredRuntime(t *testing.T) {
	calls := 0
	service := NewWithSinks(nil, Sinks{TunnelData: func(message i2np.Message) error {
		calls++
		if message.Header.Type != i2np.TunnelData {
			t.Fatalf("type = %v", message.Header.Type)
		}
		return nil
	}})
	payload := make([]byte, i2np.TunnelDataMessageLen)
	payload[3] = 1
	message := i2np.Message{Header: i2np.Header{Type: i2np.TunnelData, ID: 1, Expiration: 100}, Payload: payload}
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
	service := NewWithSinks(nil, Sinks{
		DeliveryStatus: func(i2np.DeliveryStatusMessage) error { localCalls++; return nil },
		Router:         func(foundation.Hash, i2np.Message) error { routerCalls++; return nil },
		Destination:    func(foundation.Hash, foundation.Hash, i2np.Message) error { destinationCalls++; return nil },
		Tunnel:         func(foundation.Hash, uint32, i2np.Message) error { tunnelCalls++; return nil },
	})
	cloves := []garlic.Clove{
		testClove(garlic.Delivery{Type: garlic.DeliveryLocal}, 10, 20, now),
		testClove(garlic.Delivery{Type: garlic.DeliveryRouter}, 11, 21, now),
		testClove(garlic.Delivery{Type: garlic.DeliveryDestination}, 12, 22, now),
		testClove(garlic.Delivery{Type: garlic.DeliveryTunnel, TunnelID: 1}, 13, 23, now),
	}
	set := testCloveSet(t, cloves, 1, now)
	if err := service.HandleGarlicCloveSet(set, now, false); err != nil {
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
	service := NewWithSinks(nil, Sinks{
		DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil },
		Router:         func(foundation.Hash, i2np.Message) error { t.Fatal("invalid clove was routed"); return nil },
		Destination:    func(foundation.Hash, foundation.Hash, i2np.Message) error { destinationCalls++; return nil },
	})
	invalid := testClove(garlic.Delivery{Type: garlic.DeliveryRouter}, 10, 20, now)
	invalid.Message.Payload = make([]byte, 11)
	set := testCloveSet(t, []garlic.Clove{
		invalid,
		testClove(garlic.Delivery{Type: garlic.DeliveryDestination}, 11, 21, now),
	}, 1, now)
	err := service.HandleGarlicCloveSet(set, now, false)
	if !errors.Is(err, i2np.ErrMalformed) {
		t.Fatalf("clove set error = %v, want malformed payload", err)
	}
	if destinationCalls != 1 {
		t.Fatalf("destination calls = %d, want 1", destinationCalls)
	}
}

func TestGarlicCloveReplaySeparatesSetCloveAndI2NPIdentities(t *testing.T) {
	const now = uint64(1_000)
	routerCalls := 0
	service := NewWithSinks(nil, Sinks{
		DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil },
		Router:         func(foundation.Hash, i2np.Message) error { routerCalls++; return nil },
	})
	first := testClove(garlic.Delivery{Type: garlic.DeliveryRouter}, 10, 20, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []garlic.Clove{first}, 1, now), now, false); err != nil {
		t.Fatal(err)
	}
	duplicateClove := testClove(garlic.Delivery{Type: garlic.DeliveryRouter}, 11, 20, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []garlic.Clove{duplicateClove}, 2, now), now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed clove = %v, want ErrDuplicate", err)
	}
	duplicateMessage := testClove(garlic.Delivery{Type: garlic.DeliveryRouter}, 10, 21, now)
	if err := service.HandleGarlicCloveSet(testCloveSet(t, []garlic.Clove{duplicateMessage}, 3, now), now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed embedded I2NP message = %v, want ErrDuplicate", err)
	}
	if routerCalls != 1 {
		t.Fatalf("router calls = %d, want 1", routerCalls)
	}
}

func testClove(delivery garlic.Delivery, messageID, cloveID uint32, expiration uint64) garlic.Clove {
	return garlic.Clove{
		Delivery: delivery,
		Message: i2np.Message{
			Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: messageID, Expiration: expiration},
			Payload: make([]byte, 12),
		},
		ID:         cloveID,
		Expiration: expiration,
	}
}

func testCloveSet(t *testing.T, cloves []garlic.Clove, messageID uint32, expiration uint64) garlic.CloveSet {
	t.Helper()
	length, err := garlic.CloveSetEncodedLen(cloves)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, length)
	if _, err = garlic.MarshalCloveSetTo(payload, cloves, messageID, expiration); err != nil {
		t.Fatal(err)
	}
	set, err := garlic.ParseCloveSet(payload)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
