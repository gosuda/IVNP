package router

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestServiceValidatesExpiryAndReplay(t *testing.T) {
	service := NewService(Sinks{TunnelData: func(foundation.I2NPMessage) error { return nil }})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 7, Expiration: 100}, Payload: testTunnelDataPayload()}
	if err := service.HandleI2NP(message, 99, false); err != nil {
		t.Fatal(err)
	}
	if err := service.HandleI2NP(message, 99, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	message.Header.ID++
	if err := service.HandleI2NP(message, 100+i2npMessageClockSkewMillis+1, false); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry = %v", err)
	}
}

func TestServiceAcceptsI2NPExpirationSkewBoundaries(t *testing.T) {
	service := NewService(Sinks{TunnelData: func(foundation.I2NPMessage) error { return nil }})
	now := uint64(1_000_000)

	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 1, Expiration: now - i2npMessageClockSkewMillis},
		Payload: testTunnelDataPayload(),
	}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatalf("expiration at past skew boundary = %v", err)
	}

	message.Header.ID++
	message.Header.Expiration = now - i2npMessageClockSkewMillis - 1
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiration beyond past skew = %v, want ErrExpired", err)
	}

	message.Header.ID++
	message.Header.Expiration = now + i2npMessageMaxFutureMillis
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatalf("expiration at future boundary = %v", err)
	}

	message.Header.ID++
	message.Header.Expiration = now + i2npMessageMaxFutureMillis + 1
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, ErrFutureExpiration) {
		t.Fatalf("expiration beyond future boundary = %v, want ErrFutureExpiration", err)
	}

	message.Header.ID++
	message.Header.Expiration = ^uint64(0)
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, ErrFutureExpiration) {
		t.Fatalf("maximum expiration = %v, want ErrFutureExpiration", err)
	}

	message.Header.ID++
	message.Header.Expiration = ^uint64(0)
	nearMaximumNow := message.Header.Expiration - i2npMessageMaxFutureMillis
	if err := service.HandleI2NP(message, nearMaximumNow, false); err != nil {
		t.Fatalf("future boundary near uint64 maximum = %v", err)
	}
}

func TestServiceReplayFilterSurvivesIdentifierChurn(t *testing.T) {
	service := NewService(Sinks{TunnelData: func(foundation.I2NPMessage) error { return nil }})
	now := uint64(1_000_000)
	first := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 1, Expiration: now + i2npMessageMaxFutureMillis},
		Payload: testTunnelDataPayload(),
	}
	if err := service.HandleI2NP(first, now, false); err != nil {
		t.Fatalf("initial message = %v", err)
	}
	for id := uint32(2); id <= 4097; id++ {
		message := first
		message.Header.ID = id
		if err := service.HandleI2NP(message, now, false); err != nil {
			t.Fatalf("churn message %d = %v", id, err)
		}
	}
	if err := service.HandleI2NP(first, now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed message after churn = %v, want ErrDuplicate", err)
	}
}

func TestServiceReplayIdentityIncludesExpiration(t *testing.T) {
	service := NewService(Sinks{TunnelData: func(foundation.I2NPMessage) error { return nil }})
	now := uint64(1_000_000)
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 7, Expiration: now},
		Payload: testTunnelDataPayload(),
	}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatalf("first expiration = %v", err)
	}
	message.Header.Expiration++
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatalf("same ID with new expiration = %v", err)
	}
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same ID and expiration = %v, want ErrDuplicate", err)
	}
}

func TestServiceRejectsUnhandledI2NP(t *testing.T) {
	service := NewService(Sinks{})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 7, Expiration: 100}, Payload: testTunnelDataPayload()}
	if err := service.HandleI2NP(message, 99, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("unhandled message = %v, want ErrUnhandledI2NP", err)
	}
}

func TestServiceDoesNotReplayRejectPayloadOrRouteFailures(t *testing.T) {
	calls := 0
	service := NewService(Sinks{TunnelData: func(foundation.I2NPMessage) error {
		calls++
		return nil
	}})
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPTunnelData, ID: 1, Expiration: 100},
		Payload: make([]byte, foundation.I2NPTunnelDataMessageLen-1),
	}
	if err := service.HandleI2NP(message, 1, false); !errors.Is(err, foundation.I2NPErrMalformed) {
		t.Fatalf("invalid payload = %v, want malformed payload", err)
	}
	message.Payload = testTunnelDataPayload()
	if err := service.HandleI2NP(message, 1, false); err != nil {
		t.Fatalf("valid message after invalid payload = %v", err)
	}
	if calls != 1 {
		t.Fatalf("tunnel data calls = %d, want 1", calls)
	}

	unrouted := NewService(Sinks{})
	if err := unrouted.HandleI2NP(message, 1, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("unrouted message = %v, want ErrUnhandledI2NP", err)
	}
	if err := unrouted.HandleI2NP(message, 1, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("repeated unrouted message = %v, want ErrUnhandledI2NP", err)
	}
}

func testTunnelDataPayload() []byte {
	payload := make([]byte, foundation.I2NPTunnelDataMessageLen)
	payload[3] = 1
	return payload
}
