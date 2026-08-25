package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/network_database"
	"testing"
)

func TestServiceValidatesExpiryAndReplay(t *testing.T) {
	service := NewWithSinks(nil, Sinks{DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil }})
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 7, Expiration: 100}, Payload: make([]byte, 12)}
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
	service := NewWithSinks(nil, Sinks{DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil }})
	now := uint64(1_000_000)

	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: now - i2npMessageClockSkewMillis},
		Payload: make([]byte, 12),
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
	service := NewWithSinks(nil, Sinks{DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil }})
	now := uint64(1_000_000)
	first := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: now + i2npMessageMaxFutureMillis},
		Payload: make([]byte, 12),
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
	service := NewWithSinks(nil, Sinks{DeliveryStatus: func(i2np.DeliveryStatusMessage) error { return nil }})
	now := uint64(1_000_000)
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 7, Expiration: now},
		Payload: make([]byte, 12),
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
	service := NewService(nil)
	message := i2np.Message{Header: i2np.Header{Type: i2np.DeliveryStatus, ID: 7, Expiration: 100}, Payload: make([]byte, 12)}
	if err := service.HandleI2NP(message, 99, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("unhandled message = %v, want ErrUnhandledI2NP", err)
	}
}

func TestServiceDoesNotReplayRejectPayloadOrRouteFailures(t *testing.T) {
	calls := 0
	service := NewWithSinks(nil, Sinks{DeliveryStatus: func(i2np.DeliveryStatusMessage) error {
		calls++
		return nil
	}})
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DeliveryStatus, ID: 1, Expiration: 100},
		Payload: make([]byte, 11),
	}
	if err := service.HandleI2NP(message, 1, false); !errors.Is(err, i2np.ErrMalformed) {
		t.Fatalf("invalid payload = %v, want malformed payload", err)
	}
	message.Payload = make([]byte, 12)
	if err := service.HandleI2NP(message, 1, false); err != nil {
		t.Fatalf("valid message after invalid payload = %v", err)
	}
	if calls != 1 {
		t.Fatalf("delivery status calls = %d, want 1", calls)
	}

	unrouted := NewService(nil)
	if err := unrouted.HandleI2NP(message, 1, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("unrouted message = %v, want ErrUnhandledI2NP", err)
	}
	if err := unrouted.HandleI2NP(message, 1, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("repeated unrouted message = %v, want ErrUnhandledI2NP", err)
	}
}

func TestServiceAcknowledgesSuccessfulDatabaseStoreOnce(t *testing.T) {
	const now = uint64(1_000)
	database := netdb.NewDatabase(ivnp.Hash{}, netdb.DefaultBucketCapacity)
	payload, key := testEncryptedDatabaseStore(t, 77, 9)
	replies := 0
	service := NewWithSinks(database, Sinks{DatabaseStoreReply: func(gateway ivnp.Hash, tunnelID uint32, status i2np.DeliveryStatusMessage) error {
		replies++
		if gateway[0] != 1 || tunnelID != 9 {
			t.Fatalf("reply route = %x/%d, want gateway 1/tunnel 9", gateway, tunnelID)
		}
		if status.MessageID != 77 || status.Timestamp != now {
			t.Fatalf("reply status = %#v, want token 77 at %d", status, now)
		}
		if _, found := database.EncryptedLeaseSet(key); !found {
			t.Fatal("reply was sent before DatabaseStore admission")
		}
		return nil
	}})
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DatabaseStore, ID: 1, Expiration: now},
		Payload: payload,
	}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed database store = %v, want ErrDuplicate", err)
	}
	if replies != 1 {
		t.Fatalf("database store replies = %d, want 1", replies)
	}
}

func testEncryptedDatabaseStore(t *testing.T, replyToken, replyTunnelID uint32) ([]byte, ivnp.Hash) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := make([]byte, 2+len(public)+4+2+2+2+1)
	binary.BigEndian.PutUint16(unsigned[:2], uint16(ivnp.SigningRedDSASHA512Ed25519))
	copy(unsigned[2:], public)
	offset := 2 + len(public) + 4 + 2 + 2
	binary.BigEndian.PutUint16(unsigned[offset:offset+2], 1)
	unsigned[offset+2] = 7
	signed := append([]byte{byte(i2np.StoreEncryptedLeaseSet)}, unsigned...)
	leaseSet := append(unsigned, ed25519.Sign(private, signed)...)
	parsed, err := netdb.ParseEncryptedLeaseSet(leaseSet)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.Hash()
	payload := make([]byte, 37+36+len(leaseSet))
	copy(payload[:32], key[:])
	payload[32] = byte(i2np.StoreEncryptedLeaseSet)
	binary.BigEndian.PutUint32(payload[33:37], replyToken)
	binary.BigEndian.PutUint32(payload[37:41], replyTunnelID)
	payload[41] = 1
	copy(payload[73:], leaseSet)
	return payload, key
}

func TestServiceRoutesGarlicUnwrappedOutboundBuildReplyOnly(t *testing.T) {
	const now = uint64(1_000_000)
	reply := i2np.Message{
		Header:  i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: 7, Expiration: now + 1},
		Payload: make([]byte, 1+i2np.ShortBuildRecordLen),
	}
	reply.Payload[0] = 1
	calls := 0
	service := NewWithSinks(nil, Sinks{OutboundTunnelBuildReply: func(message i2np.Message) error {
		calls++
		if message.Header.Type != reply.Header.Type || message.Header.ID != reply.Header.ID || len(message.Payload) != len(reply.Payload) {
			t.Fatalf("routed reply = %#v", message)
		}
		return nil
	}})
	if err := service.HandleI2NP(reply, now, false); !errors.Is(err, ErrUnhandledI2NP) {
		t.Fatalf("direct reply error = %v, want ErrUnhandledI2NP", err)
	}
	cloves := []garlic.Clove{{
		Delivery:   garlic.Delivery{Type: garlic.DeliveryLocal},
		Message:    reply,
		ID:         8,
		Expiration: now + 1,
	}}
	size, err := garlic.CloveSetEncodedLen(cloves)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, size)
	if _, err = garlic.MarshalCloveSetTo(encoded, cloves, 9, now+1); err != nil {
		t.Fatal(err)
	}
	set, err := garlic.ParseCloveSet(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.HandleGarlicCloveSet(set, now, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("garlic reply calls = %d, want 1", calls)
	}
}

func TestServiceTunnelBuildSetterRoutesShortBuild(t *testing.T) {
	const now = uint64(1_000_000)
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.ShortTunnelBuild, ID: 9, Expiration: now + 1},
		Payload: append([]byte{1}, make([]byte, i2np.ShortBuildRecordLen)...),
	}
	calls := 0
	peer := ivnp.Hash{7}
	service := NewService(nil)
	service.SetTunnelBuildSink(func(source I2NPSource, records i2np.BuildRecords, got i2np.Message) error {
		calls++
		if source != (I2NPSource{Peer: peer, Direct: true}) || records.Count != 1 || got.Header != message.Header {
			t.Fatalf("short build hand-off = %#v, %#v, %#v", source, records, got)
		}
		return nil
	})
	if err := service.HandleI2NPFrom(peer, message, now, false); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("short build calls = %d, want 1", calls)
	}
}
