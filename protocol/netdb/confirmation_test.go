package netdb

import (
	"context"
	"sync"
	"testing"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/protocol/i2np"
	"gosuda.org/ivnp/support/observability"
)

type publicationTestSender struct {
	mu       sync.Mutex
	messages []i2np.Message
	targets  []ivnp.Hash
}

func (s *publicationTestSender) Send(_ context.Context, target RouterRef, message i2np.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, message)
	s.targets = append(s.targets, target.Hash)
	return nil
}

type publicationTestRoute struct{ gateway ivnp.Hash }

func (r publicationTestRoute) NetDBReplyPath() (ivnp.Hash, uint32, bool) { return r.gateway, 0, true }

func TestConfirmedPublicationUsesDistinctTokensAndAcknowledgements(t *testing.T) {
	var local, gateway, key ivnp.Hash
	local[0], gateway[0], key[0] = 1, 2, 9
	database := NewDatabase(local, DefaultBucketCapacity)
	metrics := observability.NewRegistry()
	database.SetMetrics(metrics)
	for _, value := range []byte{3, 4, 5, 6} {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	now := uint64(1_000)
	sender := &publicationTestSender{}
	registry := NewPublicationTokenRegistry(func() uint64 { return now }, func() uint32 { return 17 })
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: gateway}, registry, func() uint64 { return now }, func() uint32 { return 23 }, key, i2np.StoreLeaseSet2, nil, nil)
	publication.replace([]byte{1})
	sent, err := publication.maintain(context.Background(), true)
	if err != nil || sent != PublicationFloodfillK || len(sender.messages) != PublicationFloodfillK {
		t.Fatalf("initial publication = %d, %v, %d messages", sent, err, len(sender.messages))
	}
	seen := make(map[uint32]struct{}, PublicationFloodfillK)
	for _, message := range sender.messages {
		store, parseErr := i2np.ParseDatabaseStore(message.Payload)
		if parseErr != nil || store.ReplyToken == 0 || store.ReplyToken&(uint32(1)<<31) != 0 || store.ReplyGateway != gateway {
			t.Fatalf("store = %#v, %v", store, parseErr)
		}
		if _, duplicate := seen[store.ReplyToken]; duplicate {
			t.Fatalf("duplicate token %d", store.ReplyToken)
		}
		seen[store.ReplyToken] = struct{}{}
		if !registry.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: now}) {
			t.Fatalf("acknowledgement %d was not correlated", store.ReplyToken)
		}
		if registry.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: now}) {
			t.Fatalf("duplicate acknowledgement %d accepted", store.ReplyToken)
		}
	}
	if got := metrics.Snapshot().Publication.LeaseSet2Successes; got != PublicationFloodfillK {
		t.Fatalf("confirmed LeaseSet2 publications = %d, want %d", got, PublicationFloodfillK)
	}
	if sent, err = publication.maintain(context.Background(), false); err != nil || sent != 0 {
		t.Fatalf("confirmed generation retried = %d, %v", sent, err)
	}
}

func TestConfirmedPublicationPrefersConfiguredVerifiedFloodfills(t *testing.T) {
	var local, gateway, key ivnp.Hash
	local[0], gateway[0], key[0] = 1, 2, 9
	database := NewDatabase(local, DefaultBucketCapacity)
	for _, value := range []byte{3, 4, 5, 6, 7, 8, 10, 11, 12} {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	preferred := []ivnp.Hash{requestTestHash(12), requestTestHash(3)}
	now := uint64(1_000)
	sender := &publicationTestSender{}
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: gateway}, nil, func() uint64 { return now }, func() uint32 { return 23 }, key, i2np.StoreLeaseSet2, preferred, nil)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(context.Background(), true); err != nil || sent != PublicationFloodfillK {
		t.Fatalf("preferred publication = %d, %v", sent, err)
	}
	if len(sender.targets) != PublicationFloodfillK {
		t.Fatalf("publication targets = %v, want %d", sender.targets, PublicationFloodfillK)
	}
	seen := make(map[ivnp.Hash]struct{}, len(sender.targets))
	for _, target := range sender.targets {
		if _, duplicate := seen[target]; duplicate {
			t.Fatalf("duplicate publication target %x", target)
		}
		seen[target] = struct{}{}
	}
	for _, target := range preferred {
		if _, ok := seen[target]; !ok {
			t.Fatalf("preferred publication target %x missing from %v", target, sender.targets)
		}
	}
}
