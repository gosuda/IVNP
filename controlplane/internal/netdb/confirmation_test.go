package netdb

import (
	"context"
	"sync"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

type publicationTestSender struct {
	mu       sync.Mutex
	messages []foundation.I2NPMessage
	targets  []foundation.Hash
}

func (s *publicationTestSender) Send(_ context.Context, target RouterRef, message foundation.I2NPMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, message)
	s.targets = append(s.targets, target.Hash)
	return nil
}

type publicationTestRoute struct{ gateway foundation.Hash }

func (r publicationTestRoute) NetDBReplyPath() (foundation.Hash, uint32, bool) {
	return r.gateway, 0, true
}

func TestConfirmedPublicationUsesDistinctTokensAndAcknowledgements(t *testing.T) {
	var local, gateway, key foundation.Hash
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
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: gateway}, registry, func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, PublicationFloodfillK, nil)
	publication.replace([]byte{1})
	sent, err := publication.maintain(context.Background(), true)
	if err != nil || sent != PublicationFloodfillK || len(sender.messages) != PublicationFloodfillK {
		t.Fatalf("initial publication = %d, %v, %d messages", sent, err, len(sender.messages))
	}
	seen := make(map[uint32]struct{}, PublicationFloodfillK)
	for _, message := range sender.messages {
		store, parseErr := foundation.I2NPParseDatabaseStore(message.Payload)
		if parseErr != nil || store.ReplyToken == 0 || store.ReplyToken&(uint32(1)<<31) != 0 || store.ReplyGateway != gateway {
			t.Fatalf("store = %#v, %v", store, parseErr)
		}
		if _, duplicate := seen[store.ReplyToken]; duplicate {
			t.Fatalf("duplicate token %d", store.ReplyToken)
		}
		seen[store.ReplyToken] = struct{}{}
		if !registry.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: now}) {
			t.Fatalf("acknowledgement %d was not correlated", store.ReplyToken)
		}
		if registry.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: now}) {
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
	var local, gateway, key foundation.Hash
	local[0], gateway[0], key[0] = 1, 2, 9
	database := NewDatabase(local, DefaultBucketCapacity)
	for _, value := range []byte{3, 4, 5, 6, 7, 8, 10, 11, 12} {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	preferred := []foundation.Hash{requestTestHash(12), requestTestHash(3)}
	now := uint64(1_000)
	sender := &publicationTestSender{}
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: gateway}, nil, func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, preferred, PublicationFloodfillK, nil)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(context.Background(), true); err != nil || sent != PublicationFloodfillK {
		t.Fatalf("preferred publication = %d, %v", sent, err)
	}
	if len(sender.targets) != PublicationFloodfillK {
		t.Fatalf("publication targets = %v, want %d", sender.targets, PublicationFloodfillK)
	}
	seen := make(map[foundation.Hash]struct{}, len(sender.targets))
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

func TestForcedPublicationDiscoversTargetsDuringBackoff(t *testing.T) {
	const now = uint64(1_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	sender := new(publicationTestSender)
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: foundation.Hash{2}}, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, 0, nil)
	t.Cleanup(publication.close)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != 0 {
		t.Fatalf("publication without targets = %d, %v", sent, err)
	}
	target := requestTestHash(3)
	addRequestTestFloodfill(database, target)
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != 0 {
		t.Fatalf("periodic publication ignored backoff: %d, %v", sent, err)
	}
	if sent, err := publication.maintain(t.Context(), true); err != nil || sent != 1 {
		t.Fatalf("forced publication to discovered target = %d, %v", sent, err)
	}
	if len(sender.targets) != 1 || sender.targets[0] != target {
		t.Fatalf("publication targets = %v, want [%x]", sender.targets, target)
	}
}

func TestConfirmedPublicationTargetDefaults(t *testing.T) {
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	for i := byte(2); i <= 15; i++ {
		addRequestTestFloodfill(database, requestTestHash(i))
	}
	sender := new(publicationTestSender)
	now := uint64(1_000)

	// LeaseSet should default to LeaseSetPublicationFloodfillK (4)
	lsPub := newConfirmedPublication(database, sender, publicationTestRoute{gateway: foundation.Hash{2}}, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, foundation.Hash{9}, foundation.I2NPStoreLeaseSet2, nil, 0, nil)
	lsPub.replace([]byte{1})
	if sent, err := lsPub.maintain(t.Context(), true); err != nil || sent != LeaseSetPublicationFloodfillK {
		t.Fatalf("LeaseSet default sent = %d, want %d (err: %v)", sent, LeaseSetPublicationFloodfillK, err)
	}

	// RouterInfo should default to RouterInfoPublicationFloodfillK (5)
	senderRouter := new(publicationTestSender)
	riPub := newConfirmedPublication(database, senderRouter, publicationTestRoute{gateway: foundation.Hash{2}}, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, foundation.Hash{9}, foundation.I2NPStoreRouterInfo, nil, 0, nil)
	riPub.replace([]byte{1})
	if sent, err := riPub.maintain(t.Context(), true); err != nil || sent != RouterInfoPublicationFloodfillK {
		t.Fatalf("RouterInfo default sent = %d, want %d (err: %v)", sent, RouterInfoPublicationFloodfillK, err)
	}
}
