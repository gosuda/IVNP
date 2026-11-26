package netdb

import (
	"context"
	"errors"
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

// An empty target snapshot sends nothing, so it must not arm the
// confirmation backoff: a cold-starting router whose NetDB fills seconds
// later would otherwise wait a full PublicationConfirmTimeout before its
// first RouterInfo or LeaseSet store.
func TestEmptyTargetSnapshotDoesNotArmPublicationBackoff(t *testing.T) {
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
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != 1 {
		t.Fatalf("periodic publication to target discovered after empty snapshot = %d, %v", sent, err)
	}
	if len(sender.targets) != 1 || sender.targets[0] != target {
		t.Fatalf("publication targets = %v, want [%x]", sender.targets, target)
	}
}

type toggledPublicationRoute struct {
	mu      sync.Mutex
	gateway foundation.Hash
	ready   bool
}

func (r *toggledPublicationRoute) NetDBReplyPath() (foundation.Hash, uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gateway, 0, r.ready
}

func (r *toggledPublicationRoute) set(ready bool) {
	r.mu.Lock()
	r.ready = ready
	r.mu.Unlock()
}

// A pass that skips every target because no reply path exists yet also sends
// nothing and must not arm the backoff; the store goes out as soon as the
// reply path appears.
func TestMissingReplyPathDoesNotArmPublicationBackoff(t *testing.T) {
	const now = uint64(1_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	for _, value := range []byte{3, 4, 5, 6} {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	sender := new(publicationTestSender)
	route := &toggledPublicationRoute{gateway: foundation.Hash{2}}
	publication := newConfirmedPublication(database, sender, route, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, PublicationFloodfillK, nil)
	t.Cleanup(publication.close)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(t.Context(), false); sent != 0 || !errors.Is(err, ErrInvalidReplyRoute) {
		t.Fatalf("publication without reply path = %d, %v", sent, err)
	}
	route.set(true)
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != PublicationFloodfillK {
		t.Fatalf("periodic publication after reply path appeared = %d, %v", sent, err)
	}
}

// Stores that were actually sent keep the backoff: an unconfirmed target set
// is not retried before PublicationConfirmTimeout.
func TestSentPublicationKeepsConfirmationBackoff(t *testing.T) {
	now := uint64(1_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	for _, value := range []byte{3, 4, 5} {
		addRequestTestFloodfill(database, requestTestHash(value))
	}
	sender := new(publicationTestSender)
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: foundation.Hash{2}}, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, PublicationFloodfillK, nil)
	t.Cleanup(publication.close)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != PublicationFloodfillK {
		t.Fatalf("initial publication = %d, %v", sent, err)
	}
	now += PublicationConfirmTimeout - 1
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != 0 {
		t.Fatalf("unconfirmed publication retried inside backoff = %d, %v", sent, err)
	}
	now++
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != PublicationFloodfillK {
		t.Fatalf("publication after confirmation timeout = %d, %v", sent, err)
	}
}

type failingOncePublicationSender struct {
	publicationTestSender
	failed bool
}

func (s *failingOncePublicationSender) Send(ctx context.Context, target RouterRef, message foundation.I2NPMessage) error {
	s.mu.Lock()
	if !s.failed {
		s.failed = true
		s.mu.Unlock()
		return errors.New("send failed")
	}
	s.mu.Unlock()
	return s.publicationTestSender.Send(ctx, target, message)
}

// A store handed to the sender arms the backoff even when the send fails, so
// periodic passes do not hammer an unreachable floodfill set; a forced pass
// still re-snapshots and reaches a newly discovered target.
func TestForcedPublicationDiscoversTargetsDuringBackoff(t *testing.T) {
	const now = uint64(1_000)
	key := foundation.Hash{9}
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	addRequestTestFloodfill(database, requestTestHash(3))
	sender := new(failingOncePublicationSender)
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: foundation.Hash{2}}, nil,
		func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, PublicationFloodfillK, nil)
	t.Cleanup(publication.close)
	publication.replace([]byte{1})
	if sent, err := publication.maintain(t.Context(), false); err == nil || sent != 0 {
		t.Fatalf("failed initial publication = %d, %v", sent, err)
	}
	target := requestTestHash(4)
	addRequestTestFloodfill(database, target)
	if sent, err := publication.maintain(t.Context(), false); err != nil || sent != 0 {
		t.Fatalf("periodic publication ignored backoff after a failed send: %d, %v", sent, err)
	}
	if sent, err := publication.maintain(t.Context(), true); err != nil || sent != 2 {
		t.Fatalf("forced publication after backoff = %d, %v", sent, err)
	}
	found := false
	for _, got := range sender.targets {
		found = found || got == target
	}
	if !found {
		t.Fatalf("publication targets = %v, want %x", sender.targets, target)
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

func TestConfirmedPublicationDoesNotResendToAlreadyConfirmedTargets(t *testing.T) {
	var local, gateway, key foundation.Hash
	local[0], gateway[0], key[0] = 1, 2, 9
	database := NewDatabase(local, DefaultBucketCapacity)
	onlyFloodfill := requestTestHash(3)
	addRequestTestFloodfill(database, onlyFloodfill)

	now := uint64(1_000)
	sender := &publicationTestSender{}
	registry := NewPublicationTokenRegistry(func() uint64 { return now }, func() uint32 { return 17 })
	publication := newConfirmedPublication(database, sender, publicationTestRoute{gateway: gateway}, registry, func() uint64 { return now }, func() uint32 { return 23 }, key, foundation.I2NPStoreLeaseSet2, nil, LeaseSetPublicationFloodfillK, nil)
	publication.replace([]byte{1})

	sent, err := publication.maintain(context.Background(), true)
	if err != nil || sent != 1 || len(sender.messages) != 1 {
		t.Fatalf("initial publication = %d, %v, %d messages", sent, err, len(sender.messages))
	}
	store, err := foundation.I2NPParseDatabaseStore(sender.messages[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: now}) {
		t.Fatal("acknowledgement not correlated")
	}

	now += PublicationConfirmTimeout + 1
	if sent, err = publication.maintain(context.Background(), true); err != nil || sent != 0 {
		t.Fatalf("confirmed floodfill received duplicate store: sent=%d err=%v", sent, err)
	}

	secondFloodfill := requestTestHash(4)
	addRequestTestFloodfill(database, secondFloodfill)
	if sent, err = publication.maintain(context.Background(), true); err != nil || sent != 1 {
		t.Fatalf("newly discovered floodfill publication = %d, %v", sent, err)
	}
	if sender.targets[len(sender.targets)-1] != secondFloodfill {
		t.Fatalf("new publication target = %x, want %x", sender.targets[len(sender.targets)-1], secondFloodfill)
	}
}
