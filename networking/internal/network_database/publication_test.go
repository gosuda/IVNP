package netdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"sync"
	"testing"
)

type publisherLeaseSource struct {
	leases []Lease
}

func (s *publisherLeaseSource) CurrentInboundLeases(uint64) []Lease {
	return append([]Lease(nil), s.leases...)
}

type publishedLeaseSet struct {
	peer    ivnp.Hash
	message i2np.Message
}

type publisherSender struct {
	mu        sync.Mutex
	published []publishedLeaseSet
}

func (s *publisherSender) Send(_ context.Context, peer RouterRef, message i2np.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = append(s.published, publishedLeaseSet{
		peer: peer.Hash,
		message: i2np.Message{
			Header:  message.Header,
			Payload: append([]byte(nil), message.Payload...),
		},
	})
	return nil
}

func TestLeaseSetPublisherSerializesAndRepublishes(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	for range 3 {
		if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
			t.Fatal(err)
		}
	}
	source := &publisherLeaseSource{leases: []Lease{{TunnelID: 7, EndDate: 600_000}}}
	sender := &publisherSender{}
	now := uint64(1_000)
	signCalls := 0
	signingKey, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		t.Fatalf("identity signing key remainder = %x", rest)
	}
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local:           local,
		Database:        database,
		InboundLeases:   source,
		Sender:          sender,
		EncryptionKey:   make([]byte, 256),
		SigningKey:      signingKey,
		Sign:            func(unsigned []byte) ([]byte, error) { signCalls++; return ed25519.Sign(private, unsigned), nil },
		Now:             func() uint64 { return now },
		Random:          func() uint32 { return 19 },
		FloodfillLimit:  2,
		RepublishBefore: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}

	if sent, err := publisher.Publish(context.Background()); err != nil || sent != 2 {
		t.Fatalf("Publish() = %d, %v", sent, err)
	}
	if signCalls != 1 || len(sender.published) != 2 {
		t.Fatalf("sign calls/publishes = %d/%d, want 1/2", signCalls, len(sender.published))
	}
	first := sender.published[0].message
	if first.Header.Type != i2np.DatabaseStore || first.Header.ID != 19 || first.Header.Expiration != now+leaseSetPublicationEnvelopeLifetime {
		t.Fatalf("DatabaseStore header = %#v", first.Header)
	}
	if sender.published[1].message.Header != first.Header || string(sender.published[1].message.Payload) != string(first.Payload) {
		t.Fatal("floodfill sends did not share one canonical store")
	}
	store, err := i2np.ParseDatabaseStore(first.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if store.Key != local.Hash() || store.Type != i2np.StoreLeaseSet || store.RawType != byte(i2np.StoreLeaseSet) || store.ReplyToken != 0 {
		t.Fatalf("DatabaseStore = %#v", store)
	}
	leaseSet, err := ParseLeaseSet(store.Data)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := leaseSet.Verify(); err != nil || !valid {
		t.Fatalf("published LeaseSet verification = %t, %v", valid, err)
	}
	frame := make([]byte, first.EncodedLen())
	if _, err := first.MarshalTo(frame); err != nil {
		t.Fatal(err)
	}
	if parsed, _, err := i2np.Parse(frame); err != nil || parsed.Header != first.Header || string(parsed.Payload) != string(first.Payload) {
		t.Fatalf("canonical I2NP frame = %#v, %v", parsed, err)
	}

	now = 598_000
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("early Maintain() = %d, %v", sent, err)
	}
	now = 599_000
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 2 {
		t.Fatalf("renewal Maintain() = %d, %v", sent, err)
	}
	if signCalls != 1 || len(sender.published) != 4 {
		t.Fatalf("unchanged republish signed/published = %d/%d, want 1/4", signCalls, len(sender.published))
	}

	source.leases = []Lease{{TunnelID: 8, EndDate: 620_000}}
	now = 599_100
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 2 {
		t.Fatalf("changed Maintain() = %d, %v", sent, err)
	}
	if signCalls != 2 || len(sender.published) != 6 {
		t.Fatalf("changed publication signed/published = %d/%d, want 2/6", signCalls, len(sender.published))
	}
}

func TestLeaseSetPublisherRetriesWhenNoFloodfillWasAvailable(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	source := &publisherLeaseSource{leases: []Lease{{TunnelID: 7, EndDate: 10_000}}}
	sender := &publisherSender{}
	now := uint64(1_000)
	signCalls := 0
	signingKey, _ := identity.SigningKeyParts()
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local:           local,
		Database:        database,
		InboundLeases:   source,
		Sender:          sender,
		EncryptionKey:   make([]byte, 256),
		SigningKey:      signingKey,
		Sign:            func(unsigned []byte) ([]byte, error) { signCalls++; return ed25519.Sign(private, unsigned), nil },
		Now:             func() uint64 { return now },
		Random:          func() uint32 { return 1 },
		FloodfillLimit:  1,
		RepublishBefore: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}

	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("initial Maintain() = %d, %v", sent, err)
	}
	if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
		t.Fatal(err)
	}
	now = 1_999
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("early retry Maintain() = %d, %v", sent, err)
	}
	now = 2_000
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 1 {
		t.Fatalf("retry Maintain() = %d, %v", sent, err)
	}
	if signCalls != 1 || len(sender.published) != 1 {
		t.Fatalf("retry re-signed/published = %d/%d, want 1/1", signCalls, len(sender.published))
	}
}

func TestLeaseSetPublisherRetriesAfterAllSendsFail(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
		t.Fatal(err)
	}
	source := &publisherLeaseSource{leases: []Lease{{TunnelID: 7, EndDate: 10_000}}}
	now := uint64(1_000)
	signCalls := 0
	sendCalls := 0
	fail := true
	sendErr := errors.New("send failed")
	signingKey, _ := identity.SigningKeyParts()
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local:         local,
		Database:      database,
		InboundLeases: source,
		Sender: LeaseSetPublishSenderFunc(func(context.Context, RouterRef, i2np.Message) error {
			sendCalls++
			if fail {
				return sendErr
			}
			return nil
		}),
		EncryptionKey:   make([]byte, 256),
		SigningKey:      signingKey,
		Sign:            func(unsigned []byte) ([]byte, error) { signCalls++; return ed25519.Sign(private, unsigned), nil },
		Now:             func() uint64 { return now },
		Random:          func() uint32 { return 1 },
		FloodfillLimit:  1,
		RepublishBefore: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}

	if sent, err := publisher.Maintain(context.Background()); sent != 0 || !errors.Is(err, sendErr) {
		t.Fatalf("failing Maintain() = %d, %v", sent, err)
	}
	now = 1_999
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("early retry Maintain() = %d, %v", sent, err)
	}
	fail = false
	now = 2_000
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 1 {
		t.Fatalf("retry Maintain() = %d, %v", sent, err)
	}
	if signCalls != 1 || sendCalls != 2 {
		t.Fatalf("retry re-signed/send calls = %d/%d, want 1/2", signCalls, sendCalls)
	}
}

func TestLeaseSetPublicationEnvelopeExpirationSaturates(t *testing.T) {
	if got := saturatingAdd(^uint64(0)-5, leaseSetPublicationEnvelopeLifetime); got != ^uint64(0) {
		t.Fatalf("saturatingAdd() = %d, want %d", got, ^uint64(0))
	}
}

func TestLeaseSetPublisherExpiresStaleInboundLeases(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	source := &publisherLeaseSource{leases: []Lease{{TunnelID: 3, EndDate: 100}}}
	sender := &publisherSender{}
	now := uint64(101)
	signingKey, _ := identity.SigningKeyParts()
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local:          local,
		Database:       NewDatabase(ivnp.Hash{}, DefaultBucketCapacity),
		InboundLeases:  source,
		Sender:         sender,
		EncryptionKey:  make([]byte, 256),
		SigningKey:     signingKey,
		Sign:           func(unsigned []byte) ([]byte, error) { return ed25519.Sign(private, unsigned), nil },
		Now:            func() uint64 { return now },
		Random:         func() uint32 { return 1 },
		FloodfillLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent, err := publisher.Publish(context.Background()); err != nil || sent != 0 {
		t.Fatalf("Publish() stale lease = %d, %v", sent, err)
	}
	if snapshot, ok := local.Snapshot(now); !ok || len(snapshot.Leases) != 0 || snapshot.ExpiresAt != 0 {
		t.Fatalf("stale local snapshot = %#v", snapshot)
	}
	if len(sender.published) != 0 {
		t.Fatalf("stale lease publication count = %d", len(sender.published))
	}
}

func publisherFloodfill(t *testing.T) RouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ivnp.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(ivnp.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(ivnp.CryptoElGamal)
	options := make([]byte, 16)
	optionLen, err := ivnp.MarshalMappingTo(options, []ivnp.MappingEntry{{Key: []byte("caps"), Value: []byte("f")}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := ParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestLeaseSetPublisherDoesNotRepublishWhileDiscoveryPending(t *testing.T) {
	identity, private := ed25519Identity(t)
	local, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	floodfill := publisherFloodfill(t)
	if err = database.AdmitRouterInfo(floodfill, true, 1); err != nil {
		t.Fatal(err)
	}
	now := uint64(1_000)
	lookupSender := new(requestTestSender)
	discovery, err := NewRequestManager(database, lookupSender, requestTestRoute{gateway: requestTestHash(8)}, RequestManagerConfig{
		Capacity: 1, MaxCandidates: 4, TimeoutMillis: 60_000, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	signingKey, _ := identity.SigningKeyParts()
	publishSender := new(publisherSender)
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local: local, Database: database, InboundLeases: &publisherLeaseSource{leases: []Lease{{TunnelID: 7, EndDate: 600_000}}},
		Sender: publishSender, Discovery: discovery, EncryptionKey: make([]byte, 256), SigningKey: signingKey,
		Sign: func(unsigned []byte) ([]byte, error) { return ed25519.Sign(private, unsigned), nil },
		Now:  func() uint64 { return now }, Random: func() uint32 { return 19 }, FloodfillLimit: 1, RepublishBefore: 1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent, err := publisher.Publish(context.Background()); err != nil || sent != 1 {
		t.Fatalf("initial Publish() = %d, %v", sent, err)
	}
	if len(lookupSender.snapshot()) != 1 {
		t.Fatal("publication did not start routing-key discovery")
	}
	now++
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("pending-discovery Maintain() = %d, %v", sent, err)
	}
	if len(publishSender.published) != 1 {
		t.Fatalf("pending discovery published %d stores, want 1", len(publishSender.published))
	}
}
