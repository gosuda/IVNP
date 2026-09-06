package netdb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

type publisherLeaseSource struct {
	leases []foundation.NetworkDatabaseLease
}

func (s *publisherLeaseSource) CurrentInboundLeases(uint64) []foundation.NetworkDatabaseLease {
	return append([]foundation.NetworkDatabaseLease(nil), s.leases...)
}

type publishedLeaseSet struct {
	peer    foundation.Hash
	message foundation.I2NPMessage
}

type publisherSender struct {
	mu        sync.Mutex
	published []publishedLeaseSet
}

func (s *publisherSender) Send(_ context.Context, peer RouterRef, message foundation.I2NPMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = append(s.published, publishedLeaseSet{
		peer: peer.Hash,
		message: foundation.I2NPMessage{
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	for range 3 {
		if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
			t.Fatal(err)
		}
	}
	source := &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 7, EndDate: 600_000}}}
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
	if first.Header.Type != foundation.I2NPDatabaseStore || first.Header.ID != 19 || first.Header.Expiration != now+leaseSetPublicationEnvelopeLifetime {
		t.Fatalf("DatabaseStore header = %#v", first.Header)
	}
	if sender.published[1].message.Header != first.Header || string(sender.published[1].message.Payload) != string(first.Payload) {
		t.Fatal("floodfill sends did not share one canonical store")
	}
	store, err := foundation.I2NPParseDatabaseStore(first.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if store.Key != local.Hash() || store.Type != foundation.I2NPStoreLeaseSet || store.RawType != byte(foundation.I2NPStoreLeaseSet) || store.ReplyToken != 0 {
		t.Fatalf("DatabaseStore = %#v", store)
	}
	leaseSet, err := foundation.NetworkDatabaseParseLeaseSet(store.Data)
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
	if parsed, _, err := foundation.I2NPParse(frame); err != nil || parsed.Header != first.Header || string(parsed.Payload) != string(first.Payload) {
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

	source.leases = []foundation.NetworkDatabaseLease{{TunnelID: 8, EndDate: 620_000}}
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	source := &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 7, EndDate: 10_000}}}
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(publisherFloodfill(t), true, 1); err != nil {
		t.Fatal(err)
	}
	source := &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 7, EndDate: 10_000}}}
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
		Sender: LeaseSetPublishSenderFunc(func(context.Context, RouterRef, foundation.I2NPMessage) error {
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
	source := &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 3, EndDate: 100}}}
	sender := &publisherSender{}
	now := uint64(101)
	signingKey, _ := identity.SigningKeyParts()
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local:          local,
		Database:       NewDatabase(foundation.Hash{}, DefaultBucketCapacity),
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

func publisherFloodfill(t *testing.T) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	options := make([]byte, 16)
	optionLen, err := foundation.MarshalMappingTo(options, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte("f")}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	unsigned = append(unsigned, options[:optionLen]...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
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
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
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
	defer discovery.Close()
	signingKey, _ := identity.SigningKeyParts()
	publishSender := new(publisherSender)
	publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
		Local: local, Database: database, InboundLeases: &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 7, EndDate: 600_000}}},
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
	discovery.active.Wait()
	if len(lookupSender.snapshot()) != 1 {
		t.Fatal("publication did not start routing-key discovery")
	}
	lookup, err := foundation.I2NPParseDatabaseLookup(lookupSender.snapshot()[0].Payload)
	if err != nil || LookupType(lookup.LookupType()) != LeaseSetLookup {
		t.Fatalf("publication discovery lookup = %#v, %v; want LeaseSet lookup", lookup, err)
	}
	now++
	if sent, err := publisher.Maintain(context.Background()); err != nil || sent != 0 {
		t.Fatalf("pending-discovery Maintain() = %d, %v", sent, err)
	}
	if len(publishSender.published) != 1 {
		t.Fatalf("pending discovery published %d stores, want 1", len(publishSender.published))
	}
}

func TestLeaseSetPublisherConfirmsBeforeReplicationDrains(t *testing.T) {
	for _, operation := range []string{"Maintain", "Publish"} {
		t.Run(operation, func(t *testing.T) {
			identity, private := ed25519Identity(t)
			local, err := NewLocalLeaseSet(identity)
			if err != nil {
				t.Fatal(err)
			}
			database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
			for _, value := range []byte{3, 4, 5} {
				addRequestTestFloodfill(database, requestTestHash(value))
			}
			messages := make(chan foundation.I2NPMessage, PublicationFloodfillK)
			release := make(chan struct{})
			releaseSends := sync.OnceFunc(func() { close(release) })
			var completedSends atomic.Int32
			var workers sync.WaitGroup
			defer func() {
				releaseSends()
				workers.Wait()
			}()
			signingKey, _ := identity.SigningKeyParts()
			publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
				Local: local, Database: database,
				InboundLeases: &publisherLeaseSource{leases: []foundation.NetworkDatabaseLease{{TunnelID: 7, EndDate: 600_000}}},
				Sender: LeaseSetPublishSenderFunc(func(_ context.Context, peer RouterRef, message foundation.I2NPMessage) error {
					defer completedSends.Add(1)
					payload := bytes.Clone(message.Payload)
					messages <- message
					if peer.Hash != requestTestHash(3) {
						<-release
					}
					if !bytes.Equal(message.Payload, payload) {
						return errors.New("publication payload changed before Send returned")
					}
					return nil
				}),
				EncryptionKey: bytes.Repeat([]byte{1}, 256), SigningKey: signingKey,
				Sign: func(unsigned []byte) ([]byte, error) { return ed25519.Sign(private, unsigned), nil },
				Now:  func() uint64 { return 1_000 }, Random: func() uint32 { return 19 }, FloodfillLimit: 3,
				ReplyPath: publicationTestRoute{gateway: requestTestHash(8)},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(publisher.Close)
			encryptionKey := publisher.encryptionKey
			finished := make(chan struct{})
			workers.Go(func() {
				defer close(finished)
				publish := publisher.Maintain
				if operation == "Publish" {
					publish = publisher.Publish
				}
				if sent, err := publish(t.Context()); err != nil || sent != PublicationFloodfillK {
					t.Errorf("%s() = %d, %v", operation, sent, err)
				}
			})
			var first foundation.I2NPMessage
			for range PublicationFloodfillK {
				select {
				case first = <-messages:
				case <-time.After(5 * time.Second):
					t.Fatal("publication did not start all replication sends")
				}
			}
			store, err := foundation.I2NPParseDatabaseStore(first.Payload)
			if err != nil {
				t.Fatal(err)
			}
			ready := make(chan bool, 1)
			workers.Go(func() {
				accepted := publisher.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: store.ReplyToken, Timestamp: 1_000})
				ready <- accepted && publisher.Confirmed()
			})
			select {
			case confirmed := <-ready:
				if !confirmed {
					t.Fatal("first current-generation ACK did not make publication ready")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("readiness blocked on sibling network sends")
			}
			select {
			case <-finished:
				t.Fatal("publication returned before sibling sends drained")
			default:
			}
			closing := make(chan struct{})
			workers.Go(func() {
				close(closing)
				publisher.Close()
				if got := completedSends.Load(); got != PublicationFloodfillK {
					t.Errorf("Close returned with %d/%d sends completed", got, PublicationFloodfillK)
				}
			})
			<-closing
			if !bytes.Equal(encryptionKey, bytes.Repeat([]byte{1}, 256)) {
				t.Fatal("Close wiped encryption material while publication was active")
			}
			releaseSends()
			workers.Wait()
			if publisher.Confirmed() {
				t.Error("closed publisher remained ready")
			}
			if !bytes.Equal(encryptionKey, make([]byte, 256)) {
				t.Error("Close retained copied encryption key")
			}
		})
	}
}

func TestEncryptedLeaseSetPublisherRejectsReplacedGenerationAcknowledgements(t *testing.T) {
	for _, advance := range []time.Duration{time.Second, 24 * time.Hour} {
		t.Run(advance.String(), func(t *testing.T) {
			destination, _, encrypted, now := encryptedTestSet(t, EncryptedLeaseSetAuthorization{})
			defer destination.ReleaseSensitive()
			database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
			for _, value := range []byte{3, 4, 5} {
				addRequestTestFloodfill(database, requestTestHash(value))
			}
			sender := &publisherSender{}
			registry := NewPublicationTokenRegistry(func() uint64 { return now }, func() uint32 { return 19 })
			defer registry.Close()
			publisher, err := NewLeaseSetPublisher(LeaseSetPublisherConfig{
				Encrypted: encrypted, Database: database, Sender: sender,
				InboundLeases: InboundLeaseSourceFunc(func(uint64) []foundation.NetworkDatabaseLease {
					return []foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{1}, TunnelID: 7, EndDate: now + 600_000}}
				}),
				Now: func() uint64 { return now }, Random: func() uint32 { return 23 }, FloodfillLimit: 3,
				Registry: registry, ReplyPath: publicationTestRoute{gateway: requestTestHash(8)},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			if sent, err := publisher.Publish(t.Context()); err != nil || sent != PublicationFloodfillK {
				t.Fatalf("initial Publish() = %d, %v", sent, err)
			}
			acknowledged, err := foundation.I2NPParseDatabaseStore(sender.published[0].message.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if !publisher.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: acknowledged.ReplyToken, Timestamp: now}) || !publisher.Confirmed() {
				t.Fatal("initial generation did not become ready")
			}
			pending, err := foundation.I2NPParseDatabaseStore(sender.published[1].message.Payload)
			if err != nil {
				t.Fatal(err)
			}
			stale := foundation.I2NPDeliveryStatusMessage{MessageID: pending.ReplyToken, Timestamp: now}
			now += uint64(advance / time.Millisecond)
			if sent, err := publisher.Maintain(t.Context()); err != nil || sent != PublicationFloodfillK {
				t.Fatalf("replacement Maintain() = %d, %v", sent, err)
			}
			if registry.HandleDeliveryStatus(stale) || publisher.HandleDeliveryStatus(stale) {
				t.Fatal("replaced generation accepted a pending ACK")
			}
			if publisher.Confirmed() {
				t.Fatal("replacement inherited readiness from its previous generation")
			}
			current, err := foundation.I2NPParseDatabaseStore(sender.published[PublicationFloodfillK].message.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if (current.Key != pending.Key) != (advance == 24*time.Hour) {
				t.Fatal("publication key rotation did not match the day boundary")
			}
			if !publisher.HandleDeliveryStatus(foundation.I2NPDeliveryStatusMessage{MessageID: current.ReplyToken, Timestamp: now}) || !publisher.Confirmed() {
				t.Fatal("current-generation ACK did not restore readiness")
			}
		})
	}
}
