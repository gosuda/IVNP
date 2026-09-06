package noderuntime

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type seedTestSession struct {
	calls atomic.Int32
	send  func(context.Context, foundation.I2NPMessage) error
}

func (s *seedTestSession) Send(ctx context.Context, message foundation.I2NPMessage) error {
	s.calls.Add(1)
	if s.send != nil {
		return s.send(ctx, message)
	}
	return nil
}

type seedTestTransport struct {
	session *seedTestSession
}

func (s *seedTestTransport) PrepareSession(context.Context, foundation.Hash) (dataplane.RouterSessionSender, error) {
	return s.session, nil
}

func (*seedTestTransport) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return errors.New("seed bypassed its prepared session")
}

func seedTestRouterInfo(t testing.TB, published uint64) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], private.Public().(ed25519.PublicKey))
	identity[384] = byte(foundation.CertificateKey)
	identity[386] = 4
	identity[388] = byte(foundation.SigningEdDSASHA512Ed25519)
	identity[390] = byte(foundation.CryptoElGamal)
	unsigned := append(identity, make([]byte, 12)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):], published)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func seedTestDatabase(t testing.TB, info foundation.NetworkDatabaseRouterInfo) *netdb.Database {
	t.Helper()
	database := netdb.NewDatabase(foundation.Hash{}, netdb.DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(info, false, info.Published); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestReplyRouterInfoSeedInvalidation(t *testing.T) {
	for _, scenario := range []string{"duplicate", "different endpoint", "updated snapshot", "expiry", "replacement session"} {
		t.Run(scenario, func(t *testing.T) {
			current := uint64(1_000_000)
			info := seedTestRouterInfo(t, current)
			database := seedTestDatabase(t, info)
			var cache replyRouterInfoSeeds
			session := &seedTestSession{}
			transport := &seedTestTransport{session: session}
			now := func() uint64 { return current }
			endpoint := foundation.Hash{1}
			if err := cache.seed(t.Context(), database, transport, now, endpoint, info.Hash()); err != nil {
				t.Fatal(err)
			}
			want := int32(2)
			switch scenario {
			case "duplicate":
				current += replyRouterInfoSeedLifetime - 1
				want = 1
			case "different endpoint":
				endpoint = foundation.Hash{2}
			case "updated snapshot":
				current++
				info = seedTestRouterInfo(t, current)
				if err := database.AdmitRouterInfo(info, false, current); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				current += replyRouterInfoSeedLifetime
			case "replacement session":
				transport.session = &seedTestSession{}
			}
			var delivered []byte
			transport.session.send = func(_ context.Context, message foundation.I2NPMessage) error {
				delivered = bytes.Clone(message.Payload)
				return nil
			}
			if err := cache.seed(t.Context(), database, transport, now, endpoint, info.Hash()); err != nil {
				t.Fatal(err)
			}
			calls := session.calls.Load()
			if session != transport.session {
				calls += transport.session.calls.Load()
			}
			if calls != want {
				t.Fatalf("seed sends = %d, want %d", calls, want)
			}
			if want == 2 {
				store, err := foundation.I2NPParseDatabaseStore(delivered)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := gzip.NewReader(bytes.NewReader(store.Data))
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(reader)
				if err = errors.Join(err, reader.Close()); err != nil {
					t.Fatal(err)
				}
				if store.Key != info.Hash() || !bytes.Equal(raw, info.Bytes()) {
					t.Fatal("seed did not deliver the current signed RouterInfo")
				}
			}
		})
	}
}

func TestReplyRouterInfoSeedRetriesFailuresAndCancellation(t *testing.T) {
	for _, scenario := range []string{"send failure", "canceled successful send", "already canceled"} {
		t.Run(scenario, func(t *testing.T) {
			info := seedTestRouterInfo(t, 1_000_000)
			database := seedTestDatabase(t, info)
			var cache replyRouterInfoSeeds
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("send failed")
			session := &seedTestSession{send: func(context.Context, foundation.I2NPMessage) error { return failure }}
			wantErr := failure
			wantCalls := int32(2)
			switch scenario {
			case "canceled successful send":
				session.send = func(context.Context, foundation.I2NPMessage) error { cancel(); return nil }
				wantErr = context.Canceled
			case "already canceled":
				cancel()
				wantErr = context.Canceled
				wantCalls = 1
			}
			transport := &seedTestTransport{session: session}
			now := func() uint64 { return info.Published }
			if err := cache.seed(ctx, database, transport, now, foundation.Hash{1}, info.Hash()); !errors.Is(err, wantErr) {
				t.Fatalf("seed error = %v, want %v", err, wantErr)
			}
			session.send = nil
			if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); err != nil {
				t.Fatal(err)
			}
			if calls := session.calls.Load(); calls != wantCalls {
				t.Fatalf("send attempts = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestReplyRouterInfoSeedCoalescesWithoutBlockingOtherEndpoints(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		info := seedTestRouterInfo(t, 1_000_000)
		database := seedTestDatabase(t, info)
		var cache replyRouterInfoSeeds
		entered, release := make(chan struct{}), make(chan struct{})
		var first sync.Once
		session := &seedTestSession{send: func(context.Context, foundation.I2NPMessage) error {
			blocked := false
			first.Do(func() { blocked = true; close(entered) })
			if blocked {
				<-release
			}
			return nil
		}}
		transport := &seedTestTransport{session: session}
		now := func() uint64 { return info.Published }
		results := make(chan error, 9)
		go func() { results <- cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()) }()
		<-entered
		for range 8 {
			go func() { results <- cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()) }()
		}
		synctest.Wait()
		if calls := session.calls.Load(); calls != 1 {
			t.Errorf("concurrent duplicate sends = %d, want 1", calls)
		}
		canceled, cancel := context.WithCancel(t.Context())
		canceledResult := make(chan error, 1)
		go func() {
			canceledResult <- cache.seed(canceled, database, transport, now, foundation.Hash{1}, info.Hash())
		}()
		synctest.Wait()
		cancel()
		if err := <-canceledResult; !errors.Is(err, context.Canceled) {
			t.Errorf("canceled waiter error = %v", err)
		}
		if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{2}, info.Hash()); err != nil {
			t.Error(err)
		}
		close(release)
		for range 9 {
			if err := <-results; err != nil {
				t.Error(err)
			}
		}
		if calls := session.calls.Load(); calls != 2 {
			t.Errorf("sends across two endpoints = %d, want 2", calls)
		}
	})
}

func TestReplyRouterInfoSeedRejectsSnapshotThatAgedOut(t *testing.T) {
	info := seedTestRouterInfo(t, 1_000_000)
	database := seedTestDatabase(t, info)
	var cache replyRouterInfoSeeds
	session := &seedTestSession{}
	transport := &seedTestTransport{session: session}
	current := info.Published
	now := func() uint64 { return current }
	if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); err != nil {
		t.Fatal(err)
	}
	current += netdb.RouterInfoMaxAgeMillis + 1
	if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); !errors.Is(err, netdb.ErrRouterInfoStale) {
		t.Fatalf("stale snapshot error = %v", err)
	}
	if calls := session.calls.Load(); calls != 1 {
		t.Fatalf("stale snapshot was sent: calls = %d", calls)
	}
}

func TestReplyRouterInfoSeedEvictsExpiredSessionReferences(t *testing.T) {
	info := seedTestRouterInfo(t, 1_000_000)
	database := seedTestDatabase(t, info)
	var cache replyRouterInfoSeeds
	transport := &seedTestTransport{session: &seedTestSession{}}
	current := info.Published
	now := func() uint64 { return current }
	if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); err != nil {
		t.Fatal(err)
	}
	current += replyRouterInfoSeedLifetime
	transport.session = &seedTestSession{}
	if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{2}, info.Hash()); err != nil {
		t.Fatal(err)
	}
	if len(cache.seeds) != 1 {
		t.Fatalf("retained expired transport sessions: entries = %d", len(cache.seeds))
	}
}

func BenchmarkReplyRouterInfoRepeatedSeed(b *testing.B) {
	info := seedTestRouterInfo(b, 1_000_000)
	database := seedTestDatabase(b, info)
	var cache replyRouterInfoSeeds
	transport := &seedTestTransport{session: &seedTestSession{}}
	now := func() uint64 { return info.Published }
	b.ReportAllocs()
	for b.Loop() {
		if err := cache.seed(b.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestReplyRouterInfoSeedBoundsCacheAndReseedsEvictedEndpoint(t *testing.T) {
	current := uint64(1_000_000)
	info := seedTestRouterInfo(t, current)
	database := seedTestDatabase(t, info)
	var cache replyRouterInfoSeeds
	session := &seedTestSession{}
	transport := &seedTestTransport{session: session}
	now := func() uint64 { return current }
	for id := range replyRouterInfoSeedCapacity + 1 {
		var endpoint foundation.Hash
		binary.BigEndian.PutUint32(endpoint[:4], uint32(id+1))
		if err := cache.seed(t.Context(), database, transport, now, endpoint, info.Hash()); err != nil {
			t.Fatal(err)
		}
		current++
	}
	if len(cache.seeds) > replyRouterInfoSeedCapacity {
		t.Fatalf("seed cache exceeded its bound: %d", len(cache.seeds))
	}
	var first foundation.Hash
	binary.BigEndian.PutUint32(first[:4], 1)
	if err := cache.seed(t.Context(), database, transport, now, first, info.Hash()); err != nil {
		t.Fatal(err)
	}
	if calls := session.calls.Load(); calls != replyRouterInfoSeedCapacity+2 {
		t.Fatalf("send attempts = %d, want eviction to trigger a fresh seed", calls)
	}
	for version := range replyRouterInfoPayloadCapacity + 1 {
		updated := seedTestRouterInfo(t, info.Published+uint64(version)+1)
		if _, _, err := cache.payload(updated); err != nil {
			t.Fatal(err)
		}
	}
	if len(cache.payloads) > replyRouterInfoPayloadCapacity {
		t.Fatalf("payload cache exceeded its bound: %d", len(cache.payloads))
	}
}

type seedOwningTransport struct {
	wires [][]byte
}

func (s *seedOwningTransport) Send(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage) error {
	s.wires = append(s.wires, bytes.Clone(message.Payload))
	clear(message.Payload)
	return nil
}

func TestReplyRouterInfoSeedProtectsCachedPayloadFromOwningSender(t *testing.T) {
	info := seedTestRouterInfo(t, 1_000_000)
	database := seedTestDatabase(t, info)
	var cache replyRouterInfoSeeds
	transport := &seedOwningTransport{}
	for range 2 {
		if err := cache.seed(t.Context(), database, transport, func() uint64 { return info.Published }, foundation.Hash{1}, info.Hash()); err != nil {
			t.Fatal(err)
		}
	}
	if len(transport.wires) != 2 || !bytes.Equal(transport.wires[0], transport.wires[1]) {
		t.Fatal("untracked sender suppressed a send or mutated the cached payload")
	}
}

func TestReplyRouterInfoSeedCloseReleasesHandlesAndWakesWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		info := seedTestRouterInfo(t, 1_000_000)
		database := seedTestDatabase(t, info)
		var cache replyRouterInfoSeeds
		session := &seedTestSession{}
		transport := &seedTestTransport{session: session}
		now := func() uint64 { return info.Published }
		if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{1}, info.Hash()); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		session.send = func(_ context.Context, message foundation.I2NPMessage) error {
			original := bytes.Clone(message.Payload)
			close(entered)
			<-release
			if !bytes.Equal(message.Payload, original) {
				return errors.New("close modified an active send's borrowed payload")
			}
			return nil
		}
		leader, waiter := make(chan error, 1), make(chan error, 1)
		go func() { leader <- cache.seed(t.Context(), database, transport, now, foundation.Hash{2}, info.Hash()) }()
		<-entered
		go func() { waiter <- cache.seed(t.Context(), database, transport, now, foundation.Hash{2}, info.Hash()) }()
		synctest.Wait()
		cache.close()
		cache.close()
		if err := <-waiter; !errors.Is(err, net.ErrClosed) {
			t.Errorf("released waiter error = %v", err)
		}
		if len(cache.seeds) != 0 || len(cache.payloads) != 0 {
			t.Error("close retained cached session handles or payloads")
		}
		if err := cache.seed(t.Context(), database, transport, now, foundation.Hash{3}, info.Hash()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("seed after close error = %v", err)
		}
		close(release)
		if err := <-leader; err != nil {
			t.Errorf("draining active send: %v", err)
		}
		if len(cache.seeds) != 0 || len(cache.payloads) != 0 {
			t.Error("active send repopulated the released cache")
		}
		if calls := session.calls.Load(); calls != 2 {
			t.Errorf("close allowed new sends: calls = %d", calls)
		}
	})
}

func TestReplyRouterInfoSeederReleaseRejectsFurtherCalls(t *testing.T) {
	info := seedTestRouterInfo(t, 1_000_000)
	database := seedTestDatabase(t, info)
	session := &seedTestSession{}
	seed, release := buildReplyRouterInfoSeeder(database, &seedTestTransport{session: session}, func() uint64 { return info.Published })
	release()
	if err := seed(t.Context(), foundation.Hash{1}, info.Hash()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("released seeder error = %v", err)
	}
	if calls := session.calls.Load(); calls != 0 {
		t.Fatalf("released seeder sent %d messages", calls)
	}
}
