package netdb

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func signedResponderRouter(t *testing.T, seed byte, published uint64, floodfill bool) foundation.NetworkDatabaseRouterInfo {
	t.Helper()
	var keySeed [ed25519.SeedSize]byte
	keySeed[0] = seed
	private := ed25519.NewKeyFromSeed(keySeed[:])
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], private.Public().(ed25519.PublicKey))
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	caps := "R"
	if floodfill {
		caps = "Rf"
	}
	options := make([]byte, 32)
	n, err := foundation.MarshalMappingTo(options, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte(caps)}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):], published)
	unsigned = append(unsigned, options[:n]...)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func responderTestStore(t *testing.T, path string, database *Database, profiles *ResponderProfiles, now func() uint64) *ResponderProfileStore {
	t.Helper()
	store, err := NewResponderProfileStore(ResponderProfileStoreConfig{Path: path, Database: database, Profiles: profiles, NetworkID: 2, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestResponderStoreRestoresSuccessButNotStaticSeeds(t *testing.T) {
	now := uint64(1_000_000)
	clock := func() uint64 { return now }
	database := NewDatabase(requestTestHash(99), DefaultBucketCapacity)
	first := signedResponderRouter(t, 1, now, true)
	second := signedResponderRouter(t, 2, now, true)
	for _, info := range []foundation.NetworkDatabaseRouterInfo{first, second} {
		if err := database.AdmitRouterInfo(info, false, now); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "netdb.responders")
	profiles := NewResponderProfiles(ResponderProfilesConfig{Now: clock})
	profiles.Record(first.Hash())
	profiles.Seed(second.Hash())
	writer := responderTestStore(t, path, database, profiles, clock)
	if err := writer.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions = %o, want 0600", before.Mode().Perm())
	}
	if err := writer.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("unchanged snapshot was replaced")
	}
	restored := NewResponderProfiles(ResponderProfilesConfig{Now: clock})
	reader := responderTestStore(t, path, database, restored, clock)
	if err := reader.Load(); err != nil {
		t.Fatal(err)
	}
	if !restored.Responsive(first.Hash()) || restored.Responsive(second.Hash()) {
		t.Fatal("restored history did not distinguish observed success from static configuration")
	}
	candidates := restored.Candidates(make([]foundation.Hash, 0, 2), database)
	if len(candidates) != 1 || candidates[0] != first.Hash() {
		t.Fatalf("restored candidates = %v, want only observed responder", candidates)
	}
	candidates[0] = second.Hash()
	if got := restored.Candidates(candidates[:0], database); len(got) != 1 || got[0] != first.Hash() {
		t.Fatal("caller mutation changed retained hints")
	}

	now += responderProfileMaxAgeMillis
	fresh := signedResponderRouter(t, 1, now, true)
	if err := database.AdmitRouterInfo(fresh, false, now); err != nil {
		t.Fatal(err)
	}
	if err := reader.Save(); err != nil {
		t.Fatal(err)
	}
	// Rewinding the clock distinguishes durable pruning from load-time filtering.
	now -= responderProfileMaxAgeMillis
	database = NewDatabase(requestTestHash(99), DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(first, false, now); err != nil {
		t.Fatal(err)
	}
	empty := NewResponderProfiles(ResponderProfilesConfig{Now: clock})
	if err := responderTestStore(t, path, database, empty, clock).Load(); err != nil {
		t.Fatal(err)
	}
	if empty.Responsive(first.Hash()) {
		t.Fatal("expired success remained in the snapshot")
	}
}

func TestResponderStoreRejectsForeignOrCorruptSnapshots(t *testing.T) {
	clock := func() uint64 { return 1_000_000 }
	database := NewDatabase(requestTestHash(99), DefaultBucketCapacity)
	info := signedResponderRouter(t, 1, clock(), true)
	if err := database.AdmitRouterInfo(info, false, clock()); err != nil {
		t.Fatal(err)
	}
	profiles := NewResponderProfiles(ResponderProfilesConfig{MaxPeers: 2, Now: clock})
	profiles.Record(info.Hash())
	path := filepath.Join(t.TempDir(), "netdb.responders")
	if err := responderTestStore(t, path, database, profiles, clock).Save(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"network", func(data []byte) []byte { data[13] ^= 1; return data }},
		{"identity", func(data []byte) []byte { data[14] ^= 1; return data }},
		{"checksum", func(data []byte) []byte { data[len(data)-1] ^= 1; return data }},
		{"truncated", func(data []byte) []byte { return data[:len(data)-1] }},
		{"trailing", func(data []byte) []byte { return append(data, 0) }},
		{"count", func(data []byte) []byte { binary.BigEndian.PutUint32(data[46:50], 3); return data }},
		{"duplicate", func(data []byte) []byte {
			payload := append(data[:len(data)-sha256.Size], data[responderSnapshotHeader:len(data)-sha256.Size]...)
			binary.BigEndian.PutUint32(payload[46:50], 2)
			digest := sha256.Sum256(payload)
			return append(payload, digest[:]...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(append([]byte(nil), original...))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			restored := NewResponderProfiles(ResponderProfilesConfig{MaxPeers: 2, Now: clock})
			if err := responderTestStore(t, path, database, restored, clock).Load(); !errors.Is(err, ErrResponderSnapshot) {
				t.Fatalf("Load() = %v, want rejected snapshot", err)
			}
			if restored.Responsive(info.Hash()) {
				t.Fatal("rejected snapshot changed responder history")
			}
		})
	}
}

func TestResponderStoreFiltersUnusableHistory(t *testing.T) {
	const observed = uint64(100_000_000)
	for _, scenario := range []string{"expired", "future", "unknown", "non_floodfill", "stale_router"} {
		t.Run(scenario, func(t *testing.T) {
			now := observed
			clock := func() uint64 { return now }
			database := NewDatabase(requestTestHash(99), DefaultBucketCapacity)
			info := signedResponderRouter(t, 1, observed, true)
			if err := database.AdmitRouterInfo(info, false, now); err != nil {
				t.Fatal(err)
			}
			profiles := NewResponderProfiles(ResponderProfilesConfig{Now: clock})
			profiles.Record(info.Hash())
			path := filepath.Join(t.TempDir(), "netdb.responders")
			if err := responderTestStore(t, path, database, profiles, clock).Save(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expired", "future":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				seenAt := observed + 1
				if scenario == "expired" {
					seenAt = observed - responderProfileMaxAgeMillis
				}
				binary.BigEndian.PutUint64(data[responderSnapshotHeader+foundation.HashLength:], seenAt)
				digest := sha256.Sum256(data[:len(data)-sha256.Size])
				copy(data[len(data)-sha256.Size:], digest[:])
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				database.Routers().Remove(info.Hash())
			case "non_floodfill":
				if err := database.AdmitRouterInfo(signedResponderRouter(t, 1, observed+1, false), false, observed); err != nil {
					t.Fatal(err)
				}
			case "stale_router":
				now += RouterInfoMaxAgeMillis + 1
			}
			restored := NewResponderProfiles(ResponderProfilesConfig{Now: clock})
			if err := responderTestStore(t, path, database, restored, clock).Load(); err != nil {
				t.Fatal(err)
			}
			if restored.Responsive(info.Hash()) {
				t.Fatal("unusable history gained observed-success status")
			}
		})
	}
}

func TestResponderCandidatesRotateAndRecheckEligibility(t *testing.T) {
	now := uint64(100_000_000)
	clock := func() uint64 { return now }
	database := NewDatabase(requestTestHash(99), DefaultBucketCapacity)
	profiles := NewResponderProfiles(ResponderProfilesConfig{MaxPeers: 2, Now: clock})
	first := signedResponderRouter(t, 1, now, true)
	second := signedResponderRouter(t, 2, now, true)
	for _, info := range []foundation.NetworkDatabaseRouterInfo{first, second} {
		if err := database.AdmitRouterInfo(info, false, now); err != nil {
			t.Fatal(err)
		}
		profiles.Record(info.Hash())
	}
	var buffer [1]foundation.Hash
	seen := make(map[foundation.Hash]bool)
	for range 2 {
		candidates := profiles.Candidates(buffer[:0], database)
		if len(candidates) != 1 {
			t.Fatalf("candidates = %v, want one eligible responder", candidates)
		}
		seen[candidates[0]] = true
	}
	if !seen[first.Hash()] || !seen[second.Hash()] {
		t.Fatal("selection remained pinned to one responder")
	}
	database.Routers().Remove(second.Hash())
	if got := profiles.Candidates(buffer[:0], database); len(got) != 1 || got[0] != first.Hash() {
		t.Fatalf("candidates after router removal = %v", got)
	}
	now += RouterInfoMaxAgeMillis + 1
	if got := profiles.Candidates(buffer[:0], database); len(got) != 0 {
		t.Fatalf("stale RouterInfo still eligible: %v", got)
	}
	profiles.Seed(first.Hash())
	now += responderProfileMaxAgeMillis
	if err := database.AdmitRouterInfo(signedResponderRouter(t, 1, now, true), false, now); err != nil {
		t.Fatal(err)
	}
	if profiles.Responsive(first.Hash()) {
		t.Fatal("static seed refreshed an expired success timestamp")
	}
	if got := profiles.Candidates(buffer[:0], database); len(got) != 1 || got[0] != first.Hash() {
		t.Fatal("static seed was lost when its observed success expired")
	}
}
