package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

func writeTestPeerCache(t *testing.T, entries []PeerRecord) string {
	t.Helper()
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := state.FilesystemStoreWriteAtomic(path, data, 0o600, int(maxPeerCacheBytes)); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCacheRouterInfo(t *testing.T, published uint64) (foundation.NetworkDatabaseRouterInfo, []byte) {
	t.Helper()
	return createTestRouterInfoWithEndpoint(t, bytes.Repeat([]byte{0x31}, 64), "f", "198.51.100.42", "23456", "valid-family", published)
}

func TestPeerCacheLoadRebuildsMetadataAndRequiresProbe(t *testing.T) {
	info, raw := testCacheRouterInfo(t, uint64(time.Now().UnixMilli()))
	poisoned := PeerRecord{
		Hash:        foundation.Hash{1},
		Raw:         raw,
		PublishedAt: time.Now().Add(365 * 24 * time.Hour),
		IsFloodfill: false,
		Family:      "attacker-family",
		IPv4:        []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		HasNTCP2:    false,
		HasSSU2:     true,
		Score:       1000000,
		Stats: PeerStats{
			FirstSeen:           time.Now().Add(-365 * 24 * time.Hour),
			LastSeen:            time.Now(),
			IsReachable:         true,
			TunnelBuildAccepted: true,
			TotalProbes:         100,
			SuccessProbes:       100,
			EWMARTT:             time.Millisecond,
		},
	}
	store := NewPeerStore()
	if err := store.LoadFromFile(writeTestPeerCache(t, []PeerRecord{poisoned}), 2); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	records := store.Snapshot()
	if len(records) != 1 {
		t.Fatalf("loaded %d peers, want 1", len(records))
	}
	got := records[0]
	if got.Hash != info.Hash() || !bytes.Equal(got.Raw, raw) || got.Family != "valid-family" ||
		!got.IsFloodfill || !got.HasNTCP2 || got.HasSSU2 ||
		len(got.IPv4) != 1 || got.IPv4[0] != netip.MustParseAddr("198.51.100.42") ||
		!got.PublishedAt.Equal(time.UnixMilli(int64(info.Published))) {
		t.Fatalf("restored untrusted metadata: %+v", got)
	}
	if got.Stats.IsReachable || got.Stats.TunnelBuildAccepted || got.Stats.TotalProbes != 0 ||
		!got.Stats.LastSeen.IsZero() || got.Stats.FirstSeen.IsZero() ||
		math.Abs(got.Score-calculateScore(&got)) > 0.1 {
		t.Fatalf("restored untrusted observations or score: %+v", got)
	}
	if selected := SelectDiversePeers(store.Snapshot(), DefaultSelectorConfig()); len(selected) != 0 {
		t.Fatalf("selected %d cache-only peers before probing", len(selected))
	}

	prober := NewProber(store, 1)
	prober.SetDialer(func(context.Context, string, string) (time.Duration, error) {
		return 40 * time.Millisecond, nil
	})
	if ok, _ := prober.ProbeSingle(context.Background(), info.Hash()); !ok {
		t.Fatal("expected real probe success")
	}
	if selected := SelectDiversePeers(store.Snapshot(), DefaultSelectorConfig()); len(selected) != 1 {
		t.Fatalf("selected %d peers after probing, want 1", len(selected))
	}
}

func TestPeerCacheLoadRejectsUntrustedRecordsAtomically(t *testing.T) {
	now := time.Now()
	_, validRaw := testCacheRouterInfo(t, uint64(now.UnixMilli()))
	damaged := bytes.Clone(validRaw)
	damaged[len(damaged)-1] ^= 0x01
	tooLarge := make([]byte, foundation.NetworkDatabaseMaxRouterInfoBytes+1)

	tests := []struct {
		name      string
		raw       []byte
		networkID uint32
	}{
		{name: "invalid signature", raw: damaged, networkID: 2},
		{name: "malformed RouterInfo", raw: []byte("bad"), networkID: 2},
		{name: "oversized RouterInfo", raw: tooLarge, networkID: 2},
		{name: "foreign network", raw: validRaw, networkID: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewPeerStore()
			cached := []PeerRecord{{Raw: validRaw}, {Raw: tt.raw}}
			err := store.LoadFromFile(writeTestPeerCache(t, cached), tt.networkID)
			if !errors.Is(err, errInvalidPeerCache) {
				t.Fatalf("LoadFromFile error = %v, want invalid cache", err)
			}
			if store.Len() != 0 {
				t.Fatalf("restored %d peers from invalid cache", store.Len())
			}
		})
	}
	for _, tt := range []struct {
		name      string
		published uint64
	}{
		{name: "stale", published: uint64(now.Add(-25 * time.Hour).UnixMilli())},
		{name: "future", published: uint64(now.Add(3 * time.Minute).UnixMilli())},
		{name: "zero", published: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, raw := testCacheRouterInfo(t, tt.published)
			store := NewPeerStore()
			if err := store.LoadFromFile(writeTestPeerCache(t, []PeerRecord{{Raw: raw}}), 2); !errors.Is(err, errInvalidPeerCache) {
				t.Fatalf("LoadFromFile error = %v, want stale/future rejection", err)
			}
			if store.Len() != 0 {
				t.Fatalf("loaded %d stale/future peers", store.Len())
			}
		})
	}
}

func TestPeerCacheLoadCountAndSizeBounds(t *testing.T) {
	_, raw := testCacheRouterInfo(t, uint64(time.Now().UnixMilli()))
	path := writeTestPeerCache(t, []PeerRecord{{Raw: raw}, {Raw: raw}})
	store := NewPeerStore()
	store.maxPeers = 2
	if err := store.LoadFromFile(path, 2); err != nil {
		t.Fatalf("exactly at record limit: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("deduplicated count = %d, want 1", store.Len())
	}

	path = writeTestPeerCache(t, []PeerRecord{{Raw: raw}, {Raw: raw}, {Raw: raw}})
	store = NewPeerStore()
	store.maxPeers = 2
	if err := store.LoadFromFile(path, 2); !errors.Is(err, errPeerCacheOverflow) {
		t.Fatalf("over record limit error = %v, want overflow", err)
	}
	if store.Len() != 0 {
		t.Fatalf("restored %d peers from oversized record set", store.Len())
	}

	path = filepath.Join(t.TempDir(), "oversized.json")
	if err := state.FilesystemStoreWriteAtomic(path, []byte("[]"), 0o600, int(maxPeerCacheBytes)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPeerCacheBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	store = NewPeerStore()
	if err := store.LoadFromFile(path, 2); !errors.Is(err, state.FilesystemStoreErrTooLarge) {
		t.Fatalf("oversized file error = %v, want size rejection", err)
	}
	if store.Len() != 0 {
		t.Fatalf("restored %d peers from oversized file", store.Len())
	}
}

func TestPeerCacheSavePersistsOnlyWireData(t *testing.T) {
	info, raw := testCacheRouterInfo(t, uint64(time.Now().UnixMilli()))
	store := NewPeerStore()
	rec, _ := store.AddOrUpdate(info, raw)
	rec.Stats.IsReachable = true
	rec.Score = 12345
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := store.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(data, &objects); err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || len(objects[0]) != 1 || len(objects[0]["raw"]) == 0 {
		t.Fatalf("cache saved derived fields: %s", data)
	}
}
