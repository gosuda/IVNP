package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func writePeerCacheFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signedCachedPeer(t *testing.T, seed byte, published time.Time) PeerRecord {
	t.Helper()
	info, wire := createTestRouterInfoWithEndpoint(
		t, bytes.Repeat([]byte{seed}, 64), "f", "198.51.100.9", "12345", "verified",
		uint64(published.UnixMilli()),
	)
	return PeerRecord{Hash: info.Hash(), Raw: wire}
}

func writeCachedRecords(t *testing.T, records []PeerRecord) string {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return writePeerCacheFixture(t, data)
}

func TestPeerStoreLoadRevalidatesSignedDataAndDiscardsProbeClaims(t *testing.T) {
	cached := signedCachedPeer(t, 1, time.Now())
	cached.PublishedAt = time.Now().Add(-100 * time.Hour)
	cached.Family = "forged"
	cached.IPv4 = []netip.Addr{netip.MustParseAddr("203.0.113.8")}
	cached.IsFloodfill = false
	cached.HasNTCP2 = false
	cached.HasSSU2 = true
	cached.Score = 1e9
	cached.Stats = PeerStats{
		TotalProbes:         100,
		SuccessProbes:       100,
		WinProbes:           100,
		WinSuccess:          100,
		FirstSeen:           time.Now().Add(-48 * time.Hour),
		LastSeen:            time.Now(),
		IsReachable:         true,
		TunnelBuildAccepted: true,
		EWMARTT:             time.Millisecond,
	}

	store := NewPeerStore()
	if err := store.LoadFromFile(writeCachedRecords(t, []PeerRecord{cached}), 2); err != nil {
		t.Fatal(err)
	}
	peers := store.Snapshot()
	if len(peers) != 1 {
		t.Fatalf("restored peer count = %d, want 1", len(peers))
	}
	got := peers[0]
	if got.Hash != cached.Hash || !bytes.Equal(got.Raw, cached.Raw) {
		t.Fatal("restored signed RouterInfo differs from the verified wire bytes")
	}
	if got.Family != "verified" || len(got.IPv4) != 1 || got.IPv4[0] != netip.MustParseAddr("198.51.100.9") {
		t.Fatalf("restored address/family was not derived from RouterInfo: %+v", got)
	}
	if !got.IsFloodfill || !got.HasNTCP2 || got.HasSSU2 || len(got.TCPPorts) != 1 || got.TCPPorts[0] != 12345 {
		t.Fatalf("restored transport/capabilities were not derived from RouterInfo: %+v", got)
	}
	if got.PublishedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("restored publication timestamp = %s, want recent", got.PublishedAt)
	}
	if got.Stats.IsReachable || got.Stats.TotalProbes != 0 || got.Stats.WinProbes != 0 ||
		got.Stats.TunnelBuildAccepted || got.Stats.EWMARTT != 0 || !got.Stats.LastSeen.IsZero() {
		t.Fatalf("untrusted cached probe state restored: %+v", got.Stats)
	}
	if got.Stats.FirstSeen.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("cached uptime was trusted: firstSeen=%s", got.Stats.FirstSeen)
	}
	if diff := got.Score - calculateScore(&got); diff < -0.01 || diff > 0.01 {
		t.Fatalf("cached score was trusted: score=%f delta=%f", got.Score, diff)
	}
	if len(SelectDiversePeers(peers, DefaultSelectorConfig())) != 0 {
		t.Fatal("unprobed cache records must never enter a signed bootstrap package")
	}
	store.RecordProbeResult(got.Hash, true, 50*time.Millisecond)
	if selected := SelectDiversePeers(store.Snapshot(), DefaultSelectorConfig()); len(selected) != 1 {
		t.Fatalf("freshly probed peer selection = %d, want 1", len(selected))
	}
}

func TestPeerStoreLoadRejectsInvalidRouterInfos(t *testing.T) {
	fresh := signedCachedPeer(t, 2, time.Now())
	tampered := fresh
	tampered.Raw = bytes.Clone(fresh.Raw)
	tampered.Raw[len(tampered.Raw)-1] ^= 1

	mismatched := fresh
	mismatched.Hash[0] ^= 1

	oversized := fresh
	oversized.Raw = make([]byte, foundation.NetworkDatabaseMaxRouterInfoBytes+1)

	cases := []struct {
		name      string
		record    PeerRecord
		networkID uint32
	}{
		{name: "bad signature", record: tampered, networkID: 2},
		{name: "hash mismatch", record: mismatched, networkID: 2},
		{name: "wrong network", record: fresh, networkID: 3},
		{name: "stale", record: signedCachedPeer(t, 3, time.Now().Add(-25 * time.Hour)), networkID: 2},
		{name: "future", record: signedCachedPeer(t, 4, time.Now().Add(3 * time.Minute)), networkID: 2},
		{name: "oversized RouterInfo", record: oversized, networkID: 2},
		{name: "empty RouterInfo", record: PeerRecord{Hash: fresh.Hash}, networkID: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewPeerStore()
			if err := store.LoadFromFile(writeCachedRecords(t, []PeerRecord{tc.record}), tc.networkID); err != nil {
				t.Fatal(err)
			}
			if got := store.Len(); got != 0 {
				t.Fatalf("invalid RouterInfo restored %d peers, want 0", got)
			}
		})
	}
}

func TestPeerStoreLoadEnforcesRecordLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		wantErr bool
	}{
		{name: "at limit", count: MaxStorePeers},
		{name: "above limit", count: MaxStorePeers + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("[" + strings.TrimSuffix(strings.Repeat("null,", tc.count), ",") + "]")
			store := NewPeerStore()
			err := store.LoadFromFile(writePeerCacheFixture(t, data), 2)
			if tc.wantErr && !errors.Is(err, errPeerCacheTooManyRecords) {
				t.Fatalf("LoadFromFile = %v, want too many records", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("LoadFromFile at limit = %v", err)
			}
			if got := store.Len(); got != 0 {
				t.Fatalf("unverified peers admitted = %d", got)
			}
		})
	}
}

func TestPeerStoreLoadRejectsOversizedCacheFile(t *testing.T) {
	path := writePeerCacheFixture(t, []byte("[]"))
	if err := os.Truncate(path, int64(maxPeerCacheBytes+1)); err != nil {
		t.Fatal(err)
	}
	store := NewPeerStore()
	if err := store.LoadFromFile(path, 2); err == nil {
		t.Fatal("oversized cache file was accepted")
	}
	if store.Len() != 0 {
		t.Fatal("oversized file changed the store")
	}
}

func TestPeerStoreLoadRejectsUnsafeCacheFile(t *testing.T) {
	target := writePeerCacheFixture(t, []byte("[]"))
	link := filepath.Join(t.TempDir(), "symlink.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := NewPeerStore().LoadFromFile(link, 2); err == nil {
		t.Fatal("symlink cache was accepted")
	}
}

func TestPeerStoreLoadDoesNotPartiallyApplyMalformedJSON(t *testing.T) {
	cached := signedCachedPeer(t, 5, time.Now())
	records, err := json.Marshal([]PeerRecord{cached})
	if err != nil {
		t.Fatal(err)
	}
	malformed := append(bytes.Clone(records[:len(records)-1]), ',', ']')
	store := NewPeerStore()
	if err := store.LoadFromFile(writePeerCacheFixture(t, malformed), 2); err == nil {
		t.Fatal("malformed cache was accepted")
	}
	if store.Len() != 0 {
		t.Fatal("malformed cache was partially restored")
	}
	if err := store.LoadFromFile(writePeerCacheFixture(t, []byte("[]{}")), 2); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestPeerStoreLoadSkipsLocalIdentity(t *testing.T) {
	cached := signedCachedPeer(t, 6, time.Now())
	store := NewPeerStore()
	store.SetLocalHash(cached.Hash)
	if err := store.LoadFromFile(writeCachedRecords(t, []PeerRecord{cached}), 2); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 0 {
		t.Fatal("local router was restored as a remote peer")
	}
}
