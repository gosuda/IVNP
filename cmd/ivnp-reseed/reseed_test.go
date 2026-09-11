package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
)

func createTestRouterInfo(t *testing.T, caps string) (foundation.NetworkDatabaseRouterInfo, []byte) {
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

	options := make([]byte, 64)
	entries := []foundation.MappingEntry{
		{Key: []byte("caps"), Value: []byte(caps)},
		{Key: []byte("netId"), Value: []byte("2")},
	}
	optionLen, err := foundation.MarshalMappingTo(options, entries)
	if err != nil {
		t.Fatal(err)
	}

	// unsigned: identity + 8 bytes date + 1 byte addressCount + 1 byte peerCount + options
	unsigned := append(identity, make([]byte, 10)...)
	unsigned = append(unsigned, options[:optionLen]...)
	wire := append(unsigned, ed25519.Sign(private, unsigned)...)

	info, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	return info, wire
}

func TestPeerStoreAndScoring(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "f")

	rec, isNew := store.AddOrUpdate(info, raw)
	if !isNew {
		t.Fatal("expected isNew = true")
	}
	if !rec.IsFloodfill {
		t.Fatal("expected IsFloodfill = true")
	}

	// Probe success with 50ms
	store.RecordProbeResult(info.Hash(), true, 50*time.Millisecond)
	snapshot := store.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(snapshot))
	}
	if !snapshot[0].Stats.IsReachable {
		t.Fatal("expected peer to be reachable")
	}
	if snapshot[0].Stats.EWMARTT != 50*time.Millisecond {
		t.Fatalf("EWMARTT = %v, want 50ms", snapshot[0].Stats.EWMARTT)
	}
	if snapshot[0].Score <= 0 {
		t.Fatalf("expected positive score, got %v", snapshot[0].Score)
	}

	// Test file persistence
	tmpFile := filepath.Join(t.TempDir(), "peers.json")
	if err := store.SaveToFile(tmpFile); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	store2 := NewPeerStore()
	if err := store2.LoadFromFile(tmpFile); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if store2.Len() != 1 {
		t.Fatalf("loaded store length = %d, want 1", store2.Len())
	}
}

func TestProberWithRateLimiter(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "LR")
	rec, _ := store.AddOrUpdate(info, raw)
	rec.IPv4 = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	rec.Ports = []uint16{8080}

	prober := NewProber(store, 4)
	mockDialerCalled := false
	prober.SetDialer(func(ctx context.Context, network, address string) (time.Duration, error) {
		mockDialerCalled = true
		return 35 * time.Millisecond, nil
	})

	success := prober.ProbeAll(context.Background())
	if success != 1 {
		t.Fatalf("successful probes = %d, want 1", success)
	}
	if !mockDialerCalled {
		t.Fatal("expected mock dialer to be called")
	}

	snap := store.Snapshot()
	if !snap[0].Stats.IsReachable {
		t.Fatal("expected peer to be marked reachable")
	}
	if snap[0].Stats.EWMARTT != 35*time.Millisecond {
		t.Fatalf("EWMARTT = %v, want 35ms", snap[0].Stats.EWMARTT)
	}
}

func TestSelectorFloodfillPriority(t *testing.T) {
	var peers []PeerRecord
	for i := 0; i < 20; i++ {
		var hash foundation.Hash
		hash[0] = byte(i % 5)
		hash[1] = byte(i)
		isFlood := i%3 == 0 // 1/3 are floodfills
		peers = append(peers, PeerRecord{
			Hash:        hash,
			Raw:         []byte("mock-raw"),
			IsFloodfill: isFlood,
			IPv4:        []netip.Addr{netip.MustParseAddr(fmt.Sprintf("192.168.%d.%d", i%3, i))},
			Stats: PeerStats{
				IsReachable: true,
				EWMARTT:     time.Duration(10+i) * time.Millisecond,
			},
			Score: float64(100 - i),
		})
	}

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 6
	cfg.MaxPerIPv4Subnet24 = 2
	cfg.PreferFloodfillRatio = 0.5 // request 50% floodfills
	selected := SelectDiversePeers(peers, cfg)

	if len(selected) != 6 {
		t.Fatalf("selected = %d, want 6", len(selected))
	}

	floodCount := 0
	for _, p := range selected {
		if p.IsFloodfill {
			floodCount++
		}
	}
	if floodCount == 0 {
		t.Fatal("expected floodfills to be prioritized in selected slots")
	}
}

func TestActiveCrawlerHarvestRefs(t *testing.T) {
	store := NewPeerStore()
	crawler := NewActiveCrawler(store)

	info1, _ := createTestRouterInfo(t, "f")
	info2, _ := createTestRouterInfo(t, "LR")

	refs := []controlplane.NetworkDatabaseRouterRef{
		{Hash: info1.Hash(), Info: info1, Floodfill: true},
		{Hash: info2.Hash(), Info: info2, Floodfill: false},
	}

	admitted := crawler.HarvestRefs(refs)
	if admitted != 2 {
		t.Fatalf("admitted = %d, want 2", admitted)
	}
	if store.Len() != 2 {
		t.Fatalf("store.Len = %d, want 2", store.Len())
	}
}

func TestPackagerSU3AndVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	info, raw := createTestRouterInfo(t, "f")
	peers := []PeerRecord{
		{
			Hash: info.Hash(),
			Raw:  raw,
		},
	}

	signerID := "test-signer@ivnp.network"
	su3Bytes, err := BuildSU3(peers, signerID, rsaKey, time.Now())
	if err != nil {
		t.Fatalf("BuildSU3: %v", err)
	}

	signers := map[string]controlplane.ReseedSU3Signer{
		signerID: {
			SigningType: foundation.SigningRSASHA512_4096,
			PublicKey:   rsaKey.N.FillBytes(make([]byte, 512)),
		},
	}

	extracted, err := controlplane.ReseedVerifySU3(su3Bytes, signers, int64(len(su3Bytes)))
	if err != nil {
		t.Fatalf("controlplane.ReseedVerifySU3 failed: %v", err)
	}
	if len(extracted) == 0 {
		t.Fatal("extracted empty ZIP payload from SU3")
	}
}

func TestPackagerIVBSAndParse(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	info1, raw1 := createTestRouterInfo(t, "f")
	info2, raw2 := createTestRouterInfo(t, "L")
	peers := []PeerRecord{
		{Hash: info1.Hash(), Raw: raw1},
		{Hash: info2.Hash(), Raw: raw2},
	}

	now := time.Now()
	ivbsBytes, err := BuildIVBS(peers, 2, privKey, now)
	if err != nil {
		t.Fatalf("BuildIVBS: %v", err)
	}

	parsed, err := ParseIVBS(ivbsBytes, pubKey)
	if err != nil {
		t.Fatalf("ParseIVBS: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("parsed %d RouterInfos, want 2", len(parsed))
	}
	if parsed[0].Hash() != info1.Hash() {
		t.Fatalf("parsed[0] hash mismatch")
	}
	if parsed[1].Hash() != info2.Hash() {
		t.Fatalf("parsed[1] hash mismatch")
	}

	tampered := bytes.Clone(ivbsBytes)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := ParseIVBS(tampered, pubKey); err == nil {
		t.Fatal("expected signature verification failure on tampered data")
	}
}

func TestReseedServer(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "f")
	store.AddOrUpdate(info, raw)

	server := NewReseedServer(ServerConfig{
		NetworkID:     2,
		ListenAddress: ":8443",
		CacheDuration: time.Minute,
	}, store)

	server.UpdatePackage(ReseedPackage{
		GeneratedAt: time.Now(),
		PeerCount:   1,
		SU3Data:     []byte("mock-su3-archive"),
		IVBSData:    []byte("mock-ivbs-archive"),
		ETag:        `"mock-etag"`,
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/health code = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/i2pseeds.su3?netid=2", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/i2pseeds.su3 code = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/ivnpseeds.bin?netid=2", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/ivnpseeds.bin code = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/stats code = %d, want 200", rec.Code)
	}

	var stats DetailedStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode /stats JSON: %v", err)
	}
	if stats.NetworkID != 2 {
		t.Fatalf("stats.NetworkID = %d, want 2", stats.NetworkID)
	}
	if stats.KBuckets.TotalBuckets != 256 {
		t.Fatalf("stats.KBuckets.TotalBuckets = %d, want 256", stats.KBuckets.TotalBuckets)
	}
	if stats.KBuckets.CoveredBuckets < 1 {
		t.Fatalf("stats.KBuckets.CoveredBuckets = %d, want >= 1", stats.KBuckets.CoveredBuckets)
	}
	if stats.Package.PeerCount != 1 {
		t.Fatalf("stats.Package.PeerCount = %d, want 1", stats.Package.PeerCount)
	}
	if stats.Package.SU3SizeBytes != len("mock-su3-archive") {
		t.Fatalf("stats.Package.SU3SizeBytes = %d, want %d", stats.Package.SU3SizeBytes, len("mock-su3-archive"))
	}

	// Test Web Dashboard root endpoint
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("GET / Content-Type = %q, want 'text/html; charset=utf-8'", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("IVNP Reseed Indexer")) {
		t.Fatal("GET / dashboard does not contain expected title")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("initial-data")) {
		t.Fatal("GET / dashboard does not contain bootstrap initial-data")
	}

	// Test 404 for unknown path
	req = httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /unknown/path code = %d, want 404", rec.Code)
	}
}

func TestHealthCheckFlag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{"-healthcheck", ts.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected healthcheck code 0, got %d", code)
	}

	codeFail := run([]string{"-healthcheck", "http://127.0.0.1:0/unreachable"}, &stdout, &stderr)
	if codeFail != 1 {
		t.Fatalf("expected healthcheck failure code 1, got %d", codeFail)
	}
}
