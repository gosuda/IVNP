package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
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

func TestProductionScoringRules(t *testing.T) {
	now := time.Now()

	// 1. Test Laplace smoothing: 1/1 probe vs 99/100 probes
	singleProbe := &PeerRecord{
		PublishedAt: now,
		Stats: PeerStats{
			TotalProbes:   1,
			SuccessProbes: 1,
		},
	}
	establishedProbe := &PeerRecord{
		PublishedAt: now,
		Stats: PeerStats{
			TotalProbes:   100,
			SuccessProbes: 99,
		},
	}
	scoreSingle := calculateScore(singleProbe)
	scoreEstablished := calculateScore(establishedProbe)
	if scoreSingle >= scoreEstablished {
		t.Fatalf("expected established reliable peer (score %v) to beat single-probe newcomer (score %v)",
			scoreEstablished, scoreSingle)
	}

	// 2. Test Non-linear RTT decay beyond 300ms
	peer350ms := &PeerRecord{
		PublishedAt: now,
		Stats: PeerStats{
			IsReachable: true,
			EWMARTT:     350 * time.Millisecond,
		},
	}
	peer1500ms := &PeerRecord{
		PublishedAt: now,
		Stats: PeerStats{
			IsReachable: true,
			EWMARTT:     1500 * time.Millisecond,
		},
	}
	score350 := calculateScore(peer350ms)
	score1500 := calculateScore(peer1500ms)
	if score350 <= score1500 {
		t.Fatalf("expected 350ms peer (score %v) to have higher score than 1500ms peer (score %v)",
			score350, score1500)
	}

	// 3. Test RouterInfo Recency bonus
	freshPeer := &PeerRecord{
		PublishedAt: now.Add(-1 * time.Hour),
	}
	stalePeer := &PeerRecord{
		PublishedAt: now.Add(-22 * time.Hour),
	}
	if calculateScore(freshPeer) <= calculateScore(stalePeer) {
		t.Fatalf("expected fresh peer to score higher than stale peer")
	}

	// 4. Test Dual-stack IPv4 + IPv6 bonus
	v4Peer := &PeerRecord{
		PublishedAt: now,
		IPv4:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	dualPeer := &PeerRecord{
		PublishedAt: now,
		IPv4:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		IPv6:        []netip.Addr{netip.MustParseAddr("2001:db8::1")},
	}
	if calculateScore(dualPeer)-calculateScore(v4Peer) < 4.9 {
		t.Fatalf("expected dual-stack peer to receive +5 bonus")
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
	cfg.MaxPerIPv4Subnet16 = 2
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

func TestSelectorBucketLevelingAndCap(t *testing.T) {
	// 15 peers in bucket 0, 15 in bucket 1, 1 in bucket 2
	var peers []PeerRecord
	for i := 0; i < 15; i++ {
		var h0 [32]byte
		h0[0] = 0
		h0[1] = byte(i)
		peers = append(peers, PeerRecord{
			Hash:  h0,
			Raw:   []byte("raw"),
			IPv4:  []netip.Addr{netip.MustParseAddr(fmt.Sprintf("%d.%d.1.1", 10+i, i))},
			Stats: PeerStats{IsReachable: true},
			Score: float64(100 - i),
		})

		var h1 [32]byte
		h1[0] = 1
		h1[1] = byte(i)
		peers = append(peers, PeerRecord{
			Hash:  h1,
			Raw:   []byte("raw"),
			IPv4:  []netip.Addr{netip.MustParseAddr(fmt.Sprintf("%d.%d.2.2", 40+i, i))},
			Stats: PeerStats{IsReachable: true},
			Score: float64(100 - i),
		})
	}
	var h2 [32]byte
	h2[0] = 2
	peers = append(peers, PeerRecord{
		Hash:  h2,
		Raw:   []byte("raw"),
		IPv4:  []netip.Addr{netip.MustParseAddr("80.1.3.3")},
		Stats: PeerStats{IsReachable: true},
		Score: 90,
	})

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 50 // Request more than the 31 available peers
	selected := SelectDiversePeers(peers, cfg)

	counts := make(map[byte]int)
	for _, p := range selected {
		counts[p.Hash[0]]++
	}

	// Verify no single bucket gets 15 peers (capped at max 5)
	if counts[0] > 5 {
		t.Fatalf("bucket 0 count = %d, want <= 5", counts[0])
	}
	if counts[1] > 5 {
		t.Fatalf("bucket 1 count = %d, want <= 5", counts[1])
	}
	if counts[2] != 1 {
		t.Fatalf("bucket 2 count = %d, want 1", counts[2])
	}
}

func TestSelectorRequireReachable(t *testing.T) {
	var peers []PeerRecord
	for i := 0; i < 100; i++ {
		var h [32]byte
		h[0] = byte(i % 50)
		h[1] = byte(i)
		peers = append(peers, PeerRecord{
			Hash:  h,
			Raw:   []byte("raw"),
			IPv4:  []netip.Addr{netip.MustParseAddr(fmt.Sprintf("%d.%d.1.1", 10+i, i))},
			Stats: PeerStats{IsReachable: true},
		})
	}
	for i := 100; i < 200; i++ {
		var h [32]byte
		h[0] = byte(i % 50)
		h[1] = byte(i)
		peers = append(peers, PeerRecord{
			Hash:  h,
			Raw:   []byte("raw"),
			IPv4:  []netip.Addr{netip.MustParseAddr(fmt.Sprintf("%d.%d.1.1", 10+i, i))},
			Stats: PeerStats{IsReachable: false}, // Unreachable
		})
	}

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 1024
	cfg.RequireReachable = true
	selected := SelectDiversePeers(peers, cfg)

	if len(selected) > 100 {
		t.Fatalf("selected = %d, want <= 100", len(selected))
	}
	for _, p := range selected {
		if !p.Stats.IsReachable {
			t.Fatal("selected unreachable peer when RequireReachable = true")
		}
	}
}

func TestSelectorIPv4Subnet16Filter(t *testing.T) {
	var peers []PeerRecord
	for i := 0; i < 5; i++ {
		var h [32]byte
		h[0] = byte(i)
		peers = append(peers, PeerRecord{
			Hash:  h,
			Raw:   []byte("raw"),
			IPv4:  []netip.Addr{netip.MustParseAddr(fmt.Sprintf("198.51.%d.%d", i+1, i+10))}, // Same /16: 198.51.0.0/16
			Stats: PeerStats{IsReachable: true},
			Score: float64(100 - i),
		})
	}

	// Add an outsider peer on another /16
	var hOther [32]byte
	hOther[0] = 5
	peers = append(peers, PeerRecord{
		Hash:  hOther,
		Raw:   []byte("raw"),
		IPv4:  []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		Stats: PeerStats{IsReachable: true},
		Score: 50,
	})

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 2
	cfg.MaxPerIPv4Subnet16 = 1
	selected := SelectDiversePeers(peers, cfg)

	if len(selected) != 2 {
		t.Fatalf("selected = %d, want 2", len(selected))
	}

	seen198 := 0
	for _, p := range selected {
		if IPv4Subnet16(p.IPv4[0]) == [2]byte{198, 51} {
			seen198++
		}
	}
	if seen198 != 1 {
		t.Fatalf("seen /16 subnet count = %d, want 1", seen198)
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

func TestTreeExplorationTargets(t *testing.T) {
	target0 := generatePrefixTarget(0x42, 0x00)
	if target0[0] != 0x42 {
		t.Fatalf("target0[0] = 0x%02x, want 0x42", target0[0])
	}
	if target0[1]&0x80 != 0 {
		t.Fatalf("target0[1] bit 7 = 1, want 0 for subBranch 0x00")
	}

	target1 := generatePrefixTarget(0x42, 0x80)
	if target1[0] != 0x42 {
		t.Fatalf("target1[0] = 0x%02x, want 0x42", target1[0])
	}
	if target1[1]&0x80 == 0 {
		t.Fatalf("target1[1] bit 7 = 0, want 1 for subBranch 0x80")
	}

	store := NewPeerStore()
	info1, raw1 := createTestRouterInfo(t, "f")
	store.AddOrUpdate(info1, raw1)

	dist := store.BucketDistribution()
	if dist[info1.Hash()[0]] != 1 {
		t.Fatalf("dist[%d] = %d, want 1", info1.Hash()[0], dist[info1.Hash()[0]])
	}
	if store.ReachableCount() != 1 {
		t.Fatalf("ReachableCount = %d, want 1", store.ReachableCount())
	}

	crawler := NewActiveCrawler(store)
	dispatched, err := crawler.TreeExplore(context.Background(), nil, 16)
	if err != nil {
		t.Fatalf("TreeExplore with nil subsystem error: %v", err)
	}
	if dispatched != 0 {
		t.Fatalf("TreeExplore with nil subsystem dispatched = %d, want 0", dispatched)
	}
}

func TestReseedServer(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "f")
	store.AddOrUpdate(info, raw)

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB...mock-cert\n-----END CERTIFICATE-----\n")
	pubKeyPEM := []byte("-----BEGIN PUBLIC KEY-----\nMIIB...mock-pubkey\n-----END PUBLIC KEY-----\n")
	signerID := "test-signer@ivnp.network"

	server := NewReseedServer(ServerConfig{
		NetworkID:     2,
		ListenAddress: ":8443",
		CacheDuration: time.Minute,
		SignerID:      signerID,
		CertPEM:       certPEM,
		PubKeyPEM:     pubKeyPEM,
	}, store)

	server.UpdatePackage(ReseedPackage{
		GeneratedAt: time.Now(),
		PeerCount:   1,
		SU3Data:     []byte("mock-su3-archive"),
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

	// Test certificate endpoints
	req = httptest.NewRequest(http.MethodGet, "/reseed-rsa.crt", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reseed-rsa.crt code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Fatalf("GET /reseed-rsa.crt Content-Type = %q, want 'application/x-x509-ca-cert'", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "test-signer_at_ivnp.network.crt") {
		t.Fatalf("GET /reseed-rsa.crt Content-Disposition = %q, want filename containing test-signer_at_ivnp.network.crt", cd)
	}
	if !bytes.Equal(rec.Body.Bytes(), certPEM) {
		t.Fatal("GET /reseed-rsa.crt body does not match expected certPEM")
	}

	// Test certificate alias /reseed.crt
	req = httptest.NewRequest(http.MethodGet, "/reseed.crt", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reseed.crt code = %d, want 200", rec.Code)
	}

	// Test public key endpoint /reseed-rsa.pub.pem
	req = httptest.NewRequest(http.MethodGet, "/reseed-rsa.pub.pem", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reseed-rsa.pub.pem code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("GET /reseed-rsa.pub.pem Content-Type = %q, want text/plain", ct)
	}
	if !bytes.Equal(rec.Body.Bytes(), pubKeyPEM) {
		t.Fatal("GET /reseed-rsa.pub.pem body does not match expected pubKeyPEM")
	}

	// Test public key alias /reseed.pub
	req = httptest.NewRequest(http.MethodGet, "/reseed.pub", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reseed.pub code = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/stats code = %d, want 200", rec.Code)
	}

	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("GET /stats Cache-Control = %q, want no-store", cc)
	}

	var stats DetailedStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode /stats JSON: %v", err)
	}
	if stats.NetworkID != 2 {
		t.Fatalf("stats.NetworkID = %d, want 2", stats.NetworkID)
	}
	if stats.SignerID != signerID {
		t.Fatalf("stats.SignerID = %q, want %q", stats.SignerID, signerID)
	}
	if stats.CertificatePEM != string(certPEM) {
		t.Fatalf("stats.CertificatePEM mismatch")
	}
	if stats.PublicKeyPEM != string(pubKeyPEM) {
		t.Fatalf("stats.PublicKeyPEM mismatch")
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
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("GET / Cache-Control = %q, want no-store", cc)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("IVNP Reseed Indexer")) {
		t.Fatal("GET / dashboard does not contain expected title")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("initial-data")) {
		t.Fatal("GET / dashboard does not contain bootstrap initial-data")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("btn-dl-cert")) {
		t.Fatal("GET / dashboard does not contain btn-dl-cert")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("key-modal")) {
		t.Fatal("GET / dashboard does not contain key-modal")
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

func TestStratifyByBucketDiversityForJavaI2P(t *testing.T) {
	// Create 1024 peers across diverse buckets
	var peers []PeerRecord
	for i := 0; i < 1024; i++ {
		var hash [32]byte
		// Distribute across 256 buckets
		hash[0] = byte(i % 256)
		hash[1] = byte(i / 256)
		isFlood := (i / 256) == 0
		peers = append(peers, PeerRecord{
			Hash:        hash,
			IsFloodfill: isFlood,
			Score:       100.0 - float64(i%10),
			Stats: PeerStats{
				IsReachable: true,
			},
		})
	}

	stratified := StratifyByBucketDiversity(peers)
	if len(stratified) != len(peers) {
		t.Fatalf("stratified len = %d, want %d", len(stratified), len(peers))
	}

	// Verify the first 256 entries each come from a distinct bucket
	seenBuckets := make(map[byte]bool)
	for i := 0; i < 256; i++ {
		b := stratified[i].Hash[0]
		if seenBuckets[b] {
			t.Fatalf("duplicate bucket %d at index %d in first 256 entries", b, i)
		}
		seenBuckets[b] = true
	}

	// Verify that the first 200 entries (which Java I2P parses) are 200 distinct buckets
	if len(seenBuckets) < 256 {
		t.Fatalf("expected 256 distinct buckets in first 256 entries, got %d", len(seenBuckets))
	}

	// Verify floodfills are prioritized in front slots where available
	for i := 0; i < 256; i++ {
		if !stratified[i].IsFloodfill {
			t.Fatalf("expected floodfill at front index %d", i)
		}
	}
}

func TestTargetPeersDefault1024(t *testing.T) {
	cfg := DefaultSelectorConfig()
	if cfg.TargetCount != 1024 {
		t.Fatalf("DefaultSelectorConfig.TargetCount = %d, want 1024", cfg.TargetCount)
	}
}

func TestLoadOrGenerateReseedCertificate(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "reseed-rsa.key")
	certPath := filepath.Join(tempDir, "reseed-rsa.crt")
	pubKeyPath := filepath.Join(tempDir, "reseed-rsa.pub.pem")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	key, err := loadOrGenerateRSASigningKey(keyPath, logger)
	if err != nil {
		t.Fatalf("loadOrGenerateRSASigningKey failed: %v", err)
	}

	signerID := "test-signer@ivnp.network"
	certPEM, pubPEM, err := loadOrGenerateReseedCertificate(certPath, pubKeyPath, signerID, key, logger)
	if err != nil {
		t.Fatalf("loadOrGenerateReseedCertificate failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected valid CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != signerID {
		t.Fatalf("cert CommonName = %q, want %q", cert.Subject.CommonName, signerID)
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || rsaPub.N.BitLen() != 4096 {
		t.Fatal("expected 4096-bit RSA public key in certificate")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("expected KeyUsageDigitalSignature in certificate")
	}

	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatal("expected valid PUBLIC KEY PEM block")
	}

	reloadedCert, reloadedPub, err := loadOrGenerateReseedCertificate(certPath, pubKeyPath, signerID, key, logger)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !bytes.Equal(certPEM, reloadedCert) {
		t.Fatal("expected reloaded certificate to match original")
	}
	if !bytes.Equal(pubPEM, reloadedPub) {
		t.Fatal("expected reloaded public key to match original")
	}
}

func TestTunnelBuildAcceptedTrackingAndScoring(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "LR")
	rec, _ := store.AddOrUpdate(info, raw)

	baseScore := rec.Score
	store.RecordTunnelBuildResult(info.Hash(), true)

	snap := store.Snapshot()
	if !snap[0].Stats.TunnelBuildAccepted {
		t.Fatal("expected TunnelBuildAccepted = true")
	}
	if snap[0].Stats.LastTunnelAccepted.IsZero() {
		t.Fatal("expected LastTunnelAccepted to be set")
	}
	if snap[0].Score-baseScore < 14.9 {
		t.Fatalf("expected +15 bonus for accepted tunnel, got diff %v", snap[0].Score-baseScore)
	}
}

func TestEvictionDiversityProtection(t *testing.T) {
	store := NewPeerStore()

	// Fill bucket 0 with 6 peers with very low scores
	for i := 0; i < 6; i++ {
		var h [32]byte
		h[0] = 0
		h[1] = byte(i)
		store.peers[h] = &PeerRecord{
			Hash:  h,
			Score: float64(10 + i), // low score
		}
	}

	// Fill bucket 1 with 1 peer with even lower score
	var hSparse [32]byte
	hSparse[0] = 1
	store.peers[hSparse] = &PeerRecord{
		Hash:  hSparse,
		Score: 1.0, // lowest score in entire store!
	}

	store.evictWorstLocked()

	// The sparse bucket (bucket 1) should be protected despite having the lowest score!
	if _, found := store.peers[hSparse]; !found {
		t.Fatal("expected sparse bucket peer to be protected from eviction")
	}

	// Bucket 0 should have evicted its lowest peer
	var hLowestBucket0 [32]byte
	hLowestBucket0[0] = 0
	hLowestBucket0[1] = 0
	if _, found := store.peers[hLowestBucket0]; found {
		t.Fatal("expected lowest peer from crowded bucket 0 to be evicted")
	}
}

func TestCalculatePackageStats(t *testing.T) {
	now := time.Now()
	v4Addr := netip.MustParseAddr("198.51.100.1")
	v6Addr := netip.MustParseAddr("2001:db8::1")

	peers := []PeerRecord{
		{
			Hash:        foundation.Hash{1},
			IsFloodfill: true,
			IPv4:        []netip.Addr{v4Addr},
			Stats: PeerStats{
				IsReachable:         true,
				TotalProbes:         10,
				SuccessProbes:       10,
				TunnelBuildAccepted: true,
				EWMARTT:             40 * time.Millisecond,
			},
		},
		{
			Hash:        foundation.Hash{2},
			IsFloodfill: false,
			IPv4:        []netip.Addr{v4Addr},
			IPv6:        []netip.Addr{v6Addr},
			Stats: PeerStats{
				IsReachable:         true,
				TotalProbes:         10,
				SuccessProbes:       8,
				TunnelBuildAccepted: false,
				EWMARTT:             80 * time.Millisecond,
			},
		},
		{
			Hash:        foundation.Hash{3},
			IsFloodfill: false,
			IPv6:        []netip.Addr{v6Addr},
			Stats: PeerStats{
				IsReachable:         false,
				TotalProbes:         5,
				SuccessProbes:       0,
				TunnelBuildAccepted: false,
			},
		},
	}

	stats := CalculatePackageStats(peers, 4096, `"test-etag"`, now, true)

	if stats.PeerCount != 3 {
		t.Fatalf("PeerCount = %d, want 3", stats.PeerCount)
	}
	if stats.FloodfillCount != 1 || stats.FloodfillRatio != 1.0/3.0 {
		t.Fatalf("FloodfillCount = %d, ratio = %f", stats.FloodfillCount, stats.FloodfillRatio)
	}
	if stats.IPv4OnlyCount != 1 || stats.DualStackCount != 1 || stats.IPv6OnlyCount != 1 {
		t.Fatalf("IP stack counts: v4=%d, dual=%d, v6=%d", stats.IPv4OnlyCount, stats.DualStackCount, stats.IPv6OnlyCount)
	}
	if stats.DirectlyReachableCount != 2 || stats.DirectlyReachableRatio != 2.0/3.0 {
		t.Fatalf("DirectlyReachable: count=%d, ratio=%f", stats.DirectlyReachableCount, stats.DirectlyReachableRatio)
	}
	if stats.TunnelBuildAcceptedCount != 1 || stats.TunnelBuildAcceptedRatio != 1.0/3.0 {
		t.Fatalf("TunnelBuildAccepted: count=%d, ratio=%f", stats.TunnelBuildAcceptedCount, stats.TunnelBuildAcceptedRatio)
	}
	expectedAvail := (1.0 + 0.8 + 0.0) / 3.0
	if diff := stats.AverageAvailability - expectedAvail; diff > 0.001 || diff < -0.001 {
		t.Fatalf("AverageAvailability = %f, want %f", stats.AverageAvailability, expectedAvail)
	}
	if stats.RTT.MinMs != 40 || stats.RTT.MaxMs != 80 || stats.RTT.AvgMs != 60 {
		t.Fatalf("RTT stats: min=%d, max=%d, avg=%d", stats.RTT.MinMs, stats.RTT.MaxMs, stats.RTT.AvgMs)
	}
	if !stats.RequireReachableFilter {
		t.Fatal("expected RequireReachableFilter = true")
	}
	if stats.GenerationMethod == "" {
		t.Fatal("expected GenerationMethod to be populated")
	}
}

func TestReseedPackageTelemetryInDashboard(t *testing.T) {
	stats := DetailedStatsResponse{
		Version:   "test-version",
		NetworkID: 2,
		Package: PackageStats{
			PeerCount:                500,
			FloodfillCount:           180,
			FloodfillRatio:           0.36,
			IPv4OnlyCount:            300,
			IPv4OnlyRatio:            0.60,
			DualStackCount:           190,
			DualStackRatio:           0.38,
			IPv6OnlyCount:            10,
			IPv6OnlyRatio:            0.02,
			AverageAvailability:      0.985,
			DirectlyReachableCount:   500,
			DirectlyReachableRatio:   1.0,
			TunnelBuildAcceptedCount: 470,
			TunnelBuildAcceptedRatio: 0.94,
			RTT: RTTStats{
				MinMs: 15,
				AvgMs: 145,
				P50Ms: 120,
				P90Ms: 250,
				MaxMs: 450,
			},
			GenerationMethod:       "256 K-Bucket Stratified (Java I2P 256-node Head-Start) + /16 Subnet Filter + Max-5 Bucket Leveling",
			RequireReachableFilter: true,
			SU3SizeBytes:           256000,
			ETag:                   `"mock-etag"`,
		},
	}

	var buf bytes.Buffer
	if err := RenderDashboard(&buf, stats); err != nil {
		t.Fatalf("RenderDashboard: %v", err)
	}
	html := buf.String()

	requiredSubstrings := []string{
		"Standard I2P SU3 Archive",
		"Generation Strategy",
		"Floodfill Ratio",
		"IP Stack Ratio",
		"Average Availability",
		"Package Latency",
		"su3-layout",
		"pkg-metric-ff",
		"pkg-metric-dual",
		"pkg-metric-avail",
		"pkg-metric-rtt",
		"256 K-Bucket Stratified",
	}

	for _, sub := range requiredSubstrings {
		if !strings.Contains(html, sub) {
			t.Errorf("rendered dashboard missing expected substring %q", sub)
		}
	}
}

func TestSelectorExcludesIPv6Only(t *testing.T) {
	v4Addr := netip.MustParseAddr("198.51.100.1")
	v6Addr := netip.MustParseAddr("2001:db8::1")

	peers := []PeerRecord{
		{
			Hash: foundation.Hash{1},
			Raw:  []byte("raw-dual"),
			IPv4: []netip.Addr{v4Addr},
			IPv6: []netip.Addr{v6Addr},
			Stats: PeerStats{
				IsReachable: true,
			},
			Score: 100,
		},
		{
			Hash: foundation.Hash{2},
			Raw:  []byte("raw-v4only"),
			IPv4: []netip.Addr{v4Addr},
			Stats: PeerStats{
				IsReachable: true,
			},
			Score: 90,
		},
		{
			Hash: foundation.Hash{3},
			Raw:  []byte("raw-v6only"),
			IPv6: []netip.Addr{v6Addr},
			Stats: PeerStats{
				IsReachable: true,
			},
			Score: 95,
		},
	}

	cfg := DefaultSelectorConfig()
	cfg.TargetCount = 10
	selected := SelectDiversePeers(peers, cfg)

	if len(selected) != 2 {
		t.Fatalf("selected = %d, want 2", len(selected))
	}
	for _, p := range selected {
		if len(p.IPv4) == 0 {
			t.Fatalf("selected peer %x has no IPv4 (IPv6 only), must be excluded", p.Hash)
		}
	}
}
