package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServerConfig struct {
	NetworkID     uint8
	ListenAddress string
	CacheDuration time.Duration
	SignerID      string
	CertPEM       []byte
	PubKeyPEM     []byte
}

type ReseedServer struct {
	cfg       ServerConfig
	store     *PeerStore
	startedAt time.Time

	mu      sync.RWMutex
	pkg     ReseedPackage
	handler http.Handler
}

type StatsResponse = DetailedStatsResponse

func NewReseedServer(cfg ServerConfig, store *PeerStore) *ReseedServer {
	if cfg.CacheDuration <= 0 {
		cfg.CacheDuration = 5 * time.Minute
	}
	s := &ReseedServer{
		cfg:       cfg,
		store:     store,
		startedAt: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/i2pseeds.su3", s.handleSU3)
	mux.HandleFunc("/reseed-rsa.crt", s.handleCert)
	mux.HandleFunc("/reseed.crt", s.handleCert)
	mux.HandleFunc("/reseed-rsa.pub.pem", s.handlePubKey)
	mux.HandleFunc("/reseed.pub", s.handlePubKey)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/health", s.handleHealth)
	s.handler = mux
	return s
}

func (s *ReseedServer) UpdatePackage(pkg ReseedPackage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkg = pkg
}

func (s *ReseedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *ReseedServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	stats := s.calculateStats()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_ = RenderDashboard(w, stats)
}

func (s *ReseedServer) handleSU3(w http.ResponseWriter, r *http.Request) {
	if !s.validateNetID(w, r) {
		return
	}
	s.mu.RLock()
	pkg := s.pkg
	s.mu.RUnlock()

	if len(pkg.SU3Data) == 0 {
		http.Error(w, "reseed archive not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.cfg.CacheDuration.Seconds())))
	w.Header().Set("ETag", pkg.ETag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == pkg.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(pkg.SU3Data)))
	_, _ = w.Write(pkg.SU3Data)
}

func (s *ReseedServer) validateNetID(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query().Get("netid")
	if q == "" {
		return true // Allow default
	}
	id, err := strconv.ParseUint(q, 10, 8)
	if err != nil || uint8(id) != s.cfg.NetworkID {
		http.Error(w, "invalid or unsupported network ID", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *ReseedServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

func certFileName(signerID string) string {
	clean := strings.ReplaceAll(signerID, "@", "_at_")
	clean = strings.ReplaceAll(clean, "/", "_")
	clean = strings.ReplaceAll(clean, "\\", "_")
	clean = strings.ReplaceAll(clean, ":", "_")
	return cmp.Or(clean, "reseed") + ".crt"
}

func (s *ReseedServer) handleCert(w http.ResponseWriter, _ *http.Request) {
	if len(s.cfg.CertPEM) == 0 {
		http.Error(w, "reseed certificate not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", certFileName(s.cfg.SignerID)))
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(s.cfg.CertPEM)
}

func (s *ReseedServer) handlePubKey(w http.ResponseWriter, _ *http.Request) {
	if len(s.cfg.PubKeyPEM) == 0 {
		http.Error(w, "reseed public key not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="reseed-rsa.pub.pem"`)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(s.cfg.PubKeyPEM)
}

func (s *ReseedServer) calculateStats() DetailedStatsResponse {
	s.mu.RLock()
	pkg := s.pkg
	s.mu.RUnlock()

	peers := s.store.Snapshot()
	reachable := 0
	floodfills := 0
	var rtts []time.Duration
	var totalRTT time.Duration

	var distribution [256]int
	coveredBuckets := 0

	seenSubnets16 := make(map[[2]byte]struct{})
	seenSubnets24 := make(map[[3]byte]struct{})
	seenV4 := make(map[netip.Addr]struct{})
	seenV6 := make(map[netip.Addr]struct{})
	seenFamilies := make(map[string]struct{})

	for _, p := range peers {
		bucket := int(p.Hash[0])
		if distribution[bucket] == 0 {
			coveredBuckets++
		}
		distribution[bucket]++

		if p.Stats.IsReachable {
			reachable++
		}
		if p.IsFloodfill {
			floodfills++
		}
		if p.Stats.IsReachable && p.Stats.EWMARTT > 0 {
			rtts = append(rtts, p.Stats.EWMARTT)
			totalRTT += p.Stats.EWMARTT
		}
		if p.Family != "" {
			seenFamilies[p.Family] = struct{}{}
		}
		for _, ip := range p.IPv4 {
			if ip.Is4() {
				seenV4[ip] = struct{}{}
				seenSubnets16[IPv4Subnet16(ip)] = struct{}{}
				seenSubnets24[IPv4Subnet24(ip)] = struct{}{}
			}
		}
		for _, ip := range p.IPv6 {
			if ip.Is6() {
				seenV6[ip] = struct{}{}
			}
		}
	}

	var rttStats RTTStats
	avgRTT := time.Duration(0)
	if len(rtts) > 0 {
		slices.Sort(rtts)
		rttStats.MinMs = rtts[0].Milliseconds()
		rttStats.MaxMs = rtts[len(rtts)-1].Milliseconds()
		rttStats.P50Ms = rtts[len(rtts)*50/100].Milliseconds()
		rttStats.P90Ms = rtts[len(rtts)*90/100].Milliseconds()
		rttStats.P99Ms = rtts[len(rtts)*99/100].Milliseconds()
		avgDuration := totalRTT / time.Duration(len(rtts))
		rttStats.AvgMs = avgDuration.Milliseconds()
		avgRTT = avgDuration
	}

	nextRefreshSec := int64(0)
	if !pkg.GeneratedAt.IsZero() {
		nextTime := pkg.GeneratedAt.Add(s.cfg.CacheDuration)
		rem := time.Until(nextTime)
		if rem > 0 {
			nextRefreshSec = int64(rem.Seconds())
		}
	}

	floodfillRatio := 0.0
	if pkg.PeerCount > 0 {
		floodfillRatio = float64(pkg.FloodfillCount) / float64(pkg.PeerCount)
	}

	coveragePct := float64(coveredBuckets) / 256.0 * 100.0

	mode := ExplorationModeExpansion
	if reachable >= 1024 {
		mode = ExplorationModeMaintenance
	}

	packageStats := pkg.Stats
	if packageStats.PeerCount == 0 && pkg.PeerCount > 0 {
		packageStats.PeerCount = pkg.PeerCount
		packageStats.FloodfillCount = pkg.FloodfillCount
		packageStats.FloodfillRatio = floodfillRatio
		packageStats.SU3SizeBytes = len(pkg.SU3Data)
		packageStats.ETag = pkg.ETag
		packageStats.LastGeneratedAt = pkg.GeneratedAt
		packageStats.GenerationMethod = "256 K-Bucket Stratified (Java I2P 256-node Head-Start) + /16 Subnet Filter + Max-5 Bucket Leveling"
	}
	packageStats.NextRefreshETA = nextRefreshSec

	return DetailedStatsResponse{
		Version:         version,
		NetworkID:       s.cfg.NetworkID,
		UptimeSeconds:   int64(time.Since(s.startedAt).Seconds()),
		ExplorationMode: mode,
		TotalIndexed:    len(peers),
		ReachablePeers:  reachable,
		FloodfillPeers:  floodfills,
		PublishedPeers:  pkg.PeerCount,
		AverageEWMARTT:  avgRTT / time.Millisecond,
		LastGeneratedAt: pkg.GeneratedAt,
		SignerID:        s.cfg.SignerID,
		CertificatePEM:  string(s.cfg.CertPEM),
		PublicKeyPEM:    string(s.cfg.PubKeyPEM),
		RTT:             rttStats,
		Diversity: DiversityStats{
			UniqueIPv4Subnets16: len(seenSubnets16),
			UniqueIPv4Subnets24: len(seenSubnets24),
			UniqueIPv4Count:     len(seenV4),
			UniqueIPv6Count:     len(seenV6),
			UniqueFamilies:      len(seenFamilies),
		},
		KBuckets: KBucketStats{
			TotalBuckets:    256,
			CoveredBuckets:  coveredBuckets,
			CoveragePercent: coveragePct,
			Distribution:    distribution,
		},
		Package: packageStats,
	}
}

func (s *ReseedServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	resp := s.calculateStats()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_ = json.NewEncoder(w).Encode(resp)
}
