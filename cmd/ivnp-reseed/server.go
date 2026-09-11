package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type ServerConfig struct {
	NetworkID     uint8
	ListenAddress string
	CacheDuration time.Duration
}

type ReseedServer struct {
	cfg   ServerConfig
	store *PeerStore

	mu      sync.RWMutex
	pkg     ReseedPackage
	handler http.Handler
}

func NewReseedServer(cfg ServerConfig, store *PeerStore) *ReseedServer {
	if cfg.CacheDuration <= 0 {
		cfg.CacheDuration = 5 * time.Minute
	}
	s := &ReseedServer{
		cfg:   cfg,
		store: store,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/i2pseeds.su3", s.handleSU3)
	mux.HandleFunc("/ivnpseeds.bin", s.handleIVBS)
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

func (s *ReseedServer) handleIVBS(w http.ResponseWriter, r *http.Request) {
	if !s.validateNetID(w, r) {
		return
	}
	s.mu.RLock()
	pkg := s.pkg
	s.mu.RUnlock()

	if len(pkg.IVBSData) == 0 {
		http.Error(w, "ivnp archive not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.cfg.CacheDuration.Seconds())))
	w.Header().Set("ETag", pkg.ETag+"-ivbs")

	if match := r.Header.Get("If-None-Match"); match != "" && match == pkg.ETag+"-ivbs" {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(pkg.IVBSData)))
	_, _ = w.Write(pkg.IVBSData)
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

type StatsResponse struct {
	TotalIndexed    int           `json:"total_indexed"`
	ReachablePeers  int           `json:"reachable_peers"`
	FloodfillPeers  int           `json:"floodfill_peers"`
	PublishedPeers  int           `json:"published_peers"`
	AverageEWMARTT  time.Duration `json:"average_ewma_rtt_ms"`
	LastGeneratedAt time.Time     `json:"last_generated_at"`
}

func (s *ReseedServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	pkg := s.pkg
	s.mu.RUnlock()

	peers := s.store.Snapshot()
	reachable := 0
	floodfills := 0
	var totalRTT time.Duration
	rttCount := 0

	for _, p := range peers {
		if p.Stats.IsReachable {
			reachable++
		}
		if p.IsFloodfill {
			floodfills++
		}
		if p.Stats.EWMARTT > 0 {
			totalRTT += p.Stats.EWMARTT
			rttCount++
		}
	}

	avgRTT := time.Duration(0)
	if rttCount > 0 {
		avgRTT = totalRTT / time.Duration(rttCount)
	}

	resp := StatsResponse{
		TotalIndexed:    len(peers),
		ReachablePeers:  reachable,
		FloodfillPeers:  floodfills,
		PublishedPeers:  pkg.PeerCount,
		AverageEWMARTT:  avgRTT / time.Millisecond,
		LastGeneratedAt: pkg.GeneratedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
