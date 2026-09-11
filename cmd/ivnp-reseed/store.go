package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// PeerStore provides thread-safe, memory-bounded peer indexing and snapshot persistence.
type PeerStore struct {
	mu       sync.RWMutex
	peers    map[foundation.Hash]*PeerRecord
	maxPeers int
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers:    make(map[foundation.Hash]*PeerRecord),
		maxPeers: MaxStorePeers,
	}
}

func (s *PeerStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

func (s *PeerStore) AddOrUpdate(info foundation.NetworkDatabaseRouterInfo, raw []byte) (*PeerRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := info.Hash()
	existing, found := s.peers[hash]
	if !found {
		// Enforce bounded memory: prune lowest score peer if at max capacity
		if len(s.peers) >= s.maxPeers {
			s.evictWorstLocked()
		}

		family, v4, v6, ports := extractRouterAddresses(info)
		rec := &PeerRecord{
			Hash:        hash,
			Raw:         bytes.Clone(raw),
			PublishedAt: time.UnixMilli(int64(info.Published)),
			IsFloodfill: foundation.NetworkDatabaseIsFloodfill(info),
			Family:      family,
			IPv4:        v4,
			IPv6:        v6,
			Ports:       ports,
			Stats: PeerStats{
				LastSeen: time.Now(),
			},
		}
		rec.Score = calculateScore(rec)
		s.peers[hash] = rec
		return rec, true
	}

	// Update existing record if newer published date
	if published := time.UnixMilli(int64(info.Published)); published.After(existing.PublishedAt) {
		existing.PublishedAt = published
		existing.Raw = bytes.Clone(raw)
		family, v4, v6, ports := extractRouterAddresses(info)
		existing.Family = family
		existing.IPv4 = v4
		existing.IPv6 = v6
		existing.Ports = ports
		existing.IsFloodfill = foundation.NetworkDatabaseIsFloodfill(info)
	}
	existing.Score = calculateScore(existing)
	return existing, false
}

func (s *PeerStore) evictWorstLocked() {
	var worstHash foundation.Hash
	var worstScore float64 = 1e9
	found := false

	for h, p := range s.peers {
		if !found || p.Score < worstScore {
			worstHash = h
			worstScore = p.Score
			found = true
		}
	}
	if found {
		delete(s.peers, worstHash)
	}
}

func (s *PeerStore) RecordProbeResult(hash foundation.Hash, success bool, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.peers[hash]
	if !found {
		return
	}

	now := time.Now()
	rec.Stats.TotalProbes++
	rec.Stats.LastProbed = now

	if success {
		rec.Stats.SuccessProbes++
		rec.Stats.ConsecutiveFails = 0
		rec.Stats.IsReachable = true
		rec.Stats.LastSeen = now
		rec.Stats.LastRTT = rtt
		if rec.Stats.EWMARTT == 0 {
			rec.Stats.EWMARTT = rtt
		} else {
			// EWMA: 20% current, 80% history
			rec.Stats.EWMARTT = time.Duration(0.2*float64(rtt) + 0.8*float64(rec.Stats.EWMARTT))
		}
	} else {
		rec.Stats.ConsecutiveFails++
		if rec.Stats.ConsecutiveFails >= 2 {
			rec.Stats.IsReachable = false
		}
	}

	rec.Score = calculateScore(rec)
}

func (s *PeerStore) Snapshot() []PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]PeerRecord, 0, len(s.peers))
	for _, rec := range s.peers {
		result = append(result, *rec)
	}
	return result
}

func (s *PeerStore) SaveToFile(filePath string) error {
	s.mu.RLock()
	records := make([]*PeerRecord, 0, len(s.peers))
	for _, rec := range s.peers {
		records = append(records, rec)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}

func (s *PeerStore) LoadFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var loaded []*PeerRecord
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range loaded {
		s.peers[rec.Hash] = rec
	}
	return nil
}

func calculateScore(rec *PeerRecord) float64 {
	// Base uptime score (0 ~ 50 points)
	uptimeRatio := 0.5
	if rec.Stats.TotalProbes > 0 {
		uptimeRatio = float64(rec.Stats.SuccessProbes) / float64(rec.Stats.TotalProbes)
	}
	score := uptimeRatio * 50.0

	// Latency score (0 ~ 30 points)
	if rec.Stats.IsReachable && rec.Stats.EWMARTT > 0 {
		rttMs := float64(rec.Stats.EWMARTT.Milliseconds())
		latencyPts := 30.0 - (rttMs / 10.0)
		if latencyPts < 0 {
			latencyPts = 0
		}
		score += latencyPts
	}

	// Accessible Floodfill priority bonus (+30 points)
	if rec.IsFloodfill {
		score += 30.0
	}

	// Severe penalty for consecutive failures
	if rec.Stats.ConsecutiveFails > 0 {
		score -= float64(rec.Stats.ConsecutiveFails) * 15.0
	}

	if score < 0 {
		score = 0
	}
	return score
}

func extractRouterAddresses(info foundation.NetworkDatabaseRouterInfo) (string, []netip.Addr, []netip.Addr, []uint16) {
	family := extractFamily(info)
	var v4 []netip.Addr
	var v6 []netip.Addr
	var ports []uint16

	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			break
		}
		ip, port := parseAddressEndpoint(address)
		if !ip.IsValid() {
			continue
		}
		if ip.Is4() {
			v4 = append(v4, ip)
		} else if ip.Is6() {
			v6 = append(v6, ip)
		}
		if port > 0 {
			ports = append(ports, port)
		}
	}
	return family, v4, v6, ports
}

func extractFamily(info foundation.NetworkDatabaseRouterInfo) string {
	options := info.Options.Iterator()
	for {
		key, value, ok, err := options.Next()
		if err != nil || !ok {
			return ""
		}
		if bytes.Equal(key, []byte("family")) {
			return string(value)
		}
	}
}

func parseAddressEndpoint(address foundation.NetworkDatabaseRouterAddress) (netip.Addr, uint16) {
	var host string
	var port uint64
	opts := address.Options.Iterator()
	for {
		k, v, ok, err := opts.Next()
		if err != nil || !ok {
			break
		}
		switch string(k) {
		case "host":
			host = string(v)
		case "port":
			port, _ = strconv.ParseUint(string(v), 10, 16)
		}
	}
	if host == "" {
		return netip.Addr{}, 0
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0
	}
	return ip, uint16(port)
}
