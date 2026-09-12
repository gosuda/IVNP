package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// PeerStore provides thread-safe, memory-bounded peer indexing and snapshot persistence.
type PeerStore struct {
	mu         sync.RWMutex
	peers      map[foundation.Hash]*PeerRecord
	bySubnet16 map[[2]byte]map[foundation.Hash]struct{}
	byFamily   map[string]map[foundation.Hash]struct{}
	maxPeers   int
	localHash  foundation.Hash
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers:      make(map[foundation.Hash]*PeerRecord),
		bySubnet16: make(map[[2]byte]map[foundation.Hash]struct{}),
		byFamily:   make(map[string]map[foundation.Hash]struct{}),
		maxPeers:   MaxStorePeers,
	}
}

func (s *PeerStore) SetLocalHash(h foundation.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localHash = h
	s.deletePeerLocked(h)
}

func (s *PeerStore) LocalHash() foundation.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localHash
}

func (s *PeerStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

func (s *PeerStore) AddOrUpdate(info foundation.NetworkDatabaseRouterInfo, raw []byte) (*PeerRecord, bool) {
	return s.AddOrUpdateWithSeen(info, raw, 0)
}

func (s *PeerStore) AddOrUpdateWithSeen(info foundation.NetworkDatabaseRouterInfo, raw []byte, seenAt uint64) (*PeerRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := info.Hash()
	if hash == s.localHash && s.localHash != (foundation.Hash{}) {
		return nil, false
	}

	now := time.Now()
	lastSeen := now
	if seenAt > 0 {
		seenTime := time.UnixMilli(int64(seenAt))
		if seenTime.After(lastSeen) {
			lastSeen = seenTime
		}
	}

	existing, found := s.peers[hash]
	if !found {
		family, v4, v6, ports, tcpPorts, udpPorts := extractRouterAddresses(info)
		rec := &PeerRecord{
			Hash:        hash,
			Raw:         bytes.Clone(raw),
			PublishedAt: time.UnixMilli(int64(info.Published)),
			Family:      family,
			IsFloodfill: foundation.NetworkDatabaseIsFloodfill(info),
			IPv4:        v4,
			IPv6:        v6,
			Ports:       ports,
			TCPPorts:    tcpPorts,
			UDPPorts:    udpPorts,
			Stats: PeerStats{
				LastSeen: lastSeen,
			},
		}
		if now.Sub(lastSeen) < 2*time.Hour {
			rec.Stats.IsReachable = true
		}
		rec.Score = calculateScore(rec)

		// Reject peers that lose every /16 subnet and family contest they enter:
		// a strictly better retained peer claims the group, so they can never be selected.
		if hasGroup, tops := s.topsAnyContentionLocked(rec); hasGroup && !tops {
			return nil, false
		}

		// Enforce bounded memory: evict a batch of lowest-utility peers when reaching capacity
		// to allow continuous turnover and admission of newly discovered DHT peers.
		if len(s.peers) >= s.maxPeers {
			batch := min(25, max(2, s.maxPeers/100))
			s.evictBatchLocked(batch)
		}

		s.peers[hash] = rec
		s.indexPeerLocked(rec)
		s.evictDominatedLocked(rec)
		return rec, true
	}

	if lastSeen.After(existing.Stats.LastSeen) {
		existing.Stats.LastSeen = lastSeen
		if now.Sub(lastSeen) < 2*time.Hour && existing.Stats.ConsecutiveFails == 0 {
			existing.Stats.IsReachable = true
		}
	}

	// Update existing record if newer published date
	if published := time.UnixMilli(int64(info.Published)); published.After(existing.PublishedAt) {
		existing.PublishedAt = published
		existing.Raw = bytes.Clone(raw)
		s.deindexPeerLocked(existing)
		family, v4, v6, ports, tcpPorts, udpPorts := extractRouterAddresses(info)
		existing.Family = family
		existing.IPv4 = v4
		existing.IPv6 = v6
		existing.Ports = ports
		existing.TCPPorts = tcpPorts
		existing.UDPPorts = udpPorts
		existing.IsFloodfill = foundation.NetworkDatabaseIsFloodfill(info)
		existing.Score = calculateScore(existing)
		s.indexPeerLocked(existing)
		if hasGroup, tops := s.topsAnyContentionLocked(existing); hasGroup && !tops {
			s.deletePeerLocked(existing.Hash)
			return nil, false
		}
		s.evictDominatedLocked(existing)
	}
	existing.Score = calculateScore(existing)
	return existing, false
}

func (s *PeerStore) BucketDistribution() [256]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var dist [256]int
	for _, rec := range s.peers {
		dist[rec.Hash[0]]++
	}
	return dist
}

func (s *PeerStore) ReachableCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, rec := range s.peers {
		if rec.Stats.IsReachable && rec.Stats.ConsecutiveFails < 2 {
			count++
		}
	}
	return count
}

func (s *PeerStore) ReachableBucketDistribution() [256]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var dist [256]int
	for _, rec := range s.peers {
		if rec.Stats.IsReachable && rec.Stats.ConsecutiveFails < 2 {
			dist[rec.Hash[0]]++
		}
	}
	return dist
}

func (s *PeerStore) RecordTunnelBuildResult(hash foundation.Hash, accepted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.peers[hash]
	if !found {
		return
	}
	rec.Stats.TunnelBuildAccepted = accepted
	if accepted {
		rec.Stats.LastTunnelAccepted = time.Now()
	}
	rec.Score = calculateScore(rec)
}

func (s *PeerStore) evictWorstLocked() {
	s.evictBatchLocked(1)
}

// evictBatchLocked evicts up to count lowest-utility peers to free up capacity for newly discovered nodes.
// Candidates in sparse buckets (<= 4 peers) are protected to preserve K-Bucket diversity.
func (s *PeerStore) evictBatchLocked(count int) int {
	if count <= 0 || len(s.peers) == 0 {
		return 0
	}

	var bucketCounts [256]int
	for _, p := range s.peers {
		bucketCounts[p.Hash[0]]++
	}

	now := time.Now()
	evicted := 0

	type scoredPeer struct {
		hash  foundation.Hash
		score float64
	}

	evictCandidates := func(minBucketCount int, filter func(p *PeerRecord) bool) {
		if evicted >= count {
			return
		}
		var candidates []scoredPeer
		for h, p := range s.peers {
			if bucketCounts[p.Hash[0]] > minBucketCount && (filter == nil || filter(p)) {
				candidates = append(candidates, scoredPeer{hash: h, score: p.Score})
			}
		}
		slices.SortFunc(candidates, func(a, b scoredPeer) int {
			return cmp.Compare(a.score, b.score)
		})
		for _, sp := range candidates {
			if evicted >= count {
				break
			}
			if bucketCounts[sp.hash[0]] <= minBucketCount {
				continue
			}
			if _, exists := s.peers[sp.hash]; exists {
				s.deletePeerLocked(sp.hash)
				bucketCounts[sp.hash[0]]--
				evicted++
			}
		}
	}

	// 1. Dead peers (consecutive failures >= 2 and not reachable) in non-sparse buckets (> 2 peers)
	evictCandidates(2, func(p *PeerRecord) bool {
		return !p.Stats.IsReachable && p.Stats.ConsecutiveFails >= 2
	})

	// 2. Long-stale peers (> 12h unseen) in crowded buckets (> 4 peers)
	evictCandidates(4, func(p *PeerRecord) bool {
		return !p.Stats.LastSeen.IsZero() && now.Sub(p.Stats.LastSeen) > 12*time.Hour
	})

	// 3. Lowest score peers in crowded buckets (> 4 peers)
	evictCandidates(4, nil)

	// 4. Fallback: lowest score peers overall if still needed
	evictCandidates(0, nil)

	return evicted
}

// PruneStale actively removes stale or repeatedly failed peers from non-sparse buckets.
func (s *PeerStore) PruneStale(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneStaleLocked(maxAge)
}

func (s *PeerStore) pruneStaleLocked(maxAge time.Duration) int {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	now := time.Now()
	var bucketCounts [256]int
	for _, p := range s.peers {
		bucketCounts[p.Hash[0]]++
	}

	pruned := 0
	for h, p := range s.peers {
		// Preserve sparse buckets to protect DHT keyspace diversity
		if bucketCounts[p.Hash[0]] <= 4 {
			continue
		}
		isDead := (!p.Stats.IsReachable && p.Stats.ConsecutiveFails >= 3)
		isStale := (!p.Stats.LastSeen.IsZero() && now.Sub(p.Stats.LastSeen) > maxAge && !p.Stats.IsReachable)
		if isDead || isStale {
			s.deletePeerLocked(h)
			bucketCounts[h[0]]--
			pruned++
		}
	}
	return pruned
}

// PruneRedundant removes peers that can never win selection: every contention
// group they join (each shared IPv4 /16 subnet and their router family)
// already retains a strictly better member. Admission-time rejection keeps
// redundant peers out; this sweep corrects ranking drift as probe and tunnel
// results change member scores.
func (s *PeerStore) PruneRedundant() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	subnets := make(map[[2]byte][]foundation.Hash)
	families := make(map[string][]foundation.Hash)
	for h, rec := range s.peers {
		for _, ip := range rec.IPv4 {
			if ip.Is4() {
				subnet := IPv4Subnet16(ip)
				subnets[subnet] = append(subnets[subnet], h)
			}
		}
		if rec.Family != "" {
			families[rec.Family] = append(families[rec.Family], h)
		}
	}

	keep := make(map[foundation.Hash]struct{}, len(subnets)+len(families))
	contested := make(map[foundation.Hash]struct{})
	markTop := func(members []foundation.Hash) {
		var top *PeerRecord
		for _, h := range members {
			contested[h] = struct{}{}
			rec := s.peers[h]
			if rec == nil {
				continue
			}
			if top == nil || compareRetention(rec, top) < 0 {
				top = rec
			}
		}
		if top != nil {
			keep[top.Hash] = struct{}{}
		}
	}
	for _, members := range subnets {
		markTop(members)
	}
	for _, members := range families {
		markTop(members)
	}

	evicted := 0
	for h := range contested {
		if _, ok := keep[h]; !ok {
			s.deletePeerLocked(h)
			evicted++
		}
	}
	return evicted
}

func (s *PeerStore) indexPeerLocked(rec *PeerRecord) {
	for _, ip := range rec.IPv4 {
		if !ip.Is4() {
			continue
		}
		subnet := IPv4Subnet16(ip)
		members, ok := s.bySubnet16[subnet]
		if !ok {
			members = make(map[foundation.Hash]struct{}, 1)
			s.bySubnet16[subnet] = members
		}
		members[rec.Hash] = struct{}{}
	}
	if rec.Family != "" {
		members, ok := s.byFamily[rec.Family]
		if !ok {
			members = make(map[foundation.Hash]struct{}, 1)
			s.byFamily[rec.Family] = members
		}
		members[rec.Hash] = struct{}{}
	}
}

func (s *PeerStore) deindexPeerLocked(rec *PeerRecord) {
	for _, ip := range rec.IPv4 {
		if !ip.Is4() {
			continue
		}
		subnet := IPv4Subnet16(ip)
		if members, ok := s.bySubnet16[subnet]; ok {
			delete(members, rec.Hash)
			if len(members) == 0 {
				delete(s.bySubnet16, subnet)
			}
		}
	}
	if rec.Family != "" {
		if members, ok := s.byFamily[rec.Family]; ok {
			delete(members, rec.Hash)
			if len(members) == 0 {
				delete(s.byFamily, rec.Family)
			}
		}
	}
}

func (s *PeerStore) deletePeerLocked(hash foundation.Hash) {
	rec, found := s.peers[hash]
	if !found {
		return
	}
	s.deindexPeerLocked(rec)
	delete(s.peers, hash)
}

// eachContentionGroupLocked invokes fn on every member set rec competes in:
// one per IPv4 /16 subnet it occupies, plus its declared router family.
func (s *PeerStore) eachContentionGroupLocked(rec *PeerRecord, fn func(members map[foundation.Hash]struct{})) {
	for _, ip := range rec.IPv4 {
		if ip.Is4() {
			fn(s.bySubnet16[IPv4Subnet16(ip)])
		}
	}
	if rec.Family != "" {
		fn(s.byFamily[rec.Family])
	}
}

// topsAnyContentionLocked reports whether rec belongs to at least one
// contention group and whether it outranks every other member in at least one
// of them. A peer that tops no group loses every claim during selection.
func (s *PeerStore) topsAnyContentionLocked(rec *PeerRecord) (hasGroup, tops bool) {
	s.eachContentionGroupLocked(rec, func(members map[foundation.Hash]struct{}) {
		hasGroup = true
		if tops {
			return
		}
		top := true
		for h := range members {
			if h == rec.Hash {
				continue
			}
			if other, ok := s.peers[h]; ok && compareRetention(other, rec) < 0 {
				top = false
				break
			}
		}
		if top {
			tops = true
		}
	})
	return hasGroup, tops
}

// evictDominatedLocked drops co-members of rec's contention groups that no
// longer top any of their own groups after rec took their claim.
func (s *PeerStore) evictDominatedLocked(rec *PeerRecord) {
	seen := make(map[foundation.Hash]struct{})
	var evict []foundation.Hash
	s.eachContentionGroupLocked(rec, func(members map[foundation.Hash]struct{}) {
		for h := range members {
			if h == rec.Hash {
				continue
			}
			if _, dup := seen[h]; dup {
				continue
			}
			seen[h] = struct{}{}
			other, ok := s.peers[h]
			if !ok {
				continue
			}
			if hasGroup, tops := s.topsAnyContentionLocked(other); hasGroup && !tops {
				evict = append(evict, h)
			}
		}
	})
	for _, h := range evict {
		s.deletePeerLocked(h)
	}
}

// compareRetention orders peers by retention priority within a contention
// group, mirroring SelectDiversePeers: unconditionally selectable peers
// (stored descriptor and IPv4 presence) outrank unselectable ones, reachable
// peers outrank failing ones, then floodfill status, confirmed tunnel builds,
// composite score, latency, and hash break ties.
func compareRetention(a, b *PeerRecord) int {
	aViable := len(a.Raw) > 0 && len(a.IPv4) > 0
	bViable := len(b.Raw) > 0 && len(b.IPv4) > 0
	if aViable != bViable {
		if aViable {
			return -1
		}
		return 1
	}
	aReady := a.Stats.IsReachable && a.Stats.ConsecutiveFails < 2
	bReady := b.Stats.IsReachable && b.Stats.ConsecutiveFails < 2
	if aReady != bReady {
		if aReady {
			return -1
		}
		return 1
	}
	if a.IsFloodfill != b.IsFloodfill {
		if a.IsFloodfill {
			return -1
		}
		return 1
	}
	if a.Stats.TunnelBuildAccepted != b.Stats.TunnelBuildAccepted {
		if a.Stats.TunnelBuildAccepted {
			return -1
		}
		return 1
	}
	if a.Score != b.Score {
		return cmp.Compare(b.Score, a.Score)
	}
	if a.Stats.EWMARTT != b.Stats.EWMARTT {
		return cmp.Compare(a.Stats.EWMARTT, b.Stats.EWMARTT)
	}
	return bytes.Compare(a.Hash[:], b.Hash[:])
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
	return writeFileAtomic(filePath, data, 0600)
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
		if prev, found := s.peers[rec.Hash]; found {
			s.deindexPeerLocked(prev)
		}
		s.peers[rec.Hash] = rec
		s.indexPeerLocked(rec)
	}
	return nil
}

func calculateScore(rec *PeerRecord) float64 {
	// 1. Bayesian / Laplace smoothed uptime score (0 ~ 40 points)
	// Prevents single-probe cold-start 100% bias.
	smoothedRatio := float64(rec.Stats.SuccessProbes+1) / float64(rec.Stats.TotalProbes+2)
	score := smoothedRatio * 40.0

	// 2. Non-linear RTT decay score (0 ~ 25 points)
	// Hyperbolic decay maintains discrimination across high-latency cross-continental peers (>300ms).
	if rec.Stats.IsReachable && rec.Stats.EWMARTT > 0 {
		rttMs := float64(rec.Stats.EWMARTT.Milliseconds())
		latencyPts := 25.0 / (1.0 + (rttMs / 200.0))
		score += latencyPts
	}

	// 3. Accessible Floodfill priority bonus (+25 points)
	if rec.IsFloodfill {
		score += 25.0
	}

	// 4. RouterInfo Recency / Freshness bonus (0 ~ 10 points)
	// Prefers routers whose descriptors were published within the last 24 hours.
	if !rec.PublishedAt.IsZero() {
		hoursOld := time.Since(rec.PublishedAt).Hours()
		if hoursOld >= 0 && hoursOld < 24.0 {
			score += (1.0 - (hoursOld / 24.0)) * 10.0
		}
	}

	// 5. Dual-stack (IPv4 + IPv6) reachability bonus (+5 points)
	if len(rec.IPv4) > 0 && len(rec.IPv6) > 0 {
		score += 5.0
	}

	// 6. Confirmed Tunnel Build Acceptance bonus (+15 points)
	if rec.Stats.TunnelBuildAccepted {
		score += 15.0
	}

	// 7. Severe penalty for consecutive failures
	if rec.Stats.ConsecutiveFails > 0 {
		score -= float64(rec.Stats.ConsecutiveFails) * 15.0
	}

	if score < 0 {
		score = 0
	}
	return score
}

func extractRouterAddresses(info foundation.NetworkDatabaseRouterInfo) (string, []netip.Addr, []netip.Addr, []uint16, []uint16, []uint16) {
	family := extractFamily(info)
	var v4 []netip.Addr
	var v6 []netip.Addr
	var ports []uint16
	var tcpPorts []uint16
	var udpPorts []uint16

	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			break
		}
		ip, port := parseAddressEndpoint(address)
		if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is4() {
			v4 = append(v4, ip)
		} else if ip.Is6() {
			v6 = append(v6, ip)
		}
		if port > 0 {
			ports = append(ports, port)
			style := strings.ToUpper(string(address.TransportStyle))
			if strings.HasPrefix(style, "NTCP") {
				tcpPorts = append(tcpPorts, port)
			} else if strings.HasPrefix(style, "SSU") {
				udpPorts = append(udpPorts, port)
			}
		}
	}
	return family, v4, v6, ports, tcpPorts, udpPorts
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
