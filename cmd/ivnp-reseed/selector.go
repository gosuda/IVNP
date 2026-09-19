package main

import (
	"bytes"
	"cmp"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"time"

	"gosuda.org/ivnp/foundation"
)

type SelectorConfig struct {
	TargetCount          int
	MaxPerSubnet         int // per IPv4 /16 or IPv6 /48 prefix
	MaxPerFamily         int
	PreferFloodfillRatio float64 // target ratio for floodfills, e.g. 0.5 (50%)
	ExcludeIPv6Only      bool
	MinBundlePeers       int
	MinProbeSamples      int64
	MinUptime            time.Duration
	MinProbeSuccessRate  float64
	// MaxInfoAge rejects RouterInfos whose Published timestamp is older than
	// the client-side reseed freshness window; MaxInfoFuture tolerates small
	// clock skew for future timestamps.
	MaxInfoAge    time.Duration
	MaxInfoFuture time.Duration
}

func DefaultSelectorConfig() SelectorConfig {
	return SelectorConfig{
		TargetCount:          1024,
		MaxPerSubnet:         1,
		MaxPerFamily:         1,
		PreferFloodfillRatio: 0.5,
		ExcludeIPv6Only:      true,
		MinBundlePeers:       10,
		MinProbeSamples:      2,
		MinUptime:            24 * time.Hour,
		MinProbeSuccessRate:  0.85,
		MaxInfoAge:           24 * time.Hour,
		MaxInfoFuture:        2 * time.Minute,
	}
}

// gateLevel is the deterministic relaxation ladder applied when the strict
// qualification gate yields fewer candidates than TargetCount, so a freshly
// deployed reseed can still serve a bundle while observations accumulate.
type gateLevel int

const (
	gateStrict         gateLevel = iota // v2 transport, windowed success >= MinProbeSuccessRate (85%), uptime >=24h
	gateNoUptime                        // drop the uptime requirement
	gateCumulativeRate                  // drop the windowed rate; cumulative success >= MinProbeSuccessRate
	gateReachable                       // reachability + at least one v2 transport only
)

// SelectionStats reports which pipeline level and coverage bounds a selection
// pass produced, for package stats and operator dashboards.
type SelectionStats struct {
	GateLevel     gateLevel
	Qualified     int
	DiversePool   int
	CoverageGapLZ int // min over selected peers of the longest shared prefix to any other selected peer; smaller = larger coverage gap
}

func (g gateLevel) String() string {
	switch g {
	case gateStrict:
		return "strict"
	case gateNoUptime:
		return "no-uptime"
	case gateCumulativeRate:
		return "cumulative-rate"
	case gateReachable:
		return "reachable"
	}
	return "unknown"
}

// SelectDiversePeers performs the four-stage reseed pipeline:
//  1. Hard qualification gate (v2 transports, probe success, uptime, reachable)
//  2. Subnet diversity gate (one representative per IPv4 /16 and IPv6 /48)
//  3. Max-Min XOR farthest-point sampling for uniform 256-bit keyspace coverage
//  4. First-byte bucket interleave so partial readers still see all regions
func SelectDiversePeers(peers []PeerRecord, cfg SelectorConfig) []PeerRecord {
	selected, _ := SelectDiversePeersWithStats(peers, cfg)
	return selected
}

func SelectDiversePeersWithStats(peers []PeerRecord, cfg SelectorConfig) ([]PeerRecord, SelectionStats) {
	if cfg.TargetCount <= 0 {
		cfg.TargetCount = 1024
	}
	if cfg.MaxPerSubnet <= 0 {
		cfg.MaxPerSubnet = 1
	}
	if cfg.MaxPerFamily <= 0 {
		cfg.MaxPerFamily = 1
	}
	if cfg.PreferFloodfillRatio <= 0 {
		cfg.PreferFloodfillRatio = 0.5
	}
	if cfg.MinProbeSamples <= 0 {
		cfg.MinProbeSamples = 2
	}
	if cfg.MinUptime <= 0 {
		cfg.MinUptime = 24 * time.Hour
	}
	if cfg.MinProbeSuccessRate <= 0 {
		cfg.MinProbeSuccessRate = 0.85
	}
	if cfg.MaxInfoAge <= 0 {
		cfg.MaxInfoAge = 24 * time.Hour
	}
	if cfg.MaxInfoFuture <= 0 {
		cfg.MaxInfoFuture = 2 * time.Minute
	}

	now := time.Now()

	// Stage 1: hard qualification with a deterministic relaxation ladder.
	var qualified []PeerRecord
	var lvl gateLevel
	for lvl = gateStrict; ; lvl++ {
		qualified = qualified[:0]
		for i := range peers {
			if qualify(&peers[i], lvl, now, &cfg) {
				qualified = append(qualified, peers[i])
			}
		}
		if len(qualified) >= cfg.TargetCount || lvl == gateReachable {
			break
		}
	}
	if len(qualified) == 0 {
		return nil, SelectionStats{GateLevel: lvl}
	}

	// Stage 2: subnet diversity gate. Highest-quality candidate per IPv4 /16
	// or IPv6 /48 claims the prefix; family caps are retained.
	slices.SortFunc(qualified, func(a, b PeerRecord) int {
		if c := cmp.Compare(qualityScore(&b, now), qualityScore(&a, now)); c != 0 {
			return c
		}
		return bytes.Compare(a.Hash[:], b.Hash[:])
	})
	seenSubnets := make(map[subnetKey]struct{})
	seenFamilies := make(map[string]int)
	pool := make([]PeerRecord, 0, min(len(qualified), cfg.TargetCount*2))
	for _, p := range qualified {
		keys := subnetKeys(p)
		blocked := false
		for _, k := range keys {
			if _, ok := seenSubnets[k]; ok {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		if p.Family != "" && seenFamilies[p.Family] >= cfg.MaxPerFamily {
			continue
		}
		for _, k := range keys {
			seenSubnets[k] = struct{}{}
		}
		if p.Family != "" {
			seenFamilies[p.Family]++
		}
		pool = append(pool, p)
	}
	if len(pool) == 0 {
		return nil, SelectionStats{GateLevel: lvl, Qualified: len(qualified)}
	}
	stats := SelectionStats{GateLevel: lvl, Qualified: len(qualified), DiversePool: len(pool)}
	if len(pool) <= cfg.TargetCount {
		stats.CoverageGapLZ = coverageGapLZ(pool)
		return StratifyByBucketDiversity(pool), stats
	}

	// Stage 3: Max-Min XOR farthest-point sampling.
	selected := farthestPointSample(pool, cfg, now)
	stats.CoverageGapLZ = coverageGapLZ(selected)

	// Stage 4: interleave across first-byte buckets for partial readers.
	return StratifyByBucketDiversity(selected), stats
}

// coverageGapLZ is the worst-case coverage proxy over a peer set: for each
// peer, the longest shared prefix with any sibling (its nearest neighbor in
// XOR space); the minimum over peers bounds the largest uncovered gap.
func coverageGapLZ(peers []PeerRecord) int {
	if len(peers) < 2 {
		return foundation.HashLength * 8
	}
	gap := foundation.HashLength * 8
	for i := range peers {
		nearest := 0
		for j := range peers {
			if i == j {
				continue
			}
			if lz := leadingZerosXOR(peers[i].Hash, peers[j].Hash); lz > nearest {
				nearest = lz
			}
		}
		if nearest < gap {
			gap = nearest
		}
	}
	return gap
}

// qualify reports whether a peer passes the hard gate at the given relaxation
// level. A dialable v2 transport (NTCP2 or SSU2 with host:port) is required at
// every level, and stale RouterInfos are rejected outright since clients drop
// them anyway; probe success and uptime requirements relax down the ladder.
func qualify(p *PeerRecord, lvl gateLevel, now time.Time, cfg *SelectorConfig) bool {
	if len(p.Raw) == 0 || (!p.HasNTCP2 && !p.HasSSU2) {
		return false
	}
	if !p.PublishedAt.IsZero() {
		if age := now.Sub(p.PublishedAt); age > cfg.MaxInfoAge || age < -cfg.MaxInfoFuture {
			return false
		}
	}
	if cfg.ExcludeIPv6Only && len(p.IPv4) == 0 {
		return false
	}
	if lvl == gateReachable {
		return p.Stats.IsReachable && p.Stats.ConsecutiveFails < 2
	}
	if lvl < gateNoUptime && now.Sub(p.Stats.FirstSeen) < cfg.MinUptime {
		return false
	}
	if lvl < gateCumulativeRate && p.Stats.WinProbes >= cfg.MinProbeSamples &&
		float64(p.Stats.WinSuccess)/float64(p.Stats.WinProbes) < cfg.MinProbeSuccessRate {
		return false
	}
	if p.Stats.TotalProbes > 0 &&
		float64(p.Stats.SuccessProbes)/float64(p.Stats.TotalProbes) < cfg.MinProbeSuccessRate {
		return false
	}
	return p.Stats.IsReachable && p.Stats.ConsecutiveFails < 2
}

// qualityScore orders candidates for the subnet gate and the FPS anchor:
// Score = (SuccessRate / max(RTT_ms, 1)) * ln(1 + Uptime_hours).
func qualityScore(p *PeerRecord, now time.Time) float64 {
	probes, successes := p.Stats.WinProbes, p.Stats.WinSuccess
	if probes < 2 {
		probes, successes = p.Stats.TotalProbes, p.Stats.SuccessProbes
	}
	rate := float64(successes+1) / float64(probes+2)
	rtt := math.Max(float64(p.Stats.EWMARTT.Milliseconds()), 1.0)
	uptime := math.Max(now.Sub(p.Stats.FirstSeen).Hours(), 0)
	return (rate / rtt) * math.Log1p(uptime)
}

// subnetKey discriminates IPv4 /16 and IPv6 /48 prefixes in one map.
type subnetKey [9]byte // [0] = '4'|'6', [1:] = prefix bytes

func subnetKeys(p PeerRecord) []subnetKey {
	keys := make([]subnetKey, 0, len(p.IPv4)+len(p.IPv6))
	for _, ip := range p.IPv4 {
		if !ip.Is4() {
			continue
		}
		b := ip.As4()
		keys = append(keys, subnetKey{'4', b[0], b[1]})
	}
	for _, ip := range p.IPv6 {
		if !ip.Is6() {
			continue
		}
		b := ip.As16()
		keys = append(keys, subnetKey{'6', b[0], b[1], b[2], b[3], b[4], b[5]})
	}
	return keys
}

// leadingZerosXOR returns the shared prefix length of two 256-bit hashes; the
// inverse of XOR distance. Equal hashes return 256.
func leadingZerosXOR(a, b foundation.Hash) int {
	for i := range a {
		if d := a[i] ^ b[i]; d != 0 {
			return i*8 + bits.LeadingZeros8(d)
		}
	}
	return foundation.HashLength * 8
}

// farthestPointSample greedily picks K peers maximizing the minimum XOR
// distance to the already-selected set. Floodfills are prioritized: the anchor
// is the top-quality floodfill and the floodfill quota is filled first, then
// remaining slots draw from the whole pool so the worst-case covering radius
// stays minimal. Each candidate tracks only its max shared-prefix length to
// the selected set, updated incrementally per pick for O(K*N) total cost.
func farthestPointSample(pool []PeerRecord, cfg SelectorConfig, now time.Time) []PeerRecord {
	k := min(cfg.TargetCount, len(pool))
	used := make([]bool, len(pool))
	maxLZ := make([]int, len(pool))
	for i := range maxLZ {
		maxLZ[i] = -1
	}
	scores := make([]float64, len(pool))
	for i := range pool {
		scores[i] = qualityScore(&pool[i], now)
	}

	selected := make([]int, 0, k)
	commit := func(i int) {
		selected = append(selected, i)
		used[i] = true
		for j := range pool {
			if used[j] {
				continue
			}
			if lz := leadingZerosXOR(pool[j].Hash, pool[i].Hash); lz > maxLZ[j] {
				maxLZ[j] = lz
			}
		}
	}
	// Candidate order: smaller max shared prefix (farther), floodfills at
	// equal distance, then lower RTT, then higher quality, then hash.
	better := func(a, b int) bool {
		if maxLZ[a] != maxLZ[b] {
			return maxLZ[a] < maxLZ[b]
		}
		if pool[a].IsFloodfill != pool[b].IsFloodfill {
			return pool[a].IsFloodfill
		}
		if pool[a].Stats.EWMARTT != pool[b].Stats.EWMARTT {
			return pool[a].Stats.EWMARTT < pool[b].Stats.EWMARTT
		}
		if scores[a] != scores[b] {
			return scores[a] > scores[b]
		}
		return bytes.Compare(pool[a].Hash[:], pool[b].Hash[:]) < 0
	}
	pick := func(eligible func(i int) bool) int {
		best := -1
		for i := range pool {
			if used[i] || !eligible(i) {
				continue
			}
			if best == -1 || better(i, best) {
				best = i
			}
		}
		return best
	}

	isFloodfill := func(i int) bool { return pool[i].IsFloodfill }
	anyPeer := func(int) bool { return true }

	// Anchor: highest-quality floodfill when any exist, else highest quality.
	anchorEligible := anyPeer
	if slices.ContainsFunc(pool, func(p PeerRecord) bool { return p.IsFloodfill }) {
		anchorEligible = isFloodfill
	}
	anchor := -1
	for i := range pool {
		if !anchorEligible(i) {
			continue
		}
		if anchor == -1 || scores[i] > scores[anchor] {
			anchor = i
		}
	}
	commit(anchor)
	floodfills := 0
	if pool[anchor].IsFloodfill {
		floodfills = 1
	}

	// Phase 1: floodfill quota.
	ffTarget := int(math.Round(float64(k) * cfg.PreferFloodfillRatio))
	for floodfills < ffTarget && len(selected) < k {
		i := pick(isFloodfill)
		if i < 0 {
			break
		}
		commit(i)
		if pool[i].IsFloodfill {
			floodfills++
		}
	}
	// Phase 2: remaining slots from the whole pool (floodfills may exceed
	// their quota here when the rest of the pool is exhausted).
	for len(selected) < k {
		i := pick(anyPeer)
		if i < 0 {
			break
		}
		commit(i)
	}

	out := make([]PeerRecord, len(selected))
	for n, i := range selected {
		out[n] = pool[i]
	}
	return out
}

// StratifyByBucketDiversity organizes peers so that the first up to 256 entries
// each belong to a distinct DHT key-space bucket (Hash[0]), prioritizing
// accessible Floodfill routers with top scores.
// This is critical for Java I2P clients that only parse the first ~200 router
// infos from a reseed archive, ensuring they receive a uniform DHT keyspace distribution.
func StratifyByBucketDiversity(peers []PeerRecord) []PeerRecord {
	if len(peers) <= 1 {
		return peers
	}
	const numBuckets = 256
	buckets := make([][]PeerRecord, numBuckets)
	for _, p := range peers {
		bucket := int(p.Hash[0])
		buckets[bucket] = append(buckets[bucket], p)
	}

	for i := range numBuckets {
		slices.SortFunc(buckets[i], func(a, b PeerRecord) int {
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
			return cmp.Compare(a.Stats.EWMARTT, b.Stats.EWMARTT)
		})
	}

	result := make([]PeerRecord, 0, len(peers))
	pointers := make([]int, numBuckets)

	// Round-robin across all 256 buckets
	for len(result) < len(peers) {
		added := false
		for b := 0; b < numBuckets; b++ {
			if pointers[b] < len(buckets[b]) {
				result = append(result, buckets[b][pointers[b]])
				pointers[b]++
				added = true
			}
		}
		if !added {
			break
		}
	}

	return result
}

func IPv4Subnet16(addr netip.Addr) [2]byte {
	b := addr.As4()
	return [2]byte{b[0], b[1]}
}

func IPv4Subnet24(addr netip.Addr) [3]byte {
	b := addr.As4()
	return [3]byte{b[0], b[1], b[2]}
}
