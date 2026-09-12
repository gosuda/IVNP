package main

import (
	"cmp"
	"net/netip"
	"slices"
)

type SelectorConfig struct {
	TargetCount          int
	MaxPerIPv4Subnet16   int
	MaxPerFamily         int
	RequireReachable     bool
	PreferFloodfillRatio float64 // target ratio for floodfills, e.g. 0.35 (35%)
	ExcludeIPv6Only      bool
}

func DefaultSelectorConfig() SelectorConfig {
	return SelectorConfig{
		TargetCount:          1024,
		MaxPerIPv4Subnet16:   1,
		MaxPerFamily:         1,
		RequireReachable:     true,
		PreferFloodfillRatio: 0.35,
		ExcludeIPv6Only:      true,
	}
}

// SelectDiversePeers performs K-Bucket stratified sampling prioritizing accessible Floodfill routers
// with strict bucket leveling to eliminate slot imbalances and Sybil /16 subnet filtering.
// IPv6-only peers are completely excluded so all reseed entries are accessible by IPv4 and dual-stack clients.
func SelectDiversePeers(peers []PeerRecord, cfg SelectorConfig) []PeerRecord {
	if cfg.TargetCount <= 0 {
		cfg.TargetCount = 1024
	}
	if cfg.MaxPerIPv4Subnet16 <= 0 {
		cfg.MaxPerIPv4Subnet16 = 1
	}
	if cfg.MaxPerFamily <= 0 {
		cfg.MaxPerFamily = 1
	}
	if cfg.PreferFloodfillRatio <= 0 {
		cfg.PreferFloodfillRatio = 0.35
	}

	// Filter viable candidates: if RequireReachable is set, must be verified directly reachable.
	// IPv6-only peers (no IPv4 address) are strictly excluded from reseed packages.
	var candidates []PeerRecord
	for _, p := range peers {
		if cfg.RequireReachable && (!p.Stats.IsReachable || p.Stats.ConsecutiveFails >= 2) {
			continue
		}
		if len(p.Raw) == 0 {
			continue
		}
		if len(p.IPv4) == 0 {
			continue
		}
		candidates = append(candidates, p)
	}

	if len(candidates) == 0 {
		return nil
	}

	// Group into 256 uniform DHT key-space buckets by first byte of Hash
	const numBuckets = 256
	buckets := make([][]PeerRecord, numBuckets)
	for _, p := range candidates {
		bucketIndex := int(p.Hash[0])
		buckets[bucketIndex] = append(buckets[bucketIndex], p)
	}

	// Sort peers in each bucket:
	// 1. Accessible Floodfills first
	// 2. Confirmed tunnel build acceptance
	// 3. Composite score (descending)
	// 4. EWMA RTT (ascending)
	sortBucket := func(bucket []PeerRecord) {
		slices.SortFunc(bucket, func(a, b PeerRecord) int {
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

	for i := range numBuckets {
		sortBucket(buckets[i])
	}

	selected := make([]PeerRecord, 0, min(cfg.TargetCount, len(candidates)))
	selectedHashes := make(map[[32]byte]bool)
	seenSubnets := make(map[[2]byte]int)
	seenFamilies := make(map[string]int)
	bucketCounts := make([]int, numBuckets)

	canAccept := func(p PeerRecord) bool {
		if selectedHashes[p.Hash] {
			return false
		}
		if p.Family != "" && seenFamilies[p.Family] >= cfg.MaxPerFamily {
			return false
		}
		for _, ip := range p.IPv4 {
			if ip.Is4() {
				subnet := IPv4Subnet16(ip)
				if seenSubnets[subnet] >= cfg.MaxPerIPv4Subnet16 {
					return false
				}
			}
		}
		return true
	}

	recordAccept := func(p PeerRecord) {
		selected = append(selected, p)
		selectedHashes[p.Hash] = true
		bucketCounts[p.Hash[0]]++
		if p.Family != "" {
			seenFamilies[p.Family]++
		}
		for _, ip := range p.IPv4 {
			if ip.Is4() {
				subnet := IPv4Subnet16(ip)
				seenSubnets[subnet]++
			}
		}
	}

	pointers := make([]int, numBuckets)

	pickNextInBucket := func(b int) (PeerRecord, bool) {
		for pointers[b] < len(buckets[b]) {
			candidate := buckets[b][pointers[b]]
			pointers[b]++
			if canAccept(candidate) {
				return candidate, true
			}
		}
		return PeerRecord{}, false
	}

	const maxPerBucket = 5

	// Leveling Pass & Soft Cap Overflow: Strict 1-peer-per-bucket rounds (up to max 5 per bucket)
	// Eliminates slot imbalance and prevents any single bucket from hoarding slots.
	for round := 1; round <= maxPerBucket && len(selected) < cfg.TargetCount; round++ {
		progress := false
		for b := 0; b < numBuckets && len(selected) < cfg.TargetCount; b++ {
			if bucketCounts[b] >= round {
				continue
			}
			if candidate, ok := pickNextInBucket(b); ok {
				recordAccept(candidate)
				progress = true
			}
		}
		if !progress {
			break
		}
	}

	// Relaxed Subnet Pass: If still below target, relax subnet filter but strictly
	// respect the maxPerBucket cap (5) and only select from viable candidates.
	// If RequireReachable is true, this still ONLY takes from verified reachable candidates.
	acceptRelaxedFromBucket := func(b int) {
		for _, candidate := range buckets[b] {
			if len(selected) >= cfg.TargetCount || bucketCounts[b] >= maxPerBucket {
				return
			}
			if !selectedHashes[candidate.Hash] {
				recordAccept(candidate)
			}
		}
	}
	if len(selected) < cfg.TargetCount {
		for b := 0; b < numBuckets && len(selected) < cfg.TargetCount; b++ {
			if bucketCounts[b] < maxPerBucket {
				acceptRelaxedFromBucket(b)
			}
		}
	}

	return StratifyByBucketDiversity(selected)
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
