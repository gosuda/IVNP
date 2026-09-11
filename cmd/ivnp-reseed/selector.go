package main

import (
	"cmp"
	"net/netip"
	"slices"
)

type SelectorConfig struct {
	TargetCount          int
	MaxPerIPv4Subnet24   int
	MaxPerFamily         int
	RequireReachable     bool
	PreferFloodfillRatio float64 // e.g. 0.25 (25% target floodfills)
}

func DefaultSelectorConfig() SelectorConfig {
	return SelectorConfig{
		TargetCount:          1000,
		MaxPerIPv4Subnet24:   1,
		MaxPerFamily:         1,
		RequireReachable:     true,
		PreferFloodfillRatio: 0.25,
	}
}

// SelectDiversePeers performs K-Bucket stratified sampling with anti-Sybil IP diversity filters.
func SelectDiversePeers(peers []PeerRecord, cfg SelectorConfig) []PeerRecord {
	if cfg.TargetCount <= 0 {
		cfg.TargetCount = 1000
	}
	if cfg.MaxPerIPv4Subnet24 <= 0 {
		cfg.MaxPerIPv4Subnet24 = 1
	}
	if cfg.MaxPerFamily <= 0 {
		cfg.MaxPerFamily = 1
	}

	// Filter viable candidates
	var candidates []PeerRecord
	for _, p := range peers {
		if cfg.RequireReachable && (!p.Stats.IsReachable || p.Stats.ConsecutiveFails >= 2) {
			continue
		}
		if len(p.Raw) == 0 {
			continue
		}
		candidates = append(candidates, p)
	}

	if len(candidates) <= cfg.TargetCount && !cfg.RequireReachable {
		return candidates
	}

	// Group into 256 uniform DHT key-space buckets by first byte of Hash
	const numBuckets = 256
	buckets := make([][]PeerRecord, numBuckets)
	for _, p := range candidates {
		bucketIndex := int(p.Hash[0])
		buckets[bucketIndex] = append(buckets[bucketIndex], p)
	}

	// Sort peers inside each bucket by Floodfill flag, Score, and RTT
	for i := range buckets {
		slices.SortFunc(buckets[i], func(a, b PeerRecord) int {
			if a.IsFloodfill != b.IsFloodfill {
				if a.IsFloodfill {
					return -1
				}
				return 1
			}
			if a.Score != b.Score {
				return cmp.Compare(b.Score, a.Score) // higher score first
			}
			return cmp.Compare(a.Stats.EWMARTT, b.Stats.EWMARTT) // lower RTT first
		})
	}

	selected := make([]PeerRecord, 0, min(cfg.TargetCount, len(candidates)))
	selectedHashes := make(map[[32]byte]bool)
	seenSubnets := make(map[[3]byte]int)
	seenFamilies := make(map[string]int)

	canAccept := func(p PeerRecord) bool {
		if selectedHashes[p.Hash] {
			return false
		}
		if p.Family != "" && seenFamilies[p.Family] >= cfg.MaxPerFamily {
			return false
		}
		for _, ip := range p.IPv4 {
			if ip.Is4() {
				b := ip.As4()
				subnet := [3]byte{b[0], b[1], b[2]}
				if seenSubnets[subnet] >= cfg.MaxPerIPv4Subnet24 {
					return false
				}
			}
		}
		return true
	}

	recordAccept := func(p PeerRecord) {
		selected = append(selected, p)
		selectedHashes[p.Hash] = true
		if p.Family != "" {
			seenFamilies[p.Family]++
		}
		for _, ip := range p.IPv4 {
			if ip.Is4() {
				b := ip.As4()
				subnet := [3]byte{b[0], b[1], b[2]}
				seenSubnets[subnet]++
			}
		}
	}

	// Pass 1: Stratified allocation across all 256 K-Buckets
	// target per bucket = ceil(target / 256)
	targetPerBucket := (cfg.TargetCount + numBuckets - 1) / numBuckets
	bucketPointers := make([]int, numBuckets)

	for round := 0; round < targetPerBucket && len(selected) < cfg.TargetCount; round++ {
		progress := false
		for b := 0; b < numBuckets && len(selected) < cfg.TargetCount; b++ {
			for bucketPointers[b] < len(buckets[b]) {
				candidate := buckets[b][bucketPointers[b]]
				bucketPointers[b]++
				if canAccept(candidate) {
					recordAccept(candidate)
					progress = true
					break
				}
			}
		}
		if !progress {
			break
		}
	}

	// Pass 2: Fill remainder from any bucket with high-score candidates
	if len(selected) < cfg.TargetCount {
		var remaining []PeerRecord
		for b := 0; b < numBuckets; b++ {
			for idx := bucketPointers[b]; idx < len(buckets[b]); idx++ {
				remaining = append(remaining, buckets[b][idx])
			}
		}
		slices.SortFunc(remaining, func(a, b PeerRecord) int {
			return cmp.Compare(b.Score, a.Score)
		})
		for _, p := range remaining {
			if len(selected) >= cfg.TargetCount {
				break
			}
			if canAccept(p) {
				recordAccept(p)
			}
		}
	}

	// Pass 3: If still below target due to strict subnet filter, relax subnet filter
	if len(selected) < cfg.TargetCount {
		for _, p := range candidates {
			if len(selected) >= cfg.TargetCount {
				break
			}
			if !selectedHashes[p.Hash] {
				selected = append(selected, p)
				selectedHashes[p.Hash] = true
			}
		}
	}

	return selected
}

func IPv4Subnet24(addr netip.Addr) [3]byte {
	b := addr.As4()
	return [3]byte{b[0], b[1], b[2]}
}
