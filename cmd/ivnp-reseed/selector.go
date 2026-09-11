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
	PreferFloodfillRatio float64 // target ratio for floodfills, e.g. 0.35 (35%)
}

func DefaultSelectorConfig() SelectorConfig {
	return SelectorConfig{
		TargetCount:          1000,
		MaxPerIPv4Subnet24:   1,
		MaxPerFamily:         1,
		RequireReachable:     true,
		PreferFloodfillRatio: 0.35,
	}
}

// SelectDiversePeers performs K-Bucket stratified sampling prioritizing accessible Floodfill routers.
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
	if cfg.PreferFloodfillRatio <= 0 {
		cfg.PreferFloodfillRatio = 0.35
	}

	// Filter viable candidates: must be directly reachable and not in consecutive failure
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
	floodfillBuckets := make([][]PeerRecord, numBuckets)
	standardBuckets := make([][]PeerRecord, numBuckets)

	for _, p := range candidates {
		bucketIndex := int(p.Hash[0])
		if p.IsFloodfill {
			floodfillBuckets[bucketIndex] = append(floodfillBuckets[bucketIndex], p)
		} else {
			standardBuckets[bucketIndex] = append(standardBuckets[bucketIndex], p)
		}
	}

	// Sort peers in each bucket by Score (descending) then RTT (ascending)
	sortBucket := func(bucket []PeerRecord) {
		slices.SortFunc(bucket, func(a, b PeerRecord) int {
			if a.Score != b.Score {
				return cmp.Compare(b.Score, a.Score)
			}
			return cmp.Compare(a.Stats.EWMARTT, b.Stats.EWMARTT)
		})
	}

	for i := range numBuckets {
		sortBucket(floodfillBuckets[i])
		sortBucket(standardBuckets[i])
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
				subnet := IPv4Subnet24(ip)
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
				subnet := IPv4Subnet24(ip)
				seenSubnets[subnet]++
			}
		}
	}

	// Target floodfill slots
	targetFloodfills := int(float64(cfg.TargetCount) * cfg.PreferFloodfillRatio)
	floodfillPointers := make([]int, numBuckets)
	standardPointers := make([]int, numBuckets)

	// Pass 1: Prioritize Accessible Floodfills across all 256 K-Buckets
	floodfillsPicked := 0
	for round := 0; round < 4 && floodfillsPicked < targetFloodfills && len(selected) < cfg.TargetCount; round++ {
		progress := false
		for b := 0; b < numBuckets && floodfillsPicked < targetFloodfills && len(selected) < cfg.TargetCount; b++ {
			for floodfillPointers[b] < len(floodfillBuckets[b]) {
				candidate := floodfillBuckets[b][floodfillPointers[b]]
				floodfillPointers[b]++
				if canAccept(candidate) {
					recordAccept(candidate)
					floodfillsPicked++
					progress = true
					break
				}
			}
		}
		if !progress {
			break
		}
	}

	// Pass 2: Fill general slots evenly across 256 K-Buckets
	for round := 0; round < 4 && len(selected) < cfg.TargetCount; round++ {
		progress := false
		for b := 0; b < numBuckets && len(selected) < cfg.TargetCount; b++ {
			// Try floodfills first, then standard peers
			accepted := false
			for floodfillPointers[b] < len(floodfillBuckets[b]) {
				candidate := floodfillBuckets[b][floodfillPointers[b]]
				floodfillPointers[b]++
				if canAccept(candidate) {
					recordAccept(candidate)
					progress = true
					accepted = true
					break
				}
			}
			if accepted {
				continue
			}
			for standardPointers[b] < len(standardBuckets[b]) {
				candidate := standardBuckets[b][standardPointers[b]]
				standardPointers[b]++
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

	// Pass 3: Fill any remaining quota from candidates with highest scores
	if len(selected) < cfg.TargetCount {
		var remaining []PeerRecord
		for b := 0; b < numBuckets; b++ {
			for idx := floodfillPointers[b]; idx < len(floodfillBuckets[b]); idx++ {
				remaining = append(remaining, floodfillBuckets[b][idx])
			}
			for idx := standardPointers[b]; idx < len(standardBuckets[b]); idx++ {
				remaining = append(remaining, standardBuckets[b][idx])
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

	// Pass 4: If still below target, relax subnet filter for reachable peers
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
