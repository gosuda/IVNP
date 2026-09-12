package main

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/node"
)

// ActiveCrawler harvests live, verified RouterInfos directly from the embedded router's NetDB
// and actively conducts targeted DHT tree exploration to fill empty K-Buckets.
type ActiveCrawler struct {
	store *PeerStore
}

func NewActiveCrawler(store *PeerStore) *ActiveCrawler {
	return &ActiveCrawler{store: store}
}

// Harvest extracts all verified RouterInfos currently admitted in the embedded router's NetDB
// and ingests active tunnel hops to record confirmed tunnel build acceptances.
func (c *ActiveCrawler) Harvest(subsystem *node.Subsystem) int {
	if subsystem == nil {
		return 0
	}
	localHash := subsystem.Hash()
	c.store.SetLocalHash(localHash)

	// Continuous turnover: prune stale peers when approaching capacity limit
	if c.store.Len() >= MaxStorePeers-100 {
		c.store.PruneStale(24 * time.Hour)
	}

	refs := subsystem.NetDBRoutersSnapshot()
	admitted := 0
	for _, ref := range refs {
		if ref.Info.Hash() == localHash {
			continue
		}
		raw := ref.Info.Bytes()
		if len(raw) == 0 {
			continue
		}
		if _, isNew := c.store.AddOrUpdateWithSeen(ref.Info, raw, ref.LastSeen); isNew {
			admitted++
		}
	}

	// Record confirmed tunnel build acceptance for hops in active tunnels
	for _, snap := range subsystem.TunnelEntriesSnapshot() {
		entry := snap.Entry
		if entry.Gateway != (foundation.Hash{}) && entry.Gateway != localHash {
			c.store.RecordTunnelBuildResult(entry.Gateway, true)
		}
		for i := 0; i < int(entry.HopCount) && i < len(entry.Hops); i++ {
			hop := entry.Hops[i]
			if hop != (foundation.Hash{}) && hop != localHash {
				c.store.RecordTunnelBuildResult(hop, true)
			}
		}
	}
	return admitted
}

// HarvestRefs admits a slice of RouterRefs into the store with observed reachability.
func (c *ActiveCrawler) HarvestRefs(refs []controlplane.NetworkDatabaseRouterRef) int {
	admitted := 0
	for _, ref := range refs {
		raw := ref.Info.Bytes()
		if len(raw) == 0 {
			continue
		}
		if _, isNew := c.store.AddOrUpdateWithSeen(ref.Info, raw, ref.LastSeen); isNew {
			admitted++
		}
	}
	return admitted
}

// TreeExplore inspects all 256 DHT key-space buckets, identifies empty or sparse
// buckets, and dispatches targeted exploratory lookups down the DHT prefix tree
// to discover floodfills and routers within those exact keyspace prefixes.
func (c *ActiveCrawler) TreeExplore(ctx context.Context, subsystem *node.Subsystem, maxQueries int) (int, error) {
	if subsystem == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if maxQueries <= 0 {
		maxQueries = 32
	}

	emptyBuckets, severeDeficit, moderateDeficit, minorDeficit := c.categorizeDeficits()

	dispatched := 0
	var cont bool
	var err error

	// 1. Priority 1: 4-way quadrant exploration for completely empty buckets (0 total peers)
	dispatched, cont, err = c.exploreBucketBranches(ctx, subsystem, emptyBuckets, []byte{0x00, 0x40, 0x80, 0xC0}, dispatched, maxQueries)
	if !cont {
		return dispatched, err
	}

	// 2. Priority 2: 2-way exploration for severe deficit buckets (0 reachable peers)
	dispatched, cont, err = c.exploreBucketBranches(ctx, subsystem, severeDeficit, []byte{0x00, 0x80}, dispatched, maxQueries)
	if !cont {
		return dispatched, err
	}

	// 3. Priority 3: Single lookup for moderate deficit (1 reachable peer)
	dispatched, cont, err = c.exploreBucketBranches(ctx, subsystem, moderateDeficit, []byte{0x00}, dispatched, maxQueries)
	if !cont {
		return dispatched, err
	}

	// 4. Priority 4: Minor deficit (2-3 reachable peers)
	dispatched, cont, err = c.exploreBucketBranches(ctx, subsystem, minorDeficit, []byte{0x00}, dispatched, maxQueries)
	if !cont {
		return dispatched, err
	}

	// 5. Priority 5: Full-keyspace uniform random exploration only if budget still remains
	for dispatched < maxQueries && ctx.Err() == nil {
		var target foundation.Hash
		if _, err := rand.Read(target[:]); err != nil {
			break
		}
		err := subsystem.TriggerExplore(ctx, target)
		if err != nil {
			break
		}
		dispatched++
	}

	return dispatched, nil
}

func generatePrefixTarget(prefix byte, subBranch byte) foundation.Hash {
	var target foundation.Hash
	target[0] = prefix
	_, _ = rand.Read(target[1:])
	if subBranch != 0 {
		target[1] |= subBranch
	} else {
		target[1] &^= 0x80
	}
	return target
}

func (c *ActiveCrawler) exploreBucketBranches(ctx context.Context, subsystem *node.Subsystem, buckets []int, branches []byte, dispatched, maxQueries int) (int, bool, error) {
	for _, b := range buckets {
		for _, branch := range branches {
			if dispatched >= maxQueries || ctx.Err() != nil {
				return dispatched, false, ctx.Err()
			}
			target := generatePrefixTarget(byte(b), branch)
			if err := subsystem.TriggerExplore(ctx, target); err != nil {
				if errors.Is(err, controlplane.NetworkDatabaseErrRequestManagerFull) ||
					errors.Is(err, controlplane.NetworkDatabaseErrNoFloodfill) {
					return dispatched, false, nil
				}
				continue
			}
			dispatched++
		}
	}
	return dispatched, true, nil
}

func (c *ActiveCrawler) categorizeDeficits() (empty, severe, moderate, minor []int) {
	dist := c.store.BucketDistribution()
	reachableDist := c.store.ReachableBucketDistribution()

	for b := 0; b < 256; b++ {
		switch {
		case dist[b] == 0:
			empty = append(empty, b)
		case reachableDist[b] == 0:
			severe = append(severe, b)
		case reachableDist[b] == 1:
			moderate = append(moderate, b)
		case reachableDist[b] < 4:
			minor = append(minor, b)
		}
	}
	return empty, severe, moderate, minor
}
