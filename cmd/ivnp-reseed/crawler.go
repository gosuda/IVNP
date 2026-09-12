package main

import (
	"context"
	"crypto/rand"
	"errors"

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

// Harvest extracts all verified RouterInfos currently admitted in the embedded router's NetDB.
func (c *ActiveCrawler) Harvest(subsystem *node.Subsystem) int {
	if subsystem == nil {
		return 0
	}
	refs := subsystem.NetDBRoutersSnapshot()
	return c.HarvestRefs(refs)
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
		maxQueries = 16
	}

	dist := c.store.BucketDistribution()

	var emptyBuckets []int
	var sparseBuckets []int
	for b := 0; b < 256; b++ {
		if dist[b] == 0 {
			emptyBuckets = append(emptyBuckets, b)
		} else if dist[b] < 4 {
			sparseBuckets = append(sparseBuckets, b)
		}
	}

	dispatched := 0

	// 1. Priority 1: Fill completely empty buckets via prefix tree exploration
	for _, b := range emptyBuckets {
		if dispatched >= maxQueries || ctx.Err() != nil {
			break
		}
		for _, subBranch := range []byte{0x00, 0x80} {
			if dispatched >= maxQueries || ctx.Err() != nil {
				break
			}
			target := generatePrefixTarget(byte(b), subBranch)
			err := subsystem.TriggerExplore(ctx, target)
			if err != nil {
				if errors.Is(err, controlplane.NetworkDatabaseErrRequestManagerFull) ||
					errors.Is(err, controlplane.NetworkDatabaseErrNoFloodfill) {
					return dispatched, nil
				}
				continue
			}
			dispatched++
		}
	}

	// 2. Priority 2: Fortify sparse buckets
	for _, b := range sparseBuckets {
		if dispatched >= maxQueries || ctx.Err() != nil {
			break
		}
		target := generatePrefixTarget(byte(b), 0x00)
		err := subsystem.TriggerExplore(ctx, target)
		if err != nil {
			if errors.Is(err, controlplane.NetworkDatabaseErrRequestManagerFull) ||
				errors.Is(err, controlplane.NetworkDatabaseErrNoFloodfill) {
				return dispatched, nil
			}
			continue
		}
		dispatched++
	}

	// 3. Priority 3: Full-keyspace uniform random exploration if budget remains
	for dispatched < maxQueries && ctx.Err() == nil {
		var target foundation.Hash
		if _, err := rand.Read(target[:]); err != nil {
			break
		}
		err := subsystem.TriggerExplore(ctx, target)
		if err != nil {
			if errors.Is(err, controlplane.NetworkDatabaseErrRequestManagerFull) ||
				errors.Is(err, controlplane.NetworkDatabaseErrNoFloodfill) {
				break
			}
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
