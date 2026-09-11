package main

import (
	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/node"
)

// ActiveCrawler harvests live, verified RouterInfos directly from the embedded router's NetDB memory table.
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

// HarvestRefs admits a slice of RouterRefs into the store.
func (c *ActiveCrawler) HarvestRefs(refs []controlplane.NetworkDatabaseRouterRef) int {
	admitted := 0
	for _, ref := range refs {
		raw := ref.Info.Bytes()
		if len(raw) == 0 {
			continue
		}
		if _, isNew := c.store.AddOrUpdate(ref.Info, raw); isNew {
			admitted++
		}
	}
	return admitted
}
