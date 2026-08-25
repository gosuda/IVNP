package netdb

import (
	ivnp "gosuda.org/ivnp/i2p"
	"sync"
)

const defaultResponderProfilePeers = 64

// ResponderProfiles retains a bounded, recency-ordered set of floodfills that
// either returned an authenticated DatabaseLookup reply or were explicitly
// configured as bootstrap peers. Sharing it across destination request
// managers prevents each destination from spending its five-query budget on an
// entirely unproven peer set.
type ResponderProfiles struct {
	mu       sync.RWMutex
	maxPeers int
	peers    map[ivnp.Hash]struct{}
	order    []ivnp.Hash
}

func NewResponderProfiles(maxPeers int) *ResponderProfiles {
	if maxPeers <= 0 {
		maxPeers = defaultResponderProfilePeers
	}
	return &ResponderProfiles{
		maxPeers: maxPeers,
		peers:    make(map[ivnp.Hash]struct{}, maxPeers),
		order:    make([]ivnp.Hash, 0, maxPeers),
	}
}

// Record marks peer as a preferred lookup seed and refreshes its recency entry.
func (p *ResponderProfiles) Record(peer ivnp.Hash) {
	if p == nil || peer == (ivnp.Hash{}) {
		return
	}
	p.mu.Lock()
	if _, exists := p.peers[peer]; exists {
		for index := range p.order {
			if p.order[index] == peer {
				copy(p.order[index:], p.order[index+1:])
				p.order = p.order[:len(p.order)-1]
				break
			}
		}
	} else {
		if len(p.order) == p.maxPeers {
			delete(p.peers, p.order[0])
			copy(p.order, p.order[1:])
			p.order = p.order[:len(p.order)-1]
		}
		p.peers[peer] = struct{}{}
	}
	p.order = append(p.order, peer)
	p.mu.Unlock()
}

// Responsive reports whether peer is a preferred lookup seed.
func (p *ResponderProfiles) Responsive(peer ivnp.Hash) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	_, ok := p.peers[peer]
	p.mu.RUnlock()
	return ok
}

// Candidates appends up to the free capacity in dst, newest seed first.
func (p *ResponderProfiles) Candidates(dst []ivnp.Hash) []ivnp.Hash {
	if p == nil || len(dst) == cap(dst) {
		return dst
	}
	p.mu.RLock()
	for index := len(p.order) - 1; index >= 0 && len(dst) < cap(dst); index-- {
		dst = append(dst, p.order[index])
	}
	p.mu.RUnlock()
	return dst
}
