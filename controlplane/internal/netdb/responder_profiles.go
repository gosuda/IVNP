package netdb

import (
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

const (
	defaultResponderProfilePeers = 64
	maxResponderProfilePeers     = 1024
	responderProfileMaxAgeMillis = uint64(24 * time.Hour / time.Millisecond)
)

type ResponderProfilesConfig struct {
	MaxPeers int
	Now      func() uint64
}

type responderObservation struct {
	peer    foundation.Hash
	seenAt  uint64
	seeded  bool
	success bool
}

// ResponderProfiles holds ranking hints, not authority to admit or contact a peer.
// Static seeds share the capacity bound but are never persisted as successes.
type ResponderProfiles struct {
	mu       sync.Mutex
	maxPeers int
	now      func() uint64
	peers    map[foundation.Hash]responderObservation
	order    []foundation.Hash
	next     uint64
}

func NewResponderProfiles(config ResponderProfilesConfig) *ResponderProfiles {
	if config.MaxPeers <= 0 {
		config.MaxPeers = defaultResponderProfilePeers
	}
	config.MaxPeers = min(config.MaxPeers, maxResponderProfilePeers)
	if config.Now == nil {
		config.Now = func() uint64 { return uint64(time.Now().UnixMilli()) }
	}
	return &ResponderProfiles{
		maxPeers: config.MaxPeers,
		now:      config.Now,
		peers:    make(map[foundation.Hash]responderObservation, config.MaxPeers),
		order:    make([]foundation.Hash, 0, config.MaxPeers),
	}
}

// Record records a reply attributed to a queried peer by the authenticated reply path.
func (p *ResponderProfiles) Record(peer foundation.Hash) {
	if p == nil || peer == (foundation.Hash{}) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.expireLocked(now)
	p.recordLocked(responderObservation{peer: peer, seenAt: now, success: true})
}

func (p *ResponderProfiles) Seed(peer foundation.Hash) {
	if p == nil || peer == (foundation.Hash{}) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(p.now())
	if observation, exists := p.peers[peer]; exists {
		observation.seeded = true
		p.peers[peer] = observation
	} else {
		p.recordLocked(responderObservation{peer: peer, seeded: true})
	}
}

func (p *ResponderProfiles) recordLocked(observation responderObservation) {
	if previous, exists := p.peers[observation.peer]; exists {
		if previous.success && (!observation.success || previous.seenAt > observation.seenAt) {
			return
		}
		observation.seeded = observation.seeded || previous.seeded
		for index, peer := range p.order {
			if peer == observation.peer {
				p.order = append(p.order[:index], p.order[index+1:]...)
				break
			}
		}
	} else if len(p.order) == p.maxPeers {
		delete(p.peers, p.order[0])
		p.order = append(p.order[:0], p.order[1:]...)
	}
	p.peers[observation.peer] = observation
	p.order = append(p.order, observation.peer)
}

func responderObservationFresh(seenAt, now uint64) bool {
	return seenAt <= now && now-seenAt < responderProfileMaxAgeMillis
}

func (p *ResponderProfiles) expireLocked(now uint64) {
	kept := p.order[:0]
	for _, peer := range p.order {
		observation := p.peers[peer]
		if observation.success && !responderObservationFresh(observation.seenAt, now) {
			if !observation.seeded {
				delete(p.peers, peer)
				continue
			}
			p.peers[peer] = responderObservation{peer: peer, seeded: true}
		}
		kept = append(kept, peer)
	}
	p.order = kept
}

// Responsive reports fresh observed success, independently of current RI eligibility.
func (p *ResponderProfiles) Responsive(peer foundation.Hash) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(p.now())
	return p.peers[peer].success
}

// Candidates rotates eligible hints into the free capacity of dst. Table entries
// have already passed signature verification; freshness must be checked again.
func (p *ResponderProfiles) Candidates(dst []foundation.Hash, database *Database) []foundation.Hash {
	if p == nil || database == nil || len(dst) == cap(dst) {
		return dst
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.expireLocked(now)
	if len(p.order) == 0 {
		return dst
	}
	start := int(p.next % uint64(len(p.order)))
	for offset := 0; offset < len(p.order) && len(dst) < cap(dst); offset++ {
		index := (start + offset) % len(p.order)
		peer := p.order[len(p.order)-1-index]
		p.next = uint64(index + 1)
		if responderEligible(database, peer, now) {
			dst = append(dst, peer)
		}
	}
	return dst
}

func responderEligible(database *Database, peer foundation.Hash, now uint64) bool {
	ref, known := database.Routers().Get(peer)
	return known && responderRefEligible(ref, now)
}

func responderRefEligible(ref RouterRef, now uint64) bool {
	return ref.Floodfill && len(ref.Info.Bytes()) != 0 && RouterInfoFresh(ref.Info, now) == nil
}

func (p *ResponderProfiles) snapshot(now uint64) []responderObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	observations := make([]responderObservation, 0, len(p.order))
	for _, peer := range p.order {
		if observation := p.peers[peer]; observation.success {
			observations = append(observations, observation)
		}
	}
	return observations
}
