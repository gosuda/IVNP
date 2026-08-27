package tunnel

import (
	"errors"
	"sort"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

var (
	ErrTunnelID  = errors.New("tunnel: invalid or duplicate tunnel ID")
	ErrPoolFull  = errors.New("tunnel: pool is full")
	ErrPoolOwner = errors.New("tunnel: circuit owner does not match pool")
)

type Direction uint8

const (
	Inbound Direction = iota
	Outbound
)

type Entry struct {
	ID        uint32
	Direction Direction
	Expires   uint64
	// Owner is immutable creator identity. A zero owner is reserved for
	// router exploratory/transit creator circuits.
	Owner foundation.Hash
	// Gateway and GatewayTunnelID identify the first hop of an inbound tunnel
	// and its receive-tunnel namespace. ID remains the creator's local circuit.
	Gateway         foundation.Hash
	GatewayTunnelID uint32
	// Hops is immutable creator-path metadata used only by bounded health
	// accounting. It avoids retaining a caller-owned slice in the pool.
	HopCount uint8
	Hops     [i2np.MaxVariableBuildRecords]foundation.Hash
}

// Pool stores active tunnel descriptors with capacity bounds and expiration tracking.
type Pool struct {
	mu      sync.RWMutex
	max     int
	owner   foundation.Hash
	tunnels map[uint32]Entry
}

func NewPool(max int) *Pool { return NewOwnedPool(foundation.Hash{}, max) }

// NewOwnedPool creates a Pool owned by the given Destination hash (or zero for router exploratory).
func NewOwnedPool(owner foundation.Hash, max int) *Pool {
	if max <= 0 {
		max = 64
	}
	return &Pool{max: max, owner: owner, tunnels: make(map[uint32]Entry)}
}

// Owner is immutable for the life of a pool.
func (p *Pool) Owner() foundation.Hash {
	if p == nil {
		return foundation.Hash{}
	}
	return p.owner
}

// Add inserts a tunnel entry after expiring stale entries at now.
func (p *Pool) Add(entry Entry, now uint64) error {
	_, _, err := p.Replace(entry, 0, now)
	return err
}

// Replace records entry, optionally replacing retireID if at capacity.
func (p *Pool) Replace(entry Entry, retireID uint32, now uint64) (retired Entry, replaced bool, err error) {
	if entry.ID == 0 {
		return Entry{}, false, ErrTunnelID
	}
	if p == nil || entry.Owner != p.owner {
		return Entry{}, false, ErrPoolOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if _, ok := p.tunnels[entry.ID]; ok {
		return Entry{}, false, ErrTunnelID
	}
	if len(p.tunnels) < p.max {
		p.tunnels[entry.ID] = entry
		return Entry{}, false, nil
	}
	if retireID == 0 {
		return Entry{}, false, ErrPoolFull
	}
	retired, replaced = p.tunnels[retireID]
	if !replaced {
		return Entry{}, false, ErrPoolFull
	}
	delete(p.tunnels, retireID)
	p.tunnels[entry.ID] = entry
	return retired, true, nil
}

// RollbackReplace reverts a Replace operation if the new tunnel installation failed.
func (p *Pool) RollbackReplace(entry, retired Entry, replaced bool, now uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if current, ok := p.tunnels[entry.ID]; !ok || current != entry {
		return
	}
	delete(p.tunnels, entry.ID)
	if replaced && retired.Expires > now && len(p.tunnels) < p.max {
		p.tunnels[retired.ID] = retired
	}
}
func (p *Pool) Remove(id uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.tunnels[id]; !ok {
		return false
	}
	delete(p.tunnels, id)
	return true
}

// Clear empties the pool and returns the list of removed tunnel IDs.
func (p *Pool) Clear() []uint32 {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	ids := make([]uint32, 0, len(p.tunnels))
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	clear(p.tunnels)
	p.mu.Unlock()
	return ids
}
func (p *Pool) Get(id uint32, now uint64) (Entry, bool) {
	p.mu.RLock()
	e, ok := p.tunnels[id]
	p.mu.RUnlock()
	return e, ok && e.Expires > now
}
func (p *Pool) Select(direction Direction, now uint64) (Entry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var best Entry
	ok := false
	for _, e := range p.tunnels {
		selectSelected := e.Direction == direction && e.Expires > now
		if selectSelected {
			selectSelected = (!ok || e.Expires > best.Expires)
		}
		if selectSelected {
			best, ok = e, true
		}
	}
	return best, ok
}
func (p *Pool) Count(direction Direction, now uint64) int {
	p.mu.RLock()
	count := 0
	for _, entry := range p.tunnels {
		if entry.Direction == direction && entry.Expires > now {
			count++
		}
	}
	p.mu.RUnlock()
	return count
}

// Snapshot returns a sorted slice of unexpired tunnel entries at now.
func (p *Pool) Snapshot(now uint64) []Entry {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	entries := make([]Entry, 0, len(p.tunnels))
	for _, entry := range p.tunnels {
		if entry.Expires > now {
			entries = append(entries, entry)
		}
	}
	p.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// renewalIDs returns live tunnels that must be replaced before cutoff, ordered
// by their deadline so a maintainer can assign explicit retirement candidates.
func (p *Pool) renewalIDs(direction Direction, now, cutoff uint64) []uint32 {
	p.mu.RLock()
	entries := make([]Entry, 0)
	for _, entry := range p.tunnels {
		if entry.Direction == direction && entry.Expires > now && entry.Expires <= cutoff {
			entries = append(entries, entry)
		}
	}
	p.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Expires == entries[j].Expires {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Expires < entries[j].Expires
	})
	ids := make([]uint32, len(entries))
	for index, entry := range entries {
		ids[index] = entry.ID
	}
	return ids
}

func (p *Pool) Expire(now uint64) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expireLocked(now)
}

func (p *Pool) expireLocked(now uint64) (removed int) {
	for id, entry := range p.tunnels {
		if entry.Expires <= now {
			delete(p.tunnels, id)
			removed++
		}
	}
	return removed
}
