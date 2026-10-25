// Package tunnel reassembles bounded I2NP tunnel fragments.
package tunnel

import (
	"bytes"
	"errors"
	"sync"

	"gosuda.org/ivnp/internal/pool"
)

var (
	ErrFragment = errors.New("tunnel: invalid fragment")
	ErrTooLarge = errors.New("tunnel: reassembled message exceeds limit")
)

type Fragment struct {
	MessageID uint32
	Number    uint8
	Last      bool
	Data      []byte
}

type partial struct {
	parts    [64][]byte
	leases   [64]*pool.Lease
	seen     uint64
	terminal uint64
	last     uint8
	hasLast  bool
	size     int
	created  uint64
}

// Reassembler bounds retained incomplete data by entry count and message size.
type Reassembler struct {
	mu sync.Mutex
	// +checklocks:mu
	maxEntries int
	// +checklocks:mu
	maxMessage int
	// +checklocks:mu
	entries map[uint32]*partial
	// +checklocks:mu
	partialPool sync.Pool
}

func NewReassembler(maxEntries, maxMessage int) *Reassembler {
	if maxEntries <= 0 {
		maxEntries = 128
	}
	if maxMessage <= 0 {
		maxMessage = 62_690
	}
	reassembler := &Reassembler{maxEntries: maxEntries, maxMessage: maxMessage, entries: make(map[uint32]*partial)}
	reassembler.partialPool.New = func() any { return new(partial) }
	return reassembler
}

// Add copies one fragment and returns a complete caller-owned message only
// after every fragment from zero through the final number is present.
func (r *Reassembler) Add(fragment Fragment, nowMillis uint64) ([]byte, bool, error) {
	if len(fragment.Data) == 0 || fragment.Number > 63 {
		return nil, false, ErrFragment
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[fragment.MessageID]
	if entry == nil {
		if len(r.entries) == r.maxEntries {
			r.evictOldest()
		}
		entry = r.partialPool.Get().(*partial)
		r.entries[fragment.MessageID] = entry
		entry.created = nowMillis
	}
	if entry.hasLast && fragment.Number > entry.last {
		r.remove(fragment.MessageID)
		return nil, false, ErrFragment
	}
	bit := uint64(1) << fragment.Number
	if entry.seen&bit != 0 {
		if (entry.terminal&bit != 0) != fragment.Last || !bytes.Equal(entry.parts[fragment.Number], fragment.Data) {
			r.remove(fragment.MessageID)
			return nil, false, ErrFragment
		}
		return nil, false, nil
	}
	if entry.size > r.maxMessage-len(fragment.Data) {
		r.remove(fragment.MessageID)
		return nil, false, ErrTooLarge
	}
	lease, _ := pool.AcquireLease(len(fragment.Data))
	part, _ := lease.Bytes(len(fragment.Data))
	copy(part, fragment.Data)
	entry.parts[fragment.Number], entry.leases[fragment.Number] = part, lease
	entry.seen |= bit
	if fragment.Last {
		entry.terminal |= bit
	}
	entry.size += len(fragment.Data)
	if fragment.Last {
		if entry.hasLast && entry.last != fragment.Number {
			r.remove(fragment.MessageID)
			return nil, false, ErrFragment
		}
		if entry.seen>>(fragment.Number+1) != 0 {
			r.remove(fragment.MessageID)
			return nil, false, ErrFragment
		}
		entry.last, entry.hasLast = fragment.Number, true
	}
	if !entry.hasLast {
		return nil, false, nil
	}
	requiredMask := (^uint64(0)) >> (63 - entry.last)
	if entry.seen&requiredMask != requiredMask {
		return nil, false, nil
	}
	message := make([]byte, 0, entry.size)
	for i := uint8(0); i <= entry.last; i++ {
		message = append(message, entry.parts[i]...)
	}
	r.remove(fragment.MessageID)
	return message, true, nil
}

// Expire removes incomplete assemblies created at or before cutoff.
func (r *Reassembler) Expire(cutoff uint64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for id, entry := range r.entries {
		if entry.created <= cutoff {
			r.remove(id)
			removed++
		}
	}
	return removed
}

// +checklocks:r.mu
func (r *Reassembler) evictOldest() {
	var oldestID uint32
	var oldest uint64 = ^uint64(0)
	for id, entry := range r.entries {
		if entry.created < oldest {
			oldestID, oldest = id, entry.created
		}
	}
	r.remove(oldestID)
}

// +checklocks:r.mu
func (r *Reassembler) remove(messageID uint32) {
	entry := r.entries[messageID]
	if entry == nil {
		return
	}
	delete(r.entries, messageID)
	for _, lease := range entry.leases {
		if lease != nil {
			lease.Release()
		}
	}
	*entry = partial{}
	r.partialPool.Put(entry)
}
