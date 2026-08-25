// Package tunnel reassembles bounded I2NP tunnel fragments.
package tunnel

import (
	"bytes"
	"errors"
	"sync"
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
	parts    [128][]byte
	seen     [128]bool
	terminal [128]bool
	last     uint8
	hasLast  bool
	size     int
	touched  uint64
}

// Reassembler bounds retained incomplete data by entry count and message size.
type Reassembler struct {
	mu         sync.Mutex
	maxEntries int
	maxMessage int
	clock      uint64
	entries    map[uint32]*partial
}

func NewReassembler(maxEntries, maxMessage int) *Reassembler {
	if maxEntries <= 0 {
		maxEntries = 128
	}
	if maxMessage <= 0 {
		maxMessage = 62_690
	}
	return &Reassembler{maxEntries: maxEntries, maxMessage: maxMessage, entries: make(map[uint32]*partial)}
}

// Add copies one fragment and returns a complete caller-owned message only
// after every fragment from zero through the final number is present.
func (r *Reassembler) Add(fragment Fragment) ([]byte, bool, error) {
	if len(fragment.Data) == 0 || fragment.Number > 127 {
		return nil, false, ErrFragment
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock++
	entry := r.entries[fragment.MessageID]
	if entry == nil {
		if len(r.entries) == r.maxEntries {
			r.evictOldest()
		}
		entry = new(partial)
		r.entries[fragment.MessageID] = entry
	}
	entry.touched = r.clock
	if entry.hasLast && fragment.Number > entry.last {
		delete(r.entries, fragment.MessageID)
		return nil, false, ErrFragment
	}
	if entry.seen[fragment.Number] {
		if entry.terminal[fragment.Number] != fragment.Last || !bytes.Equal(entry.parts[fragment.Number], fragment.Data) {
			delete(r.entries, fragment.MessageID)
			return nil, false, ErrFragment
		}
		return nil, false, nil
	}
	if entry.size > r.maxMessage-len(fragment.Data) {
		delete(r.entries, fragment.MessageID)
		return nil, false, ErrTooLarge
	}
	entry.parts[fragment.Number] = append([]byte(nil), fragment.Data...)
	entry.seen[fragment.Number], entry.terminal[fragment.Number], entry.size = true, fragment.Last, entry.size+len(fragment.Data)
	if fragment.Last {
		if entry.hasLast && entry.last != fragment.Number {
			delete(r.entries, fragment.MessageID)
			return nil, false, ErrFragment
		}
		for i := int(fragment.Number) + 1; i < len(entry.seen); i++ {
			if entry.seen[i] {
				delete(r.entries, fragment.MessageID)
				return nil, false, ErrFragment
			}
		}
		entry.last, entry.hasLast = fragment.Number, true
	}
	if !entry.hasLast {
		return nil, false, nil
	}
	for i := uint8(0); i <= entry.last; i++ {
		if !entry.seen[i] {
			return nil, false, nil
		}
	}
	message := make([]byte, 0, entry.size)
	for i := uint8(0); i <= entry.last; i++ {
		message = append(message, entry.parts[i]...)
	}
	delete(r.entries, fragment.MessageID)
	return message, true, nil
}

// Expire removes incomplete assemblies not touched since cutoff clock ticks.
func (r *Reassembler) Expire(cutoff uint64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for id, entry := range r.entries {
		if entry.touched < cutoff {
			delete(r.entries, id)
			removed++
		}
	}
	return removed
}

func (r *Reassembler) evictOldest() {
	var oldestID uint32
	var oldest uint64 = ^uint64(0)
	for id, entry := range r.entries {
		if entry.touched < oldest {
			oldestID, oldest = id, entry.touched
		}
	}
	delete(r.entries, oldestID)
}
