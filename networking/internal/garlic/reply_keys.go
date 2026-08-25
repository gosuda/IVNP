package garlic

import (
	"errors"
	"sync"
)

var (
	ErrReplyKeyRegistryFull      = errors.New("garlic: reply-key registry full")
	ErrReplyKeyRegistryDuplicate = errors.New("garlic: duplicate reply-key tag")
)

// ReplyKeyRegistry is a bounded store for one-time ECIES build and encrypted
// DatabaseLookup reply keys. Garlic's Existing Session receiver must consume
// the tag before authentication so forgery cannot make a one-time key reusable.
// Authenticated cloves return through the router's normal Garlic dispatch.
type ReplyKeyRegistry struct {
	mu      sync.Mutex
	max     int
	entries map[[8]byte]GarlicReplyKey
}

// ReplyKeyConsumer is the ECIES one-time Existing Session receiver seam. It
// consumes the leading 8-byte tag before authentication, preventing a failed
// packet from restoring a reply key.
type ReplyKeyConsumer interface {
	ConsumeGarlicReplyKey([8]byte, uint64) (GarlicReplyKey, bool)
}

// NewReplyKeyRegistry constructs a bounded registry. A non-positive limit uses
// the maximum number of pending outbound builds supported by BuildManager.
func NewReplyKeyRegistry(max int) *ReplyKeyRegistry {
	if max <= 0 {
		max = 64
	}
	return &ReplyKeyRegistry{max: max, entries: make(map[[8]byte]GarlicReplyKey)}
}

// RegisterGarlicReplyKey retains key until it is consumed, explicitly removed,
// or expired. It never evicts a live reply key: callers must fail the matching
// build rather than make its reply undecryptable.
func (r *ReplyKeyRegistry) RegisterGarlicReplyKey(key GarlicReplyKey) error {
	if r == nil || key.ExpiresAt == 0 {
		return ErrReplyKeyRegistryFull
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[key.Tag]; exists {
		return ErrReplyKeyRegistryDuplicate
	}
	if len(r.entries) >= r.max {
		return ErrReplyKeyRegistryFull
	}
	r.entries[key.Tag] = key
	return nil
}

// ConsumeGarlicReplyKey returns and removes an unexpired reply key. It is
// one-use even when subsequent packet authentication fails.
func (r *ReplyKeyRegistry) ConsumeGarlicReplyKey(tag [8]byte, nowMillis uint64) (GarlicReplyKey, bool) {
	var zero GarlicReplyKey
	if r == nil {
		return zero, false
	}
	r.mu.Lock()
	key, ok := r.entries[tag]
	if ok {
		delete(r.entries, tag)
	}
	r.mu.Unlock()
	if !ok || key.ExpiresAt <= nowMillis {
		clear(key.Key[:])
		return zero, false
	}
	return key, true
}

// RemoveGarlicReplyKey drops a key when sending or building fails.
func (r *ReplyKeyRegistry) RemoveGarlicReplyKey(tag [8]byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	key, ok := r.entries[tag]
	if ok {
		delete(r.entries, tag)
	}
	r.mu.Unlock()
	if ok {
		clear(key.Key[:])
	}
}

// Expire removes reply keys no longer valid at nowMillis.
func (r *ReplyKeyRegistry) Expire(nowMillis uint64) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	removed := 0
	for tag, key := range r.entries {
		if key.ExpiresAt <= nowMillis {
			delete(r.entries, tag)
			clear(key.Key[:])
			removed++
		}
	}
	r.mu.Unlock()
	return removed
}

// Len returns the retained reply-key count for lifecycle checks.
func (r *ReplyKeyRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	count := len(r.entries)
	r.mu.Unlock()
	return count
}
