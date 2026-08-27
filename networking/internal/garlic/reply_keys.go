package garlic

import (
	"errors"
	"sync"
)

var (
	ErrReplyKeyRegistryFull      = errors.New("garlic: reply-key registry full")
	ErrReplyKeyRegistryDuplicate = errors.New("garlic: duplicate reply-key tag")
)

// ReplyKeyRegistry stores one-time reply keys for encrypted lookups and tunnel build replies.
type ReplyKeyRegistry struct {
	mu      sync.Mutex
	max     int
	entries map[[8]byte]GarlicReplyKey
}

// ReplyKeyConsumer consumes single-use reply keys by their 8-byte tag.
type ReplyKeyConsumer interface {
	ConsumeGarlicReplyKey([8]byte, uint64) (GarlicReplyKey, bool)
}

// NewReplyKeyRegistry creates a bounded ReplyKeyRegistry.
func NewReplyKeyRegistry(max int) *ReplyKeyRegistry {
	if max <= 0 {
		max = 64
	}
	return &ReplyKeyRegistry{max: max, entries: make(map[[8]byte]GarlicReplyKey)}
}

// RegisterGarlicReplyKey stores a reply key until it is consumed or expired.
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

// ConsumeGarlicReplyKey looks up, removes, and returns a single-use reply key by tag.
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
