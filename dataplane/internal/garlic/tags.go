package garlic

import (
	"crypto/subtle"
	"sync"
)

type tagEntry struct {
	key     [32]byte
	expires uint64
}

// TagStore keeps one-use inbound session tags under a fixed cardinality cap.
type TagStore struct {
	mu   sync.Mutex
	max  int
	tags map[[32]byte]tagEntry
}

func NewTagStore(max int) *TagStore {
	if max <= 0 {
		max = 4096
	}
	return &TagStore{max: max, tags: make(map[[32]byte]tagEntry)}
}

func (s *TagStore) Put(tag, key []byte, expires uint64) bool {
	if len(tag) != 32 || len(key) != 32 {
		return false
	}
	var id, sessionKey [32]byte
	copy(id[:], tag)
	copy(sessionKey[:], key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tags == nil {
		s.tags = make(map[[32]byte]tagEntry)
	}
	if len(s.tags) == s.max {
		var oldest [32]byte
		var deadline uint64 = ^uint64(0)
		for candidate, entry := range s.tags {
			if entry.expires < deadline {
				oldest, deadline = candidate, entry.expires
			}
		}
		entry := s.tags[oldest]
		clear(entry.key[:])
		s.tags[oldest] = entry
		delete(s.tags, oldest)
	}
	s.tags[id] = tagEntry{key: sessionKey, expires: expires}
	return true
}

// Take returns and removes a matching unexpired tag in constant time for the
// key comparison. A tag is consumed whether decryption later succeeds.
func (s *TagStore) Take(tag []byte, now uint64) ([32]byte, bool) {
	var zero, id [32]byte
	if len(tag) != 32 {
		return zero, false
	}
	copy(id[:], tag)
	s.mu.Lock()
	entry, ok := s.tags[id]
	if ok {
		wiped := entry
		clear(wiped.key[:])
		s.tags[id] = wiped
		delete(s.tags, id)
	}
	s.mu.Unlock()
	if !ok || entry.expires < now || subtle.ConstantTimeCompare(id[:], tag) != 1 {
		return zero, false
	}
	return entry.key, true
}

func (s *TagStore) Expire(now uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for tag, entry := range s.tags {
		if entry.expires < now {
			clear(entry.key[:])
			s.tags[tag] = entry
			delete(s.tags, tag)
			removed++
		}
	}
	return removed
}

// Clear removes every tag, overwrites retained session keys, and releases the
// backing map. A later Put allocates a fresh map.
func (s *TagStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tag, entry := range s.tags {
		clear(entry.key[:])
		s.tags[tag] = entry
	}
	s.tags = nil
}
