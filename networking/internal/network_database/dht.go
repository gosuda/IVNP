package netdb

import (
	"crypto/subtle"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"math/bits"
	"sync"
)

const BucketCount = ivnp.HashLength * 8

var ErrInvalidSignature = errors.New("netdb: signature verification failed")

type routerEntry struct {
	info      RouterInfo
	floodfill bool
	lastSeen  uint64
}

// RouterRef is a borrowed snapshot. Its RouterInfo aliases the bytes supplied
// when the entry was admitted, so callers must not mutate those bytes.
type RouterRef struct {
	Hash      ivnp.Hash
	Info      RouterInfo
	Floodfill bool
	LastSeen  uint64
}
type routerSelectionBuffer struct {
	peers []RouterRef
}

// Table mirrors Java I2P's split NetDB model: routers owns every verified
// RouterInfo, while routing is the bounded KBucketSet used by DHT traversal.
type Table struct {
	mu            sync.RWMutex
	local         ivnp.Hash
	routers       map[ivnp.Hash]routerEntry
	routing       kBucketSet
	generation    uint64
	selectionPool chan *routerSelectionBuffer
}

func NewTable(local ivnp.Hash, bucketCapacity int) *Table {
	if bucketCapacity <= 0 {
		bucketCapacity = DefaultBucketCapacity
	}
	selectionWorkers := parallelism.CPUs()
	table := &Table{
		local: local, routers: make(map[ivnp.Hash]routerEntry), routing: newKBucketSet(bucketCapacity),
		selectionPool: make(chan *routerSelectionBuffer, selectionWorkers),
	}
	for range selectionWorkers {
		table.selectionPool <- new(routerSelectionBuffer)
	}
	return table
}

func (t *Table) Len() int {
	t.mu.RLock()
	n := len(t.routers)
	t.mu.RUnlock()
	return n
}

// Local returns the routing table's local identity hash.
func (t *Table) Local() ivnp.Hash {
	t.mu.RLock()
	local := t.local
	t.mu.RUnlock()
	return local
}

// Generation increases after every retained-table mutation. It lets durable
// snapshots avoid rewriting unchanged NetDB state.
func (t *Table) Generation() uint64 {
	t.mu.RLock()
	generation := t.generation
	t.mu.RUnlock()
	return generation
}

// BucketCapacity returns K for the Java-compatible KBucketSet.
func (t *Table) BucketCapacity() int {
	t.mu.RLock()
	capacity := t.routing.capacity
	t.mu.RUnlock()
	return capacity
}
func (t *Table) borrowSelection(routing bool) *routerSelectionBuffer {
	buffer := <-t.selectionPool
	buffer.peers = buffer.peers[:0]
	t.mu.RLock()
	if routing {
		for _, bucket := range t.routing.buckets {
			for _, hash := range bucket.members {
				if entry, ok := t.routers[hash]; ok {
					buffer.peers = append(buffer.peers, RouterRef{Hash: hash, Info: entry.info, Floodfill: entry.floodfill, LastSeen: entry.lastSeen})
				}
			}
		}
	} else {
		for hash, entry := range t.routers {
			buffer.peers = append(buffer.peers, RouterRef{Hash: hash, Info: entry.info, Floodfill: entry.floodfill, LastSeen: entry.lastSeen})
		}
	}
	t.mu.RUnlock()
	return buffer
}

func (t *Table) releaseSelection(buffer *routerSelectionBuffer) {
	clear(buffer.peers)
	buffer.peers = buffer.peers[:0]
	t.selectionPool <- buffer
}

// Snapshot copies every RouterInfo in the independent NetDB data store.
// RouterInfo bytes remain borrowed from the table and must not be mutated.
func (t *Table) Snapshot() (uint64, []RouterRef) {
	t.mu.RLock()
	peers := make([]RouterRef, 0, len(t.routers))
	for hash, entry := range t.routers {
		peers = append(peers, RouterRef{Hash: hash, Info: entry.info, Floodfill: entry.floodfill, LastSeen: entry.lastSeen})
	}
	generation := t.generation
	t.mu.RUnlock()
	return generation, peers
}

// BucketOccupancy aggregates Java-compatible KBucket members by leading XOR
// bit for the existing exploration scheduler's fixed-size telemetry.
func (t *Table) BucketOccupancy(dst *[BucketCount]uint16) {
	if dst == nil {
		return
	}
	clear(dst[:])
	t.mu.RLock()
	for _, bucket := range t.routing.buckets {
		for _, hash := range bucket.members {
			dst[distanceBucket(t.local, hash)]++
		}
	}
	t.mu.RUnlock()
}

func (t *Table) ClosestNonFloodfillsInto(dst []RouterRef, target ivnp.Hash) []RouterRef {
	dst = dst[:0]
	if cap(dst) == 0 {
		return dst
	}
	limit := cap(dst)
	buffer := t.borrowSelection(false)
	defer t.releaseSelection(buffer)
	for _, candidate := range buffer.peers {
		if candidate.Floodfill {
			continue
		}
		i := len(dst)
		for i > 0 && distanceLess(target, candidate.Hash, dst[i-1].Hash) {
			i--
		}
		if i == limit {
			continue
		}
		if len(dst) < limit {
			dst = append(dst, RouterRef{})
		}
		copy(dst[i+1:], dst[i:len(dst)-1])
		dst[i] = candidate
	}
	return dst
}

// Get returns an exact borrowed RouterInfo snapshot for hash. Its wire bytes
// remain owned by the table and must not be modified by the caller.
func (t *Table) Get(hash ivnp.Hash) (RouterRef, bool) {
	t.mu.RLock()
	entry, ok := t.routers[hash]
	t.mu.RUnlock()
	if !ok {
		return RouterRef{}, false
	}
	return RouterRef{Hash: hash, Info: entry.info, Floodfill: entry.floodfill, LastSeen: entry.lastSeen}, true
}

// Store verifies then inserts or refreshes an entry. Verification occurs
// outside the lock; invalid network data never enters the routing table.
func (t *Table) Store(info RouterInfo, floodfill bool, seenAt uint64) error {
	valid, err := info.Verify()
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidSignature
	}
	t.StoreVerified(info, floodfill, seenAt)
	return nil
}

// StoreVerified admits a previously verified RouterInfo. As in Java I2P, the
// DataStore retains it independently even when the RejectTrimmer declines to
// add its hash to a full terminal KBucket.
func (t *Table) StoreVerified(info RouterInfo, floodfill bool, seenAt uint64) {
	hash := info.Hash()
	if subtle.ConstantTimeCompare(hash[:], t.local[:]) == 1 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, exists := t.routers[hash]; exists {
		// RouterInfo publication time is its version. An older or equal
		// advertisement must neither replace a newer static transport key nor
		// refresh its liveness.
		if old.info.Published >= info.Published {
			return
		}
		old.info, old.floodfill = info, floodfill
		if seenAt > old.lastSeen {
			old.lastSeen = seenAt
		}
		t.routers[hash] = old
		t.generation++
		return
	}
	t.routing.add(t.local, hash, seenAt)
	t.routers[hash] = routerEntry{info: info, floodfill: floodfill, lastSeen: seenAt}
	t.generation++
}

func (t *Table) Remove(hash ivnp.Hash) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.routers[hash]; !exists {
		return false
	}
	delete(t.routers, hash)
	t.routing.remove(t.local, hash)
	t.generation++
	return true
}

// Expire removes stale RouterInfos from both the independent data store and
// the KBucketSet index.
func (t *Table) Expire(cutoff uint64) int {
	buffer := t.borrowSelection(false)
	defer t.releaseSelection(buffer)
	if len(buffer.peers) == 0 {
		return 0
	}
	batchSize := max(1, (len(buffer.peers)+parallelism.CPUs()-1)/parallelism.CPUs())
	removed := 0
	for start := 0; start < len(buffer.peers); start += batchSize {
		end := min(len(buffer.peers), start+batchSize)
		t.mu.Lock()
		batchRemoved := 0
		for _, candidate := range buffer.peers[start:end] {
			entry, ok := t.routers[candidate.Hash]
			if !ok || entry.lastSeen >= cutoff {
				continue
			}
			delete(t.routers, candidate.Hash)
			t.routing.remove(t.local, candidate.Hash)
			batchRemoved++
		}
		if batchRemoved != 0 {
			t.generation++
			removed += batchRemoved
		}
		t.mu.Unlock()
	}
	return removed
}

// ClosestInto writes up to len(dst) closest peers by XOR metric and returns
// the populated prefix. A zero-length dst is valid and never allocates.
func (t *Table) ClosestInto(dst []RouterRef, target ivnp.Hash) []RouterRef {
	return t.closestInto(dst, target, false, nil)
}

// ClosestRoutingInto searches only hashes admitted by the Java-compatible
// KBucketSet and orders the result by strict XOR distance.
func (t *Table) ClosestRoutingInto(dst []RouterRef, target ivnp.Hash) []RouterRef {
	return t.closestRoutingInto(dst, target, false, nil)
}

// ClosestRoutingNonFloodfillsInto implements Java's EXPL response: strict XOR
// order over KBucketSet members after excluding every floodfill.
func (t *Table) ClosestRoutingNonFloodfillsInto(dst []RouterRef, target ivnp.Hash) []RouterRef {
	return t.closestRoutingInto(dst, target, true, nil)
}

// ClosestRoutingNonFloodfillsExcludingInto applies Java's peersToIgnore set
// while scanning, before the result limit is enforced.
func (t *Table) ClosestRoutingNonFloodfillsExcludingInto(dst []RouterRef, target ivnp.Hash, excluded map[ivnp.Hash]struct{}) []RouterRef {
	return t.closestRoutingInto(dst, target, true, excluded)
}

func (t *Table) closestRoutingInto(dst []RouterRef, target ivnp.Hash, excludeFloodfills bool, excluded map[ivnp.Hash]struct{}) []RouterRef {
	dst = dst[:0]
	if cap(dst) == 0 {
		return dst
	}
	limit := cap(dst)
	buffer := t.borrowSelection(true)
	defer t.releaseSelection(buffer)
	for _, candidate := range buffer.peers {
		_, skip := excluded[candidate.Hash]
		if skip || excludeFloodfills && candidate.Floodfill {
			continue
		}
		index := len(dst)
		for index > 0 && distanceLess(target, candidate.Hash, dst[index-1].Hash) {
			index--
		}
		if index == limit {
			continue
		}
		if len(dst) < limit {
			dst = append(dst, RouterRef{})
		}
		copy(dst[index+1:], dst[index:len(dst)-1])
		dst[index] = candidate
	}
	return dst
}

// ClosestFloodfillsInto is ClosestInto restricted to floodfill routers.
func (t *Table) ClosestFloodfillsInto(dst []RouterRef, target ivnp.Hash) []RouterRef {
	return t.closestInto(dst, target, true, nil)
}

// ClosestFloodfillsExcludingInto applies exclusions before limiting results.
func (t *Table) ClosestFloodfillsExcludingInto(dst []RouterRef, target ivnp.Hash, excluded map[ivnp.Hash]struct{}) []RouterRef {
	return t.closestInto(dst, target, true, excluded)
}

func (t *Table) closestInto(dst []RouterRef, target ivnp.Hash, floodfillOnly bool, excluded map[ivnp.Hash]struct{}) []RouterRef {
	dst = dst[:0]
	if cap(dst) == 0 {
		return dst
	}
	limit := cap(dst)
	buffer := t.borrowSelection(false)
	defer t.releaseSelection(buffer)
	for _, candidate := range buffer.peers {
		_, skip := excluded[candidate.Hash]
		if skip || floodfillOnly && !candidate.Floodfill {
			continue
		}
		index := len(dst)
		for index > 0 && distanceLess(target, candidate.Hash, dst[index-1].Hash) {
			index--
		}
		if index == limit {
			continue
		}
		if len(dst) < limit {
			dst = append(dst, RouterRef{})
		}
		copy(dst[index+1:], dst[index:len(dst)-1])
		dst[index] = candidate
	}
	return dst
}

// distanceBucket returns the first differing bit from the most-significant
// end. Equal hashes do not have a DHT bucket and map to the final bucket only
// for defensive callers; Store excludes them before this function is used.
func distanceBucket(local, remote ivnp.Hash) int {
	for i := range local {
		delta := local[i] ^ remote[i]
		if delta != 0 {
			return i*8 + bits.LeadingZeros8(delta)
		}
	}
	return BucketCount - 1
}

// distanceLess compares XOR(target, left) and XOR(target, right) without
// allocating a temporary distance array.
func distanceLess(target, left, right ivnp.Hash) bool {
	for i := range target {
		leftByte := target[i] ^ left[i]
		rightByte := target[i] ^ right[i]
		if leftByte != rightByte {
			return leftByte < rightByte
		}
	}
	return false
}
