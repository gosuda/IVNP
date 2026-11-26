package netdb

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"math/bits"
	"net/netip"
	"slices"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
)

const (
	BucketCount              = foundation.HashLength * 8
	DefaultBucketSubnetQuota = 2
)

var ErrInvalidSignature = errors.New("netdb: signature verification failed")

type routingSubnet [8]byte

type routerEntry struct {
	info      foundation.NetworkDatabaseRouterInfo
	floodfill bool
	// trusted marks a RouterInfo this router obtained through a path it
	// initiated or vouches for (reseed, bootstrap, import, snapshot, or a reply
	// to its own lookup), or whose router answered one of its lookups. Records
	// pushed by peers (unsolicited DatabaseStore, transport handshakes) stay
	// untrusted, so they are evicted first and never persisted.
	trusted     bool
	lastSeen    uint64
	subnets     [4]routingSubnet
	subnetCount uint8
}

// RouterRef is a borrowed snapshot. Its RouterInfo aliases the bytes supplied
// when the entry was admitted, so callers must not mutate those bytes.
type RouterRef struct {
	Hash      foundation.Hash
	Info      foundation.NetworkDatabaseRouterInfo
	Floodfill bool
	Trusted   bool
	LastSeen  uint64
}

func (e routerEntry) ref(hash foundation.Hash) RouterRef {
	return RouterRef{Hash: hash, Info: e.info, Floodfill: e.floodfill, Trusted: e.trusted, LastSeen: e.lastSeen}
}

type routerSelectionBuffer struct {
	peers []RouterRef
}

// Table mirrors Java I2P's split NetDB model: routers owns every verified
// RouterInfo, while routing is the bounded KBucketSet used by DHT traversal.
type Table struct {
	mu    sync.RWMutex
	local foundation.Hash
	// +checklocks:mu
	routers map[foundation.Hash]routerEntry
	// +checklocks:mu
	floodfills map[foundation.Hash]struct{}
	// +checklocks:mu
	routing kBucketSet
	// +checklocks:mu
	generation    uint64
	selectionPool chan *routerSelectionBuffer
	// +checklocks:mu
	routerLimit int
	// +checklocks:mu
	subnetQuota int
}

func NewTable(local foundation.Hash, bucketCapacity int) *Table {
	if bucketCapacity <= 0 {
		bucketCapacity = DefaultBucketCapacity
	}
	selectionWorkers := parallelism.CPUs()
	routing := newKBucketSet(bucketCapacity)
	table := &Table{
		local: local, routers: make(map[foundation.Hash]routerEntry),
		floodfills:    make(map[foundation.Hash]struct{}),
		routing:       routing,
		selectionPool: make(chan *routerSelectionBuffer, selectionWorkers),
		routerLimit:   BucketCount * routing.capacity,
		subnetQuota:   DefaultBucketSubnetQuota,
	}
	for range selectionWorkers {
		table.selectionPool <- new(routerSelectionBuffer)
	}
	return table
}

// SetBucketSubnetQuota bounds how many routers sharing an IPv4 /16 or IPv6 /48
// prefix may occupy the same local XOR distance bucket in the routing index. A
// nonpositive quota disables per-subnet filtering.
func (t *Table) SetBucketSubnetQuota(quota int) {
	t.mu.Lock()
	t.subnetQuota = quota
	t.mu.Unlock()
}

// SetRouterLimit bounds retained RouterInfos independently of the routing index.
// A nonpositive limit restores the default BucketCount * BucketCapacity bound;
// retention is never unbounded because any peer can push RouterInfos.
func (t *Table) SetRouterLimit(limit int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit <= 0 {
		limit = t.defaultRouterLimitLocked()
	}
	t.routerLimit = limit
	for len(t.routers) > limit {
		t.evictLeastUsefulLocked()
	}
}

// defaultRouterLimitLocked matches the KBucketSet's full capacity and the
// durable snapshot bound.
//
// +checklocksread:t.mu
func (t *Table) defaultRouterLimitLocked() int {
	return BucketCount * t.routing.capacity
}

// routerTrust says whether a RouterInfo reached this router through a path it
// initiated or vouches for, rather than being pushed by a peer.
type routerTrust bool

const (
	routerUntrusted routerTrust = false
	routerTrusted   routerTrust = true
)

// retentionRank orders RouterInfos by how much they are worth keeping.
type retentionRank struct {
	trusted   bool
	floodfill bool
	lastSeen  uint64
}

// below reports whether r is less useful than other: untrusted before
// trusted, then non-floodfill before floodfill, then older lastSeen first.
func (r retentionRank) below(other retentionRank) bool {
	if r.trusted != other.trusted {
		return !r.trusted
	}
	if r.floodfill != other.floodfill {
		return !r.floodfill
	}
	return r.lastSeen < other.lastSeen
}

// evictLeastUsefulLocked removes the lowest-ranked RouterInfo, breaking rank
// ties by the farthest XOR distance from the local hash. Because untrusted
// records rank lowest, a flood of unsolicited RouterInfos can only displace
// other untrusted records while any remain.
//
// +checklocks:t.mu
func (t *Table) evictLeastUsefulLocked() {
	var victim foundation.Hash
	var victimRank retentionRank
	found := false
	for hash, entry := range t.routers {
		rank := retentionRank{trusted: entry.trusted, floodfill: entry.floodfill, lastSeen: entry.lastSeen}
		replace := !found || rank.below(victimRank)
		if !replace && rank == victimRank {
			replace = distanceLess(t.local, victim, hash)
		}
		if replace {
			victim, victimRank, found = hash, rank, true
		}
	}
	if found {
		delete(t.routers, victim)
		delete(t.floodfills, victim)
		t.routing.remove(t.local, victim)
		t.generation++
	}
}

// markTrusted records that hash answered one of this router's lookups.
func (t *Table) markTrusted(hash foundation.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.routers[hash]
	if !ok || entry.trusted {
		return
	}
	entry.trusted = true
	t.routers[hash] = entry
	t.generation++
}

func (t *Table) Len() int {
	t.mu.RLock()
	n := len(t.routers)
	t.mu.RUnlock()
	return n
}

// Counts returns the current total and floodfill router counts without allocating.
func (t *Table) Counts() (routers, floodfills int) {
	t.mu.RLock()
	routers = len(t.routers)
	floodfills = len(t.floodfills)
	t.mu.RUnlock()
	return routers, floodfills
}

// Local returns the routing table's local identity hash.
func (t *Table) Local() foundation.Hash {
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
					buffer.peers = append(buffer.peers, entry.ref(hash))
				}
			}
		}
	} else {
		for hash, entry := range t.routers {
			buffer.peers = append(buffer.peers, entry.ref(hash))
		}
	}
	t.mu.RUnlock()
	return buffer
}

func (t *Table) borrowSelectionFloodfills() *routerSelectionBuffer {
	buffer := <-t.selectionPool
	buffer.peers = buffer.peers[:0]
	t.mu.RLock()
	if len(t.floodfills) > 0 {
		for hash := range t.floodfills {
			if entry, ok := t.routers[hash]; ok && entry.floodfill {
				buffer.peers = append(buffer.peers, entry.ref(hash))
			}
		}
	} else {
		for hash, entry := range t.routers {
			if entry.floodfill {
				buffer.peers = append(buffer.peers, entry.ref(hash))
			}
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

// Visit iterates over a borrowed snapshot of all retained RouterInfos using
// the pooled selection buffer, stopping early when fn returns false.
func (t *Table) Visit(fn func(RouterRef) bool) {
	if t == nil || fn == nil {
		return
	}
	buffer := t.borrowSelection(false)
	defer t.releaseSelection(buffer)
	for _, peer := range buffer.peers {
		if !fn(peer) {
			return
		}
	}
}

// Snapshot copies every RouterInfo in the independent NetDB data store.
// RouterInfo bytes remain borrowed from the table and must not be mutated.
func (t *Table) Snapshot() (uint64, []RouterRef) {
	t.mu.RLock()
	peers := make([]RouterRef, 0, len(t.routers))
	for hash, entry := range t.routers {
		peers = append(peers, entry.ref(hash))
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

func (t *Table) ClosestNonFloodfillsInto(dst []RouterRef, target foundation.Hash) []RouterRef {
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
func (t *Table) Get(hash foundation.Hash) (RouterRef, bool) {
	t.mu.RLock()
	entry, ok := t.routers[hash]
	t.mu.RUnlock()
	if !ok {
		return RouterRef{}, false
	}
	return entry.ref(hash), true
}

// Store verifies then inserts or refreshes an entry. Verification occurs
// outside the lock; invalid network data never enters the routing table.
func (t *Table) Store(info foundation.NetworkDatabaseRouterInfo, floodfill bool, seenAt uint64) error {
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

// StoreVerified admits a previously verified RouterInfo as trusted. As in Java
// I2P, the DataStore retains it independently even when the RejectTrimmer or
// per-bucket subnet quota declines to add its hash to the KBucketSet routing
// index.
func (t *Table) StoreVerified(info foundation.NetworkDatabaseRouterInfo, floodfill bool, seenAt uint64) {
	t.storeVerified(info, floodfill, seenAt, routerTrusted)
}

// storeVerified admits a signature-verified RouterInfo. At the retention bound
// it evicts the least useful entry, so an untrusted admission displaces a
// trusted entry only when no untrusted entry remains.
func (t *Table) storeVerified(info foundation.NetworkDatabaseRouterInfo, floodfill bool, seenAt uint64, trust routerTrust) {
	trusted := bool(trust)
	hash := info.Hash()
	if subtle.ConstantTimeCompare(hash[:], t.local[:]) == 1 {
		return
	}
	subnets, subnetCount := routingSubnetsOf(info)
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, exists := t.routers[hash]; exists {
		// RouterInfo publication time is its version. An older or equal
		// advertisement must neither replace a newer static transport key nor
		// refresh its liveness.
		if old.info.Published >= info.Published {
			if trusted && !old.trusted {
				old.trusted = true
				t.routers[hash] = old
				t.generation++
			}
			return
		}
		old.info, old.floodfill = info, floodfill
		old.trusted = old.trusted || trusted
		old.subnets, old.subnetCount = subnets, subnetCount
		if seenAt > old.lastSeen {
			old.lastSeen = seenAt
		}
		t.routers[hash] = old
		if floodfill {
			t.floodfills[hash] = struct{}{}
		} else {
			delete(t.floodfills, hash)
		}
		if !t.routingAllowsSubnetsLocked(hash, subnets[:subnetCount]) {
			t.routing.remove(t.local, hash)
		}
		t.generation++
		return
	}
	if len(t.routers) >= t.routerLimit {
		t.evictLeastUsefulLocked()
	}
	if t.routingAllowsSubnetsLocked(hash, subnets[:subnetCount]) {
		t.routing.add(t.local, hash, seenAt)
	}
	t.routers[hash] = routerEntry{
		info:        info,
		floodfill:   floodfill,
		trusted:     trusted,
		lastSeen:    seenAt,
		subnets:     subnets,
		subnetCount: subnetCount,
	}
	if floodfill {
		t.floodfills[hash] = struct{}{}
	}
	t.generation++
}

// +checklocksread:t.mu
func (t *Table) routingAllowsSubnetsLocked(candidate foundation.Hash, subnets []routingSubnet) bool {
	if t.subnetQuota <= 0 || len(subnets) == 0 {
		return true
	}
	targetBand := distanceBucket(t.local, candidate)
	var counts [4]int
	for _, bucket := range t.routing.buckets {
		for _, member := range bucket.members {
			if member == candidate || distanceBucket(t.local, member) != targetBand {
				continue
			}
			entry, ok := t.routers[member]
			if !ok || entry.subnetCount == 0 {
				continue
			}
			if accumulateSubnetMatches(&counts, subnets, entry.subnets[:entry.subnetCount], t.subnetQuota) {
				return false
			}
		}
	}
	return true
}

func accumulateSubnetMatches(counts *[4]int, subnets, existing []routingSubnet, quota int) bool {
	for i, subnet := range subnets {
		if slices.Contains(existing, subnet) {
			counts[i]++
			if counts[i] >= quota {
				return true
			}
		}
	}
	return false
}

func routingSubnetsOf(info foundation.NetworkDatabaseRouterInfo) ([4]routingSubnet, uint8) {
	var out [4]routingSubnet
	var count uint8
	addresses := info.Addresses()
	for count < uint8(len(out)) {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			break
		}
		var host []byte
		options := address.Options.Iterator()
		for {
			key, value, optOK, optErr := options.Next()
			if optErr != nil || !optOK {
				break
			}
			if bytes.Equal(key, []byte("host")) {
				host = value
				break
			}
		}
		if len(host) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(string(host))
		if err != nil || ip.IsLoopback() {
			continue
		}
		var subnet routingSubnet
		if ip.Is4() {
			octets := ip.As4()
			if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
				continue
			}
			subnet = routingSubnet{1, octets[0], octets[1]}
		} else if ip.Is6() {
			octets := ip.As16()
			subnet = routingSubnet{2, octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]}
		} else {
			continue
		}
		duplicate := false
		for i := range count {
			if out[i] == subnet {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out[count] = subnet
			count++
		}
	}
	return out, count
}

func (t *Table) Remove(hash foundation.Hash) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.routers[hash]; !exists {
		return false
	}
	delete(t.routers, hash)
	delete(t.floodfills, hash)
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
			delete(t.floodfills, candidate.Hash)
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
func (t *Table) ClosestInto(dst []RouterRef, target foundation.Hash) []RouterRef {
	return t.closestInto(dst, target, false, nil, nil)
}

// ClosestRoutingInto searches only hashes admitted by the Java-compatible
// KBucketSet and orders the result by strict XOR distance.
func (t *Table) ClosestRoutingInto(dst []RouterRef, target foundation.Hash) []RouterRef {
	return t.closestRoutingInto(dst, target, false, nil)
}

// ClosestRoutingNonFloodfillsInto implements Java's EXPL response: strict XOR
// order over KBucketSet members after excluding every floodfill.
func (t *Table) ClosestRoutingNonFloodfillsInto(dst []RouterRef, target foundation.Hash) []RouterRef {
	return t.closestRoutingInto(dst, target, true, nil)
}

// ClosestRoutingNonFloodfillsExcludingInto applies Java's peersToIgnore set
// while scanning, before the result limit is enforced.
func (t *Table) ClosestRoutingNonFloodfillsExcludingInto(dst []RouterRef, target foundation.Hash, excluded map[foundation.Hash]struct{}) []RouterRef {
	return t.closestRoutingInto(dst, target, true, excluded)
}

func (t *Table) closestRoutingInto(dst []RouterRef, target foundation.Hash, excludeFloodfills bool, excluded map[foundation.Hash]struct{}) []RouterRef {
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
func (t *Table) ClosestFloodfillsInto(dst []RouterRef, target foundation.Hash) []RouterRef {
	return t.closestInto(dst, target, true, nil, nil)
}

// ClosestFloodfillsExcludingInto applies exclusions before limiting results.
func (t *Table) ClosestFloodfillsExcludingInto(dst []RouterRef, target foundation.Hash, excluded map[foundation.Hash]struct{}) []RouterRef {
	return t.closestInto(dst, target, true, excluded, nil)
}

func (t *Table) closestInto(dst []RouterRef, target foundation.Hash, floodfillOnly bool, excluded map[foundation.Hash]struct{}, eligible func(RouterRef) bool) []RouterRef {
	dst = dst[:0]
	if cap(dst) == 0 {
		return dst
	}
	limit := cap(dst)
	var buffer *routerSelectionBuffer
	if floodfillOnly {
		buffer = t.borrowSelectionFloodfills()
	} else {
		buffer = t.borrowSelection(false)
	}
	defer t.releaseSelection(buffer)
	for _, candidate := range buffer.peers {
		_, skip := excluded[candidate.Hash]
		if skip || floodfillOnly && !candidate.Floodfill {
			continue
		}
		if eligible != nil && !eligible(candidate) {
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
func distanceBucket(local, remote foundation.Hash) int {
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
func distanceLess(target, left, right foundation.Hash) bool {
	for i := range target {
		leftByte := target[i] ^ left[i]
		rightByte := target[i] ^ right[i]
		if leftByte != rightByte {
			return leftByte < rightByte
		}
	}
	return false
}
