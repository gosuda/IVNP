package netdb

import (
	"math/bits"

	"gosuda.org/ivnp"
)

// Java I2P's router NetDB uses K=24 and B=4. B divides every XOR-distance
// bit range into eight subranges, yielding 2,048 possible terminal ranges.
const (
	KademliaB             = 4
	kademliaBFactor       = 1 << (KademliaB - 1)
	kademliaRangeCount    = ivnp.HashLength * 8 * kademliaBFactor
	DefaultBucketCapacity = 24
)

type kBucket struct {
	begin       uint16
	end         uint16
	members     []ivnp.Hash
	lastChanged uint64
}

type kBucketSet struct {
	capacity int
	buckets  []kBucket // closest to local first
}

func newKBucketSet(capacity int) kBucketSet {
	if capacity <= 4 {
		capacity = DefaultBucketCapacity
	}
	return kBucketSet{capacity: capacity, buckets: []kBucket{{end: kademliaRangeCount - 1}}}
}

// kademliaRange is a direct translation of Java I2P KBucketSet.Range.getRange.
// It returns -1 for the local hash and otherwise 0..2047 for B=4.
func kademliaRange(local, peer ivnp.Hash) int {
	leading := 0
	for index := range ivnp.HashLength {
		delta := local[index] ^ peer[index]
		if delta == 0 {
			leading += 8
			continue
		}
		leading += bits.LeadingZeros8(delta)
		break
	}
	if leading == ivnp.HashLength*8 {
		return -1
	}
	highBit := ivnp.HashLength*8 - 1 - leading
	rangeNumber := highBit << (KademliaB - 1)
	if highBit+1 < KademliaB {
		return rangeNumber
	}
	for offset := 1; offset < KademliaB; offset++ {
		bitFromMSB := leading + offset
		value := (local[bitFromMSB/8] ^ peer[bitFromMSB/8]) >> (7 - bitFromMSB%8) & 1
		rangeNumber |= int(value) << (KademliaB - 1 - offset)
	}
	return rangeNumber
}

func (s *kBucketSet) add(local, peer ivnp.Hash, now uint64) bool {
	rangeNumber := kademliaRange(local, peer)
	if rangeNumber < 0 {
		return false
	}
	index := s.bucketIndex(rangeNumber)
	bucket := &s.buckets[index]
	for _, member := range bucket.members {
		if member == peer {
			bucket.lastChanged = now
			return false
		}
	}
	if bucket.begin == bucket.end && len(bucket.members) >= s.capacity {
		return false // Java router uses RejectTrimmer for flood resistance.
	}
	bucket.members = append(bucket.members, peer)
	bucket.lastChanged = now
	if bucket.begin != bucket.end && len(bucket.members) > s.capacity {
		s.split(index, local)
	}
	return true
}

// split is a direct translation of KBucketSet.locked_split(). It repeatedly
// splits the bucket containing the original range start only. An overfull
// second bucket is intentionally left for a later add, matching Java I2P.
func (s *kBucketSet) split(index int, local ivnp.Hash) {
	for {
		original := s.buckets[index]
		if original.begin == original.end || len(original.members) <= s.capacity {
			return
		}
		start, end := int(original.begin), int(original.end)
		secondStart := 0
		if KademliaB == 1 || (start&(kademliaBFactor-1) == 0 && (end+1)&(kademliaBFactor-1) == 0 && end > start+kademliaBFactor) {
			secondStart = end + 1 - kademliaBFactor
		} else {
			secondStart = start + (1+end-start)/2
		}
		first := kBucket{begin: uint16(start), end: uint16(secondStart - 1), members: make([]ivnp.Hash, 0, len(original.members)), lastChanged: original.lastChanged}
		second := kBucket{begin: uint16(secondStart), end: uint16(end), members: make([]ivnp.Hash, 0, len(original.members)), lastChanged: original.lastChanged}
		for _, member := range original.members {
			if kademliaRange(local, member) < secondStart {
				s.redistribute(&first, member)
			} else {
				s.redistribute(&second, member)
			}
		}
		s.buckets = append(s.buckets, kBucket{})
		copy(s.buckets[index+2:], s.buckets[index+1:])
		s.buckets[index], s.buckets[index+1] = first, second
		// Java deliberately continues only through the first bucket, which
		// contains the original range start.
	}
}

// redistribute matches KBucketImpl.add() during Java's split: nonterminal
// buckets may temporarily exceed K, while a full terminal bucket invokes the
// RejectTrimmer and drops the excess hash.
func (s *kBucketSet) redistribute(bucket *kBucket, member ivnp.Hash) {
	if bucket.begin == bucket.end && len(bucket.members) >= s.capacity {
		return
	}
	bucket.members = append(bucket.members, member)
}

func (s *kBucketSet) bucketIndex(rangeNumber int) int {
	low, high := 0, len(s.buckets)
	for low < high {
		middle := low + (high-low)/2
		bucket := s.buckets[middle]
		if rangeNumber < int(bucket.begin) {
			high = middle
		} else if rangeNumber > int(bucket.end) {
			low = middle + 1
		} else {
			return middle
		}
	}
	panic("netdb: Kademlia range is outside all buckets")
}

func (s *kBucketSet) remove(local, peer ivnp.Hash) bool {
	rangeNumber := kademliaRange(local, peer)
	if rangeNumber < 0 {
		return false
	}
	bucket := &s.buckets[s.bucketIndex(rangeNumber)]
	for index, member := range bucket.members {
		if member != peer {
			continue
		}
		copy(bucket.members[index:], bucket.members[index+1:])
		bucket.members = bucket.members[:len(bucket.members)-1]
		return true
	}
	return false
}
