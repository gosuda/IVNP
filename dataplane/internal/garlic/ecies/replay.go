package garlicecies

const (
	// A bucket can accept only replayBucketCapacity authenticated New Sessions.
	// Recycling a bucket is safe only after every entry in it has expired.
	replayBucketCount    = 256
	replayBucketCapacity = 64
)

type replayStamp struct {
	epoch   uint64
	expires uint64
}

type replayBucket struct {
	epoch      uint64
	ephemerals [][32]byte
}

// replayWindow bounds authenticated New Session replay state to
// replayBucketCount * replayBucketCapacity entries. It is protected by the
// RatchetManager mutex. At most one bucket (64 entries) is retired per check.
type replayWindow struct {
	entries     map[[32]byte]replayStamp
	buckets     [replayBucketCount]replayBucket
	tick        uint64
	newestEpoch uint64
	used        bool
}

func newReplayWindow(lifetime uint64) replayWindow {
	// An epoch's last insertion and the next use of its bucket are separated
	// by at least (replayBucketCount-1)*tick+1 milliseconds, beyond lifetime.
	return replayWindow{
		entries: make(map[[32]byte]replayStamp),
		tick:    lifetime/(replayBucketCount-1) + 1,
	}
}

// check rejects duplicate ephemerals and enforces a bounded admission budget.
// It may discard an expired bucket, but only add records an authenticated key.
func (r *replayWindow) check(ephemeral [32]byte, now uint64) error {
	if stamp, ok := r.entries[ephemeral]; ok && stamp.expires >= now {
		return ErrRatchetReplay
	}
	epoch := now / r.tick
	// A reversed clock must not recycle a bucket containing live records.
	if r.used && epoch < r.newestEpoch {
		return ErrRatchetExpired
	}
	r.used = true
	r.newestEpoch = epoch
	bucket := &r.buckets[epoch%replayBucketCount]
	if bucket.epoch != epoch {
		for _, old := range bucket.ephemerals {
			if stamp, ok := r.entries[old]; ok && stamp.epoch == bucket.epoch {
				delete(r.entries, old)
			}
		}
		clear(bucket.ephemerals)
		bucket.ephemerals = bucket.ephemerals[:0]
		bucket.epoch = epoch
	}
	if len(bucket.ephemerals) >= replayBucketCapacity {
		return ErrRatchetReplayFull
	}
	return nil
}

// add must follow a successful check with the same now under the manager lock.
func (r *replayWindow) add(ephemeral [32]byte, now, lifetime uint64) {
	epoch := now / r.tick
	bucket := &r.buckets[epoch%replayBucketCount]
	if bucket.epoch != epoch || len(bucket.ephemerals) >= replayBucketCapacity {
		panic("garlic/ecies: replay admission invariant violated")
	}
	bucket.ephemerals = append(bucket.ephemerals, ephemeral)
	expires := now + lifetime
	if expires < now {
		expires = ^uint64(0)
	}
	r.entries[ephemeral] = replayStamp{epoch: epoch, expires: expires}
}
