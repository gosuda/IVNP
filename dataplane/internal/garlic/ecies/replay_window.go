package garlicecies

// Replay expiries are grouped into a fixed number of time buckets. A bucket is
// retired by dropping its map, so no receive walks the set of replay keys.
const (
	replayBucketCount = 16
	replayBucketSpan  = replayBucketCount - 2
)

type replayBucket struct {
	epoch      uint64
	ephemerals map[[32]byte]struct{}
}

type replayWindow struct {
	buckets      [replayBucketCount]replayBucket
	lifetime     uint64
	bucketWidth  uint64
	lastNow      uint64
	currentEpoch uint64
	capacity     int
	count        int
}

// newReplayWindow requires a positive lifetime and capacity. The extra two
// buckets allow an entire replay lifetime of future expiry epochs without a
// collision with a still-live bucket.
func newReplayWindow(lifetime uint64, capacity int) replayWindow {
	if lifetime == 0 || capacity <= 0 {
		panic("garlic/ecies: invalid replay window parameters")
	}
	width := lifetime / replayBucketSpan
	if lifetime%replayBucketSpan != 0 {
		width++
	}
	return replayWindow{lifetime: lifetime, bucketWidth: width, capacity: capacity}
}

// expire removes whole expired buckets in constant time relative to replay
// volume. Never rewind its clock: a backward wall-clock adjustment must not
// resurrect expired entries or reuse a live bucket prematurely.
func (w *replayWindow) expire(now uint64) {
	if now > w.lastNow {
		w.lastNow = now
	}
	epoch := w.lastNow / w.bucketWidth
	if epoch <= w.currentEpoch {
		return
	}
	for i := range w.buckets {
		bucket := &w.buckets[i]
		if bucket.ephemerals != nil && bucket.epoch < epoch {
			w.count -= len(bucket.ephemerals)
			*bucket = replayBucket{}
		}
	}
	w.currentEpoch = epoch
}

// check rejects duplicates and refuses admission at capacity before the
// caller performs expensive New Session authentication.
func (w *replayWindow) check(ephemeral [32]byte, now uint64) error {
	w.expire(now)
	for i := range w.buckets {
		if _, exists := w.buckets[i].ephemerals[ephemeral]; exists {
			return ErrRatchetReplay
		}
	}
	if w.count >= w.capacity {
		return ErrRatchetReplayExhausted
	}
	return nil
}

// reserve must be called only after authenticating and validating the packet.
// Entries live at least lifetime milliseconds; bucket rounding can retain them
// for up to one additional bucket width, never shorten replay protection.
func (w *replayWindow) reserve(ephemeral [32]byte, now uint64) error {
	if err := w.check(ephemeral, now); err != nil {
		return err
	}
	expiry := w.lastNow + w.lifetime
	if expiry < w.lastNow {
		expiry = ^uint64(0)
	}
	epoch := expiry / w.bucketWidth
	bucket := &w.buckets[epoch%replayBucketCount]
	if bucket.ephemerals == nil {
		bucket.epoch = epoch
		bucket.ephemerals = make(map[[32]byte]struct{})
	} else if bucket.epoch != epoch {
		panic("garlic/ecies: overlapping replay buckets")
	}
	bucket.ephemerals[ephemeral] = struct{}{}
	w.count++
	return nil
}

func (w *replayWindow) clear() {
	for i := range w.buckets {
		w.buckets[i] = replayBucket{}
	}
	w.count = 0
}
