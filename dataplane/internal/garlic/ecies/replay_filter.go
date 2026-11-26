package garlicecies

const (
	defaultMaxReplays = 16384
	replayBuckets     = 8
	// replayAcceptWindow is the longest a New Session DateTime block can keep
	// validating after receipt: 120 s ahead plus 300 s behind, to the last ms.
	replayAcceptWindow = 420_999
)

// replayFilter remembers decoded New Session ephemeral keys until their
// reservations expire. Keys are grouped into expiry buckets of a fixed span,
// so expiry drops whole buckets in constant time and never rescans live keys.
// A key may outlive its own expiry by at most one span. The filter holds at
// most limit keys and refuses new reservations when full rather than evicting
// a live one, which would reopen that New Session to replay.
type replayFilter struct {
	span    uint64
	limit   int
	count   int
	buckets [replayBuckets]replayBucket
}

type replayBucket struct {
	// until is the last millisecond for which keys stay reserved.
	until uint64
	keys  map[[32]byte]struct{}
}

func newReplayFilter(lifetime uint64, limit int) replayFilter {
	lifetime = max(lifetime, replayAcceptWindow)
	// Reservations made at nondecreasing times then occupy at most
	// replayBuckets distinct spans.
	span := (lifetime + replayBuckets - 3) / (replayBuckets - 2)
	return replayFilter{span: span, limit: limit}
}

// expire releases every bucket whose reservations ended before now.
func (f *replayFilter) expire(now uint64) {
	for i := range f.buckets {
		bucket := &f.buckets[i]
		if bucket.keys != nil && bucket.until < now {
			f.count -= len(bucket.keys)
			*bucket = replayBucket{}
		}
	}
}

func (f *replayFilter) contains(key [32]byte, now uint64) bool {
	for i := range f.buckets {
		bucket := &f.buckets[i]
		if bucket.keys == nil || bucket.until < now {
			continue
		}
		if _, ok := bucket.keys[key]; ok {
			return true
		}
	}
	return false
}

func (f *replayFilter) full() bool { return f.count >= f.limit }

// add reserves key through at least expires. Callers check full first.
func (f *replayFilter) add(key [32]byte, expires uint64) {
	until := expires/f.span*f.span + f.span - 1
	bucket := f.bucketFor(until)
	if _, ok := bucket.keys[key]; !ok {
		bucket.keys[key] = struct{}{}
		f.count++
	}
}

func (f *replayFilter) bucketFor(until uint64) *replayBucket {
	for i := range f.buckets {
		if f.buckets[i].keys != nil && f.buckets[i].until == until {
			return &f.buckets[i]
		}
	}
	for i := range f.buckets {
		if f.buckets[i].keys == nil {
			f.buckets[i] = replayBucket{until: until, keys: make(map[[32]byte]struct{})}
			return &f.buckets[i]
		}
	}
	// Only a clock step backwards can occupy every bucket. Extending the
	// latest one keeps each of its keys reserved at least as long as required.
	latest := &f.buckets[0]
	for i := range f.buckets {
		if f.buckets[i].until > latest.until {
			latest = &f.buckets[i]
		}
	}
	latest.until = max(latest.until, until)
	return latest
}

func (f *replayFilter) reset() {
	f.buckets = [replayBuckets]replayBucket{}
	f.count = 0
}
