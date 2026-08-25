// Package packet provides single-owner buffers for I2NP packet construction and parsing.
package packet

import (
	"sync"

	"gosuda.org/ivnp/internal/pool"
)

// Buffer is a single-owner contiguous packet buffer. It is not safe for
// concurrent use and must not be copied after first use.
//
// Slices returned by its methods are borrowed views. They are invalidated by
// any subsequent mutation of the Buffer and by Release.
type Buffer struct {
	buf      []byte
	lease    *pool.Lease
	reserved int
	start    int
	end      int
	limit    int
	released bool
}

// Acquire returns an empty buffer with room for reserved header bytes and
// payloadCapacity payload bytes. The backing slab can be larger, but the
// buffer's logical capacity is exactly reserved + payloadCapacity.
func Acquire(reserved, payloadCapacity int) (*Buffer, bool) {
	if reserved < 0 || payloadCapacity < 0 || reserved > maxInt-payloadCapacity {
		return nil, false
	}

	b := bufferPool.Get().(*Buffer)
	limit := reserved + payloadCapacity
	lease, ok := pool.AcquireLease(limit)
	if !ok {
		bufferPool.Put(b)
		return nil, false
	}
	bytes, ok := lease.Bytes(limit)
	if !ok {
		lease.Release()
		bufferPool.Put(b)
		return nil, false
	}
	*b = Buffer{
		buf:      bytes,
		lease:    lease,
		reserved: reserved,
		start:    reserved,
		end:      reserved,
		limit:    limit,
	}
	return b, true
}

// Release returns the backing slab to the pool. It is idempotent.
func (b *Buffer) Release() {
	if b == nil || b.released {
		return
	}
	lease := b.lease
	*b = Buffer{released: true}
	lease.Release()
	bufferPool.Put(b)
}

// Push reserves n header bytes immediately before the current header and
// returns them for writing.
func (b *Buffer) Push(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.availableHeader() {
		return nil, false
	}
	b.start -= n
	return b.buf[b.start : b.start+n], true
}

// Append reserves n payload bytes at the tail and returns them for writing.
func (b *Buffer) Append(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.limit-b.end {
		return nil, false
	}
	start := b.end
	b.end += n
	return b.buf[start:b.end], true
}

// Consume returns the next n bytes and advances the read position. If fewer
// than n bytes remain, it returns nil, false and leaves the position unchanged.
func (b *Buffer) Consume(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.end-b.start {
		return nil, false
	}
	start := b.start
	b.start += n
	return b.buf[start:b.start], true
}

// Header returns the unconsumed header bytes.
func (b *Buffer) Header() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	if b.start >= b.reserved {
		return b.buf[b.reserved:b.reserved], true
	}
	return b.buf[b.start:b.reserved], true
}

// Payload returns the unconsumed payload bytes.
func (b *Buffer) Payload() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	start := b.start
	if start < b.reserved {
		start = b.reserved
	}
	return b.buf[start:b.end], true
}

// Bytes returns all unconsumed bytes in wire order.
func (b *Buffer) Bytes() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	return b.buf[b.start:b.end], true
}

// AvailableHeader returns the number of header bytes that can be pushed.
func (b *Buffer) AvailableHeader() (int, bool) {
	if !b.live() {
		return 0, false
	}
	return b.availableHeader(), true
}

// AvailablePayload returns the number of payload bytes that can be appended.
func (b *Buffer) AvailablePayload() (int, bool) {
	if !b.live() {
		return 0, false
	}
	return b.limit - b.end, true
}

func (b *Buffer) availableHeader() int {
	if b.start > b.reserved {
		return 0
	}
	return b.start
}

func (b *Buffer) live() bool {
	return b != nil && !b.released
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(Buffer)
	},
}

const maxInt = int(^uint(0) >> 1)
