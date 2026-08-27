// Package packet provides packet buffer primitives for zero-allocation I2NP packet encoding and parsing.
package packet

import (
	"sync"

	"gosuda.org/ivnp/internal/pool"
)

// Buffer is a single-owner packet buffer that supports prepending headers and appending payloads.
// It is not safe for concurrent use. Slices returned by its methods borrow the underlying memory.
type Buffer struct {
	buf      []byte
	lease    *pool.Lease
	reserved int
	start    int
	end      int
	limit    int
	released bool
}

// Acquire gets a Buffer with headroom for reserved header bytes and payloadCapacity payload bytes.
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

// Release returns the buffer and its underlying slab back to their pools.
func (b *Buffer) Release() {
	if b == nil || b.released {
		return
	}
	lease := b.lease
	*b = Buffer{released: true}
	lease.Release()
	bufferPool.Put(b)
}

// Push reserves n bytes in the header headroom and returns the writable slice.
func (b *Buffer) Push(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.availableHeader() {
		return nil, false
	}
	b.start -= n
	return b.buf[b.start : b.start+n], true
}

// Append reserves n bytes at the end of the payload and returns the writable slice.
func (b *Buffer) Append(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.limit-b.end {
		return nil, false
	}
	start := b.end
	b.end += n
	return b.buf[start:b.end], true
}

// Consume advances the read cursor by n bytes and returns the consumed slice.
func (b *Buffer) Consume(n int) ([]byte, bool) {
	if !b.live() || n < 0 || n > b.end-b.start {
		return nil, false
	}
	start := b.start
	b.start += n
	return b.buf[start:b.start], true
}

// Header returns the active header bytes.
func (b *Buffer) Header() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	if b.start >= b.reserved {
		return b.buf[b.reserved:b.reserved], true
	}
	return b.buf[b.start:b.reserved], true
}

// Payload returns the active payload bytes.
func (b *Buffer) Payload() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	start := max(b.start, b.reserved)
	return b.buf[start:b.end], true
}

// Bytes returns all active bytes (headers + payload).
func (b *Buffer) Bytes() ([]byte, bool) {
	if !b.live() {
		return nil, false
	}
	return b.buf[b.start:b.end], true
}

// AvailableHeader returns remaining header headroom.
func (b *Buffer) AvailableHeader() (int, bool) {
	if !b.live() {
		return 0, false
	}
	return b.availableHeader(), true
}

// AvailablePayload returns remaining payload capacity.
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
