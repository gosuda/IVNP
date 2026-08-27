// Package pool provides power-of-two reusable byte slabs for high-throughput networking paths.
package pool

import (
	"math/bits"
	"sync"
)

const (
	minClass  = 8  // 256 bytes
	maxClass  = 16 // 65536 bytes
	maxPooled = 1 << maxClass
)

var (
	slabs      [maxClass - minClass + 1]sync.Pool
	leaseSlabs [maxClass - minClass + 1]sync.Pool
)

func init() {
	for i := range slabs {
		size := 1 << (minClass + i)
		class := i
		slabs[i].New = func() any { return make([]byte, size) }
		leaseSlabs[i].New = func() any {
			return &Lease{buf: make([]byte, size), class: class}
		}
	}
}

// Lease holds a pooled slab without slice header boxing overhead on release.
// Bytes returns a slice into the lease and becomes invalid once the lease is released.
type Lease struct {
	buf      []byte
	class    int
	released bool
}

// AcquireLease returns a pooled slab lease with at least n bytes of capacity.
func AcquireLease(n int) (*Lease, bool) {
	if n < 0 {
		return nil, false
	}
	if n == 0 {
		return &Lease{class: -1}, true
	}
	class, ok := classFor(n)
	if !ok {
		return &Lease{buf: make([]byte, n), class: -1}, true
	}
	lease := leaseSlabs[class].Get().(*Lease)
	lease.released = false
	return lease, true
}

// Bytes returns a slice of n bytes from the leased slab.
func (l *Lease) Bytes(n int) ([]byte, bool) {
	if l == nil || l.released || n < 0 || n > cap(l.buf) {
		return nil, false
	}
	return l.buf[:n], true
}

// Release returns the lease to its slab pool. It is safe to call multiple times.
func (l *Lease) Release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	if l.class < 0 {
		return
	}
	leaseSlabs[l.class].Put(l)
}

// ReleaseSensitive zeroes the backing memory before returning the lease to the pool.
func (l *Lease) ReleaseSensitive() {
	if l == nil || l.released {
		return
	}
	clear(l.buf[:cap(l.buf)])
	l.Release()
}

// Acquire returns a byte slice of length n backed by a pooled slab (up to 64 KiB).
// Slices larger than 64 KiB are allocated directly and not pooled.
func Acquire(n int) ([]byte, bool) {
	if n < 0 {
		return nil, false
	}
	if n == 0 {
		return nil, true
	}
	class, ok := classFor(n)
	if !ok {
		return make([]byte, n), true
	}
	return slabs[class].Get().([]byte)[:n], true
}

// Release returns a buffer to its corresponding slab pool.
func Release(buf []byte) {
	class, ok := classFor(cap(buf))
	if !ok || cap(buf) != 1<<(minClass+class) {
		return
	}
	slabs[class].Put(buf[:cap(buf)])
}

// ReleaseSensitive zeroes the backing memory before returning the buffer to the pool.
func ReleaseSensitive(buf []byte) {
	if buf == nil {
		return
	}
	clear(buf[:cap(buf)])
	Release(buf)
}

func classFor(n int) (int, bool) {
	if n <= 0 || n > maxPooled {
		return 0, false
	}
	exponent := max(bits.Len(uint(n-1)), minClass)
	return exponent - minClass, true
}
