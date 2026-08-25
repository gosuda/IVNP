// Package pool owns bounded reusable byte slabs for transport and I2NP hot paths.
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

// Lease owns one pooled slab without boxing a slice header on every Release.
// It is intended for higher-level single-owner buffers that can retain the
// lease until their explicit Release; Bytes aliases the lease and becomes
// invalid after Release.
type Lease struct {
	buf      []byte
	class    int
	released bool
}

// AcquireLease returns a single-owner slab lease sized to n writable bytes.
// Unlike Acquire, the hot Release path puts a pointer into sync.Pool and does
// not allocate a boxed slice header.
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

// Bytes returns n bytes from the leased slab. It fails rather than panicking
// when called after Release or beyond the lease capacity.
func (l *Lease) Bytes(n int) ([]byte, bool) {
	if l == nil || l.released || n < 0 || n > cap(l.buf) {
		return nil, false
	}
	return l.buf[:n], true
}

// Release returns a leased slab to its original pool. It is idempotent.
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

// ReleaseSensitive clears the complete backing slab before returning it to its
// original pool. It is idempotent and also clears oversized unpooled leases.
func (l *Lease) ReleaseSensitive() {
	if l == nil || l.released {
		return
	}
	clear(l.buf[:cap(l.buf)])
	l.Release()
}

// Acquire returns n writable bytes. Requests up to 64 KiB are served by a
// power-of-two sync.Pool class; larger requests are deliberately unpooled.
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

// Release returns a non-sensitive slab. Callers must not retain buf after it
// is released. Arbitrary or oversized slices are dropped instead of pooled.
func Release(buf []byte) {
	class, ok := classFor(cap(buf))
	if !ok || cap(buf) != 1<<(minClass+class) {
		return
	}
	slabs[class].Put(buf[:cap(buf)])
}

// ReleaseSensitive clears every byte in the backing slab before pooling it.
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
	exponent := bits.Len(uint(n - 1))
	if exponent < minClass {
		exponent = minClass
	}
	return exponent - minClass, true
}
