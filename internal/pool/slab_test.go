package pool

import (
	"testing"
)

func TestAcquireClassSizing(t *testing.T) {
	for _, size := range []int{1, 256, 257, 1024, 65536} {
		buf, ok := Acquire(size)
		if !ok {
			t.Fatalf("Acquire(%d) failed", size)
		}
		if len(buf) != size {
			t.Fatalf("Acquire(%d) length = %d", size, len(buf))
		}
		if cap(buf) < size {
			t.Fatalf("Acquire(%d) capacity = %d", size, cap(buf))
		}
		Release(buf)
	}
}

func TestReleaseSensitiveWipesEntireBackingStorage(t *testing.T) {
	buf, ok := Acquire(257)
	if !ok {
		t.Fatal("Acquire failed")
	}
	backing := buf[:cap(buf)]
	for i := range backing {
		backing[i] = 0xff
	}
	ReleaseSensitive(buf)

	// No parallel tests or intervening acquisitions may reuse this released slab.
	for i, value := range backing {
		if value != 0 {
			t.Fatalf("backing byte %d = %#x after sensitive release", i, value)
		}
	}
}

func BenchmarkAcquireRelease(b *testing.B) {
	buf, ok := Acquire(1024)
	if !ok {
		b.Fatal("Acquire failed")
	}
	Release(buf)
	b.ReportAllocs()
	for b.Loop() {
		buf, ok = Acquire(1024)
		if !ok {
			b.Fatal("Acquire failed")
		}
		Release(buf)
	}
}

func BenchmarkAcquireLeaseRelease(b *testing.B) {
	lease, ok := AcquireLease(1024)
	if !ok {
		b.Fatal("AcquireLease failed")
	}
	lease.Release()
	b.ReportAllocs()
	for b.Loop() {
		lease, ok = AcquireLease(1024)
		if !ok {
			b.Fatal("AcquireLease failed")
		}
		lease.Release()
	}
}

func TestAcquireRejectsNegativeSize(t *testing.T) {
	if buf, ok := Acquire(-1); ok || buf != nil {
		t.Fatalf("Acquire(-1) = %v, %t", buf, ok)
	}
	if lease, ok := AcquireLease(-1); ok || lease != nil {
		t.Fatalf("AcquireLease(-1) = %v, %t", lease, ok)
	}
}

func TestLeaseReleaseIsIdempotent(t *testing.T) {
	lease, ok := AcquireLease(1)
	if !ok {
		t.Fatal("AcquireLease failed")
	}
	if _, ok := lease.Bytes(1); !ok {
		t.Fatal("leased bytes unavailable")
	}
	lease.Release()
	lease.Release()
	if bytes, ok := lease.Bytes(1); ok || bytes != nil {
		t.Fatalf("released lease bytes = %v, %t", bytes, ok)
	}
}

func TestLeaseReleaseSensitiveWipesEntireBackingStorage(t *testing.T) {
	lease, ok := AcquireLease(257)
	if !ok {
		t.Fatal("AcquireLease failed")
	}
	backing, ok := lease.Bytes(cap(lease.buf))
	if !ok {
		t.Fatal("leased slab capacity unavailable")
	}
	for index := range backing {
		backing[index] = 0xff
	}
	lease.ReleaseSensitive()

	// Observe the released storage before any acquisition can reuse it.
	for index, value := range backing {
		if value != 0 {
			t.Fatalf("backing byte %d = %#x after sensitive lease release", index, value)
		}
	}
}
