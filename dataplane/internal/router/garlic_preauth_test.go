package router

import (
	"sync"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestGarlicPreauthWorkBoundaries(t *testing.T) {
	var limiter garlicPreauthLimiter
	now := uint64(1_000_000)
	first := I2NPSource{Peer: foundation.Hash{1}, Direct: true}
	second := I2NPSource{Peer: foundation.Hash{2}, Direct: true}
	third := I2NPSource{Peer: foundation.Hash{3}, Direct: true}

	for range garlicCryptoSourceWorkLimit {
		if !limiter.allowWork(first, now) {
			t.Fatal("first source rejected before its limit")
		}
	}
	if limiter.allowWork(first, now) {
		t.Fatal("first source exceeded its limit")
	}
	for range garlicCryptoSourceWorkLimit {
		if !limiter.allowWork(second, now) {
			t.Fatal("second source rejected before global limit")
		}
	}
	if limiter.allowWork(third, now) {
		t.Fatal("global crypto work limit exceeded")
	}
	if limiter.allowWork(first, now+garlicCryptoWindowMillis-1) {
		t.Fatal("budget refilled before the next window")
	}
	if !limiter.allowWork(first, now+garlicCryptoWindowMillis) {
		t.Fatal("budget did not refill in the next window")
	}
}

func TestGarlicPreauthDoesNotTrustIndirectSource(t *testing.T) {
	var limiter garlicPreauthLimiter
	now := uint64(1_000_000)
	for range garlicCryptoSourceWorkLimit {
		if !limiter.allowWork(I2NPSource{Peer: foundation.Hash{1}}, now) {
			t.Fatal("indirect source exhausted prematurely")
		}
	}
	if limiter.allowWork(I2NPSource{Peer: foundation.Hash{2}}, now) {
		t.Fatal("untrusted peer field escaped the shared source limit")
	}
}

func TestGarlicPreauthDuplicateAndReservationLifetime(t *testing.T) {
	var limiter garlicPreauthLimiter
	now := uint64(1_000_000)
	packet := []byte("unauthenticated ciphertext")

	first, fresh := limiter.begin(packet, now)
	if !fresh {
		t.Fatal("first receipt was rejected")
	}
	if _, fresh := limiter.begin(packet, now); fresh {
		t.Fatal("in-flight duplicate was admitted")
	}
	limiter.forget(first)
	second, fresh := limiter.begin(packet, now)
	if !fresh {
		t.Fatal("released reservation was not retryable")
	}
	limiter.forget(first)
	if _, fresh := limiter.begin(packet, now); fresh {
		t.Fatal("stale completion removed a newer reservation")
	}
	if _, fresh := limiter.begin(packet, now+garlicInvalidCiphertextLifetime-1); fresh {
		t.Fatal("invalid ciphertext cache expired prematurely")
	}
	if _, fresh := limiter.begin(packet, now+garlicInvalidCiphertextLifetime); !fresh {
		t.Fatal("invalid ciphertext did not expire")
	}
	_ = second
}

func TestGarlicPreauthCacheCapacity(t *testing.T) {
	var limiter garlicPreauthLimiter
	now := uint64(1_000_000)
	old := []byte{7}
	if _, fresh := limiter.begin(old, now); !fresh {
		t.Fatal("first digest was rejected")
	}
	for index := range garlicInvalidCiphertextCapacity {
		packet := []byte{byte(index >> 8), byte(index), 0xcc}
		if _, fresh := limiter.begin(packet, now); !fresh {
			t.Fatal("unique digest was rejected")
		}
	}
	if len(limiter.cached) != garlicInvalidCiphertextCapacity {
		t.Fatalf("cache contains %d entries, limit %d", len(limiter.cached), garlicInvalidCiphertextCapacity)
	}
	if _, fresh := limiter.begin(old, now); !fresh {
		t.Fatal("evicted digest still blocked admission")
	}
}

func TestGarlicPreauthConcurrentDuplicates(t *testing.T) {
	var limiter garlicPreauthLimiter
	const goroutines = 16
	start := make(chan struct{})
	results := make(chan bool, goroutines)
	var workers sync.WaitGroup
	for range goroutines {
		workers.Go(func() {
			<-start
			_, admitted := limiter.begin([]byte("same ciphertext"), 1_000_000)
			results <- admitted
		})
	}
	close(start)
	workers.Wait()
	close(results)
	admitted := 0
	for result := range results {
		if result {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("concurrent admission count = %d, want 1", admitted)
	}
}
