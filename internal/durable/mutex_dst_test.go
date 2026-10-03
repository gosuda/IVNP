//go:build dst || synctest

package durable_test

import (
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/internal/durable"
)

func TestMutexContentionAdvancesVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu durable.Mutex
		mu.Lock()
		start := time.Now()
		const hold = 2 * time.Second
		go func() {
			time.Sleep(hold)
			mu.Unlock()
		}()
		mu.Lock()
		// >= not == : incidental bubble timers may add to the elapsed time,
		// but the contention itself must advance the fake clock by the hold.
		if elapsed := time.Since(start); elapsed < hold {
			t.Fatalf("contended Lock advanced %v, want at least %v", elapsed, hold)
		}
		mu.Unlock()
	})
}
