//go:build dst || synctest

package durable_test

import (
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/internal/durable"
)

func TestWaitGroupWaitAdvancesVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg durable.WaitGroup
		start := time.Now()
		const work = 3 * time.Second
		wg.Go(func() {
			time.Sleep(work)
		})
		wg.Wait()
		// >= not == : incidental bubble timers may add to the elapsed time,
		// but the Wait itself must span the workers' virtual duration.
		if elapsed := time.Since(start); elapsed < work {
			t.Fatalf("Wait advanced %v, want at least %v", elapsed, work)
		}
	})
}
