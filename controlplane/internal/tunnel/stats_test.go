package tunnel

import (
	"sync"
	"testing"
)

func TestBuildStatisticsInitialColdStart(t *testing.T) {
	stats := NewBuildStatistics()
	for _, dir := range []Direction{Inbound, Outbound} {
		rate := stats.SuccessRateBasisPoints(dir)
		if rate != DefaultInitialSuccessRateBasisPoints {
			t.Fatalf("cold start %v rate=%d, want %d", dir, rate, DefaultInitialSuccessRateBasisPoints)
		}
		// Needed = 1 at 30% -> ceil(10000 / 3000) = 4
		if limit := stats.ParallelLimit(dir, 1, 32); limit != 4 {
			t.Fatalf("limit needed=1 rate=30%% got=%d, want 4", limit)
		}
		// Needed = 2 at 30% -> ceil(20000 / 3000) = 7
		if limit := stats.ParallelLimit(dir, 2, 32); limit != 7 {
			t.Fatalf("limit needed=2 rate=30%% got=%d, want 7", limit)
		}
		// Needed = 10 at 30% -> ceil(100000 / 3000) = 34 -> clamped to 32
		if limit := stats.ParallelLimit(dir, 10, 32); limit != 32 {
			t.Fatalf("limit needed=10 clamped got=%d, want 32", limit)
		}
	}
}

func TestBuildStatisticsBayesianConvergence(t *testing.T) {
	stats := NewBuildStatistics()

	// Record 90 successes and 10 failures
	for range 90 {
		stats.Record(Inbound, true)
	}
	for range 10 {
		stats.Record(Inbound, false)
	}

	// With prior (3 succ, 7 fail, total 10):
	// Total succ = 93, total fail = 17, total = 110
	// Rate = 93 * 10000 / 110 = 8454 (84.54%)
	rate := stats.SuccessRateBasisPoints(Inbound)
	wantRate := (93 * 10000) / 110
	if rate != wantRate {
		t.Fatalf("converged rate=%d, want %d", rate, wantRate)
	}

	// At ~84.5% success rate, needed = 1 -> ceil(10000 / 8454) = 2
	limit := stats.ParallelLimit(Inbound, 1, 32)
	if limit != 2 {
		t.Fatalf("limit needed=1 at 84.5%% got=%d, want 2", limit)
	}
}

func TestBuildStatisticsDecayThreshold(t *testing.T) {
	stats := NewBuildStatistics()

	// Push over decayThreshold (256): e.g. 200 successes, 60 failures = 260 total
	for range 200 {
		stats.Record(Outbound, true)
	}
	for range 60 {
		stats.Record(Outbound, false)
	}

	succ, fail, _ := stats.Snapshot(Outbound)
	// Should have decayed (halved)
	if succ+fail >= decayThreshold {
		t.Fatalf("expected decay, got total=%d >= %d", succ+fail, decayThreshold)
	}
	if succ == 0 || fail == 0 {
		t.Fatalf("decay zeroed counts: succ=%d fail=%d", succ, fail)
	}
}

func TestBuildStatisticsConcurrentRaceFree(t *testing.T) {
	stats := NewBuildStatistics()
	const goroutines = 16
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for g := range goroutines {
		// Writers
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				stats.Record(Inbound, (id+i)%3 == 0)
				stats.Record(Outbound, (id+i)%2 == 0)
			}
		}(g)

		// Readers
		go func() {
			defer wg.Done()
			for range iterations {
				_ = stats.SuccessRateBasisPoints(Inbound)
				_ = stats.ParallelLimit(Outbound, 2, 32)
				_, _, _ = stats.Snapshot(Inbound)
			}
		}()
	}

	wg.Wait()
}
