package tunnel

import (
	"sync/atomic"
)

const (
	// DefaultInitialSuccessRateBasisPoints represents 30.00% initial success probability.
	DefaultInitialSuccessRateBasisPoints = 3000
	// BasisPointsTotal represents 100.00%.
	BasisPointsTotal = 10000

	// Bayesian smoothing prior: equivalent to 3 successes out of 10 prior virtual attempts (30.00%).
	priorSuccesses = 3
	priorFailures  = 7
	priorTotal     = priorSuccesses + priorFailures

	// decayThreshold triggers opportunistic halving of packed counts to maintain
	// a bounded rolling window where recent observations dominate.
	decayThreshold = 256
)

// BuildStatistics tracks tunnel build success and failure outcomes using lock-free
// atomic operations, providing zero-allocation and contention-free metrics.
type BuildStatistics struct {
	// packed stores: upper 32 bits = successes, lower 32 bits = failures.
	inbound  atomic.Uint64
	outbound atomic.Uint64
}

// NewBuildStatistics creates an initialized BuildStatistics with a 30% initial Bayesian prior.
func NewBuildStatistics() *BuildStatistics {
	return &BuildStatistics{}
}

// Record updates the directional outcome counter using a lock-free atomic addition.
func (s *BuildStatistics) Record(direction Direction, success bool) {
	if s == nil {
		return
	}
	target := &s.inbound
	if direction == Outbound {
		target = &s.outbound
	}
	if success {
		target.Add(1 << 32)
	} else {
		target.Add(1)
	}
	v := target.Load()
	successes := uint32(v >> 32)
	failures := uint32(v & 0xffffffff)
	if successes+failures >= decayThreshold {
		newPacked := (uint64(successes/2) << 32) | uint64(failures/2)
		_ = target.CompareAndSwap(v, newPacked)
	}
}

// SuccessRateBasisPoints calculates the current empirical success rate in basis points (0..10000),
// incorporating Bayesian smoothing so cold start returns exactly 3000 (30.00%).
func (s *BuildStatistics) SuccessRateBasisPoints(direction Direction) int {
	if s == nil {
		return DefaultInitialSuccessRateBasisPoints
	}
	target := &s.inbound
	if direction == Outbound {
		target = &s.outbound
	}
	v := target.Load()
	successes := uint32(v >> 32)
	failures := uint32(v & 0xffffffff)
	total := successes + failures
	num := uint64(successes+priorSuccesses) * BasisPointsTotal
	den := uint64(total + priorTotal)
	return int(num / den)
}

// ParallelLimit computes how many parallel builds to attempt to achieve needed successes,
// given the current empirical success rate, clamped between needed and maxLimit.
func (s *BuildStatistics) ParallelLimit(direction Direction, needed int, maxLimit int) int {
	if needed <= 0 {
		return 0
	}
	if maxLimit <= 0 {
		maxLimit = defaultMaxPendingBuilds
	}
	rate := s.SuccessRateBasisPoints(direction)
	if rate <= 0 {
		rate = DefaultInitialSuccessRateBasisPoints
	}
	k := (needed*BasisPointsTotal + rate - 1) / rate
	if k < needed {
		k = needed
	}
	if k > maxLimit {
		k = maxLimit
	}
	return k
}

// Snapshot returns the current raw successes, failures, and computed basis points.
func (s *BuildStatistics) Snapshot(direction Direction) (successes, failures int, rateBasisPoints int) {
	if s == nil {
		return 0, 0, DefaultInitialSuccessRateBasisPoints
	}
	target := &s.inbound
	if direction == Outbound {
		target = &s.outbound
	}
	v := target.Load()
	succ := int(uint32(v >> 32))
	fail := int(uint32(v & 0xffffffff))
	rate := s.SuccessRateBasisPoints(direction)
	return succ, fail, rate
}
