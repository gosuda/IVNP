package router

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrDestinationBandwidthConfig = errors.New("router: invalid destination bandwidth configuration")
	ErrDestinationBandwidth       = errors.New("router: destination bandwidth exhausted")
)

// DestinationBandwidthConfig defines one destination-local byte token bucket.
// Now must return a monotonic time source. RateBytesPerSecond and BurstBytes
// are deliberately integral so snapshots never expose traffic contents.
type DestinationBandwidthConfig struct {
	RateBytesPerSecond uint64
	BurstBytes         uint64
	Now                func() time.Time
}

// DestinationBandwidthSnapshot is a non-sensitive, consistent view of one
// destination's pacing state.
type DestinationBandwidthSnapshot struct {
	RateBytesPerSecond uint64
	BurstBytes         uint64
	AvailableBytes     uint64
	AcceptedBytes      uint64
	BackpressuredBytes uint64
	Waiters            uint32
}

// DestinationBandwidthLimiter is a bounded token bucket owned by exactly one
// local destination. It contains no process-global state and is safe for
// concurrent ingress and egress use.
type DestinationBandwidthLimiter struct {
	mu       sync.Mutex
	rate     uint64
	burst    uint64
	tokens   uint64
	fraction uint64
	last     time.Time
	now      func() time.Time
	accepted uint64
	blocked  uint64
	waiters  uint32
}

func NewDestinationBandwidthLimiter(config DestinationBandwidthConfig) (*DestinationBandwidthLimiter, error) {
	if config.RateBytesPerSecond == 0 || config.BurstBytes == 0 || config.RateBytesPerSecond > uint64(^uint32(0)) || config.BurstBytes > uint64(^uint32(0)) {
		return nil, ErrDestinationBandwidthConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	now := config.Now()
	return &DestinationBandwidthLimiter{
		rate: config.RateBytesPerSecond, burst: config.BurstBytes,
		tokens: config.BurstBytes, last: now, now: config.Now,
	}, nil
}

// TryAcquire admits n bytes without waiting. Oversized requests are rejected
// because no request may consume more than the configured bounded burst.
func (l *DestinationBandwidthLimiter) TryAcquire(n uint64) bool {
	if l == nil || n == 0 {
		return n == 0
	}
	l.mu.Lock()
	l.refillLocked(l.now())
	if n > l.burst || n > l.tokens {
		l.blocked = saturatingCounterAdd(l.blocked, n)
		l.mu.Unlock()
		return false
	}
	l.tokens -= n
	l.accepted = saturatingCounterAdd(l.accepted, n)
	l.mu.Unlock()
	return true
}

// Wait applies destination-local backpressure until n bytes are available or
// ctx is cancelled. No goroutine or global scheduler is retained by the
// limiter. Cancellation is checked before every token transition.
func (l *DestinationBandwidthLimiter) Wait(ctx context.Context, n uint64) error {
	if l == nil {
		return ErrDestinationBandwidthConfig
	}
	if n == 0 {
		return nil
	}
	if n > l.burst {
		l.mu.Lock()
		l.blocked = saturatingCounterAdd(l.blocked, n)
		l.mu.Unlock()
		return ErrDestinationBandwidth
	}
	if ctx ==
		nil {
		ctx = context.Background()
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := l.now()
		l.refillLocked(now)
		if n <= l.tokens {
			l.tokens -= n
			l.accepted = saturatingCounterAdd(l.accepted, n)
			l.mu.Unlock()
			return nil
		}
		missing := n - l.tokens
		l.blocked = saturatingCounterAdd(l.blocked, missing)
		l.waiters++
		rate := l.rate
		l.mu.Unlock()

		delay := time.Duration((missing*uint64(time.Second) + rate - 1) / rate)
		if delay <= 0 {
			delay = time.Nanosecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			l.mu.Lock()
			l.waiters--
			l.mu.Unlock()
			return ctx.Err()
		case <-timer.C:
			l.mu.Lock()
			l.waiters--
			l.mu.Unlock()
		}
	}
}

func (l *DestinationBandwidthLimiter) Snapshot() DestinationBandwidthSnapshot {
	if l == nil {
		return DestinationBandwidthSnapshot{}
	}
	l.mu.Lock()
	l.refillLocked(l.now())
	snapshot := DestinationBandwidthSnapshot{
		RateBytesPerSecond: l.rate, BurstBytes: l.burst, AvailableBytes: l.tokens,
		AcceptedBytes: l.accepted, BackpressuredBytes: l.blocked, Waiters: l.waiters,
	}
	l.mu.Unlock()
	return snapshot
}

func (l *DestinationBandwidthLimiter) refillLocked(now time.Time) {
	if now.Before(l.last) {
		// A source without a monotonic component may move backwards. Never mint
		// tokens in that case; retain the last observed instant.
		return
	}
	elapsed := now.Sub(l.last)
	if elapsed <= 0 || l.tokens == l.burst {
		l.last = now
		if l.tokens == l.burst {
			l.fraction = 0
		}
		return
	}
	seconds := uint64(elapsed / time.Second)
	nanos := uint64(elapsed % time.Second)
	missing := l.burst - l.tokens
	secondsToFill := (missing + l.rate - 1) / l.rate
	if seconds >= secondsToFill {
		l.tokens = l.burst
		l.fraction = 0
		l.last = now
		return
	}
	added := seconds * l.rate
	partial := nanos*l.rate + l.fraction
	added += partial / uint64(time.Second)
	l.fraction = partial % uint64(time.Second)
	if added >= missing {
		l.tokens = l.burst
		l.fraction = 0
	} else {
		l.tokens += added
	}
	l.last = now
}

func saturatingCounterAdd(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}
