package router

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDestinationBandwidthLimitersAreIndependent(t *testing.T) {
	now := time.Unix(1, 0)
	newLimiter := func() *DestinationBandwidthLimiter {
		limiter, err := NewDestinationBandwidthLimiter(DestinationBandwidthConfig{
			RateBytesPerSecond: 100, BurstBytes: 10, Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		return limiter
	}
	first, second := newLimiter(), newLimiter()
	if !first.TryAcquire(10) || first.TryAcquire(1) {
		t.Fatal("first destination did not saturate at its own burst")
	}
	if !second.TryAcquire(1) {
		t.Fatal("first destination saturation blocked its sibling")
	}
	firstSnapshot, secondSnapshot := first.Snapshot(), second.Snapshot()
	if firstSnapshot.AvailableBytes != 0 || secondSnapshot.AvailableBytes != 9 || firstSnapshot.BackpressuredBytes == 0 || secondSnapshot.BackpressuredBytes != 0 {
		t.Fatalf("independent snapshots = %#v / %#v", firstSnapshot, secondSnapshot)
	}

	now = now.Add(50 * time.Millisecond)
	if !first.TryAcquire(5) || first.TryAcquire(1) {
		t.Fatal("monotonic refill did not pace exactly five bytes")
	}
	if second.Snapshot().AvailableBytes != 10 {
		t.Fatal("refilling first destination changed sibling tokens")
	}
}

func TestDestinationBandwidthBackpressureHonorsCancellation(t *testing.T) {
	limiter, err := NewDestinationBandwidthLimiter(DestinationBandwidthConfig{
		RateBytesPerSecond: 1, BurstBytes: 1, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.TryAcquire(1) {
		t.Fatal("initial token was not admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = limiter.Wait(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled backpressure = %v", err)
	}
	if err = limiter.Wait(context.Background(), 2); !errors.Is(err, ErrDestinationBandwidth) {
		t.Fatalf("oversized request = %v", err)
	}
}
