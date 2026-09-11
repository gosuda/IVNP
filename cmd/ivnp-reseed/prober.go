package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// DialFunc abstracts network reachability probes for testing.
type DialFunc func(ctx context.Context, network, address string) (time.Duration, error)

func defaultDialProbe(ctx context.Context, network, address string) (time.Duration, error) {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	start := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// TokenBucketRateLimiter ensures outgoing probe rate does not trigger DDoS / flood alerts.
type TokenBucketRateLimiter struct {
	rate       float64
	capacity   float64
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucketRateLimiter(rate, capacity float64) *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucketRateLimiter) Wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastRefill).Seconds()
		tb.lastRefill = now
		tb.tokens = min(tb.capacity, tb.tokens+elapsed*tb.rate)

		if tb.tokens >= 1.0 {
			tb.tokens -= 1.0
			tb.mu.Unlock()
			return nil
		}

		sleepNeeded := time.Duration((1.0 - tb.tokens) / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepNeeded):
		}
	}
}

// Prober runs rate-limited, non-disruptive connectivity probes across known peers.
type Prober struct {
	store       *PeerStore
	workers     int
	probeDialer DialFunc
	limiter     *TokenBucketRateLimiter
}

func NewProber(store *PeerStore, workers int) *Prober {
	if workers <= 0 {
		workers = 16 // Bounded worker count
	}
	return &Prober{
		store:       store,
		workers:     workers,
		probeDialer: defaultDialProbe,
		limiter:     NewTokenBucketRateLimiter(DefaultProbeRateLimit, 20.0),
	}
}

func (p *Prober) SetDialer(d DialFunc) {
	p.probeDialer = d
}

// ProbeAll runs a rate-limited probing pass against peers eligible for probing.
func (p *Prober) ProbeAll(ctx context.Context) int {
	peers := p.store.Snapshot()
	if len(peers) == 0 {
		return 0
	}

	now := time.Now()
	var candidates []PeerRecord
	for _, rec := range peers {
		// Respect per-peer cooldown to avoid nagging peers
		if now.Sub(rec.Stats.LastProbed) >= ProbeCooldownInterval {
			candidates = append(candidates, rec)
		}
	}

	if len(candidates) == 0 {
		return 0
	}

	// Prioritize: unprobed newcomers first, then floodfills, then longest cooldown
	slices.SortFunc(candidates, func(a, b PeerRecord) int {
		if (a.Stats.TotalProbes == 0) != (b.Stats.TotalProbes == 0) {
			if a.Stats.TotalProbes == 0 {
				return -1
			}
			return 1
		}
		if a.IsFloodfill != b.IsFloodfill {
			if a.IsFloodfill {
				return -1
			}
			return 1
		}
		return a.Stats.LastProbed.Compare(b.Stats.LastProbed)
	})

	jobs := make(chan PeerRecord, len(candidates))
	for _, rec := range candidates {
		jobs <- rec
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := min(p.workers, len(candidates))
	var successCount sync.Map

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rec := range jobs {
				if ctx.Err() != nil {
					return
				}
				// Rate limit: pause if token rate exceeded
				if p.limiter != nil {
					if err := p.limiter.Wait(ctx); err != nil {
						return
					}
				}
				success, rtt := p.probePeer(ctx, rec)
				p.store.RecordProbeResult(rec.Hash, success, rtt)
				if success {
					successCount.Store(rec.Hash, struct{}{})
				}
			}
		}()
	}

	wg.Wait()
	totalSuccess := 0
	successCount.Range(func(_, _ any) bool {
		totalSuccess++
		return true
	})
	return totalSuccess
}

func (p *Prober) probePeer(ctx context.Context, rec PeerRecord) (bool, time.Duration) {
	var targets []string
	addEndpoints := func(ips []netip.Addr, ports []uint16) {
		for _, ip := range ips {
			for _, port := range ports {
				targets = append(targets, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			}
		}
	}

	addEndpoints(rec.IPv4, rec.Ports)
	if len(targets) == 0 {
		addEndpoints(rec.IPv6, rec.Ports)
	}

	if len(targets) == 0 {
		return false, 0
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			return false, 0
		}
		rtt, err := p.probeDialer(ctx, "tcp", target)
		if err == nil {
			return true, rtt
		}
	}

	return false, 0
}

func (p *Prober) ProbeSingle(ctx context.Context, hash foundation.Hash) (bool, time.Duration) {
	peers := p.store.Snapshot()
	for _, rec := range peers {
		if rec.Hash == hash {
			success, rtt := p.probePeer(ctx, rec)
			p.store.RecordProbeResult(hash, success, rtt)
			return success, rtt
		}
	}
	return false, 0
}
