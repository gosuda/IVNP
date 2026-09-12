package main

import (
	"cmp"
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
		workers = 48 // Loosened bounded worker count
	}
	return &Prober{
		store:       store,
		workers:     workers,
		probeDialer: defaultDialProbe,
		limiter:     NewTokenBucketRateLimiter(DefaultProbeRateLimit, DefaultProbeBurst),
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

	reachableCount := p.store.ReachableCount()
	cooldownFailed := ProbeCooldownFailed
	if reachableCount < 1024 {
		cooldownFailed = 60 * time.Second // Rapid retry in expansion mode
	} else {
		cooldownFailed = 3 * time.Minute // Conservative backoff in maintenance mode
	}

	now := time.Now()
	var candidates []PeerRecord
	for _, rec := range peers {
		cooldown := ProbeCooldownReachable
		if rec.Stats.TotalProbes == 0 {
			cooldown = 0
		} else if rec.Stats.ConsecutiveFails > 0 {
			cooldown = cooldownFailed
		}
		if now.Sub(rec.Stats.LastProbed) >= cooldown {
			candidates = append(candidates, rec)
		}
	}

	if len(candidates) == 0 {
		return 0
	}

	reachableDist := p.store.ReachableBucketDistribution()

	// Prioritize:
	// 1. Sparse bucket deficit: candidate in bucket with < 4 reachable peers prioritized
	// 2. Unprobed newcomers first
	// 3. Floodfills first
	// 4. Longest elapsed since last probe
	slices.SortFunc(candidates, func(a, b PeerRecord) int {
		aBucketCount := reachableDist[a.Hash[0]]
		bBucketCount := reachableDist[b.Hash[0]]
		aDeficit := aBucketCount < 4
		bDeficit := bBucketCount < 4
		if aDeficit != bDeficit {
			if aDeficit {
				return -1
			}
			return 1
		}
		if aDeficit && aBucketCount != bBucketCount {
			return cmp.Compare(aBucketCount, bBucketCount)
		}

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
	// If the peer has TCP ports (NTCP/NTCP2), or fallback to general Ports if unclassified:
	tcpPorts := rec.TCPPorts
	if len(tcpPorts) == 0 && len(rec.UDPPorts) == 0 {
		tcpPorts = rec.Ports
	}

	var targets []string
	addEndpoints := func(ips []netip.Addr, ports []uint16) {
		for _, ip := range ips {
			if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			for _, port := range ports {
				targets = append(targets, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			}
		}
	}

	if len(tcpPorts) > 0 {
		addEndpoints(rec.IPv4, tcpPorts)
		if len(targets) == 0 {
			addEndpoints(rec.IPv6, tcpPorts)
		}
		for _, target := range targets {
			if ctx.Err() != nil {
				return false, 0
			}
			rtt, err := p.probeDialer(ctx, "tcp", target)
			if err == nil {
				// Reject localhost / host-local bridge sockets that complete in < 5ms
				if rtt < 5*time.Millisecond {
					continue
				}
				return true, rtt
			}
		}
	}

	// For peers with only UDP (SSU2) endpoints: do not fail them with TCP.
	// If the router recently received or admitted them, they are reachable.
	if len(rec.TCPPorts) == 0 && len(rec.UDPPorts) > 0 {
		if time.Since(rec.Stats.LastSeen) < 2*time.Hour {
			rtt := rec.Stats.EWMARTT
			if rtt <= 0 {
				rtt = 50 * time.Millisecond
			}
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
