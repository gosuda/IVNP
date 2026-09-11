package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// DialFunc abstracts network reachability probes for testing.
type DialFunc func(ctx context.Context, network, address string) (time.Duration, error)

func defaultDialProbe(ctx context.Context, network, address string) (time.Duration, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// Prober runs concurrent connectivity and latency probes across known peers.
type Prober struct {
	store       *PeerStore
	workers     int
	probeDialer DialFunc
}

func NewProber(store *PeerStore, workers int) *Prober {
	if workers <= 0 {
		workers = 32
	}
	return &Prober{
		store:       store,
		workers:     workers,
		probeDialer: defaultDialProbe,
	}
}

func (p *Prober) SetDialer(d DialFunc) {
	p.probeDialer = d
}

// ProbeAll runs a probing pass against all peers currently in store.
func (p *Prober) ProbeAll(ctx context.Context) int {
	peers := p.store.Snapshot()
	if len(peers) == 0 {
		return 0
	}

	jobs := make(chan PeerRecord, len(peers))
	for _, rec := range peers {
		jobs <- rec
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := min(p.workers, len(peers))
	var successCount sync.Map

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rec := range jobs {
				if ctx.Err() != nil {
					return
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
	// Candidate target endpoints (IPv4 preferred for wider compatibility)
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

	// Probe the first reachable target
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
