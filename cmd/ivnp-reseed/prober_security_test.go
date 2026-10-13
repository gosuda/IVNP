package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
)

func TestProberPreservesRouterInfoEndpointPairs(t *testing.T) {
	info, raw := createTestRouterInfoWithEndpoints(t, bytes.Repeat([]byte{11}, 32), "LR", []testRouterEndpoint{
		{host: "198.51.100.10", port: "1101", style: "NTCP2"},
		{host: "198.51.100.11", port: "2202", style: "NTCP2"},
		{host: "198.51.100.12", port: "3303", style: "SSU2"},
		{host: "2001:db8::12", port: "4404", style: "NTCP2"},
	}, "", 1000)
	store := NewPeerStore()
	rec, added := store.AddOrUpdate(info, raw)
	if !added || rec == nil {
		t.Fatal("test RouterInfo was not admitted")
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.10:1101"),
		netip.MustParseAddrPort("198.51.100.11:2202"),
		netip.MustParseAddrPort("[2001:db8::12]:4404"),
	}
	if !slices.Equal(rec.ProbeEndpoints, want) {
		t.Fatalf("probe endpoints = %v, want %v", rec.ProbeEndpoints, want)
	}

	prober := NewProber(store, 1)
	var targets []string
	prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
		if network != "tcp" {
			t.Fatalf("probe network = %q, want tcp", network)
		}
		targets = append(targets, address)
		return 0, errMockDialFailed
	})
	if success, _ := prober.ProbeSingle(context.Background(), rec.Hash); success {
		t.Fatal("every dial failed; peer must not be reachable")
	}
	if wantTargets := []string{"198.51.100.10:1101", "198.51.100.11:2202"}; !slices.Equal(targets, wantTargets) {
		t.Fatalf("dialed %v, want exact IPv4 TCP pairs %v", targets, wantTargets)
	}
}

func TestProberBoundsAttemptsPerPeer(t *testing.T) {
	endpoints := make([]testRouterEndpoint, MaxProbeAttemptsPerPeer+1)
	for i := range endpoints {
		endpoints[i] = testRouterEndpoint{
			host:  fmt.Sprintf("198.51.100.%d", i+10),
			port:  fmt.Sprintf("%d", 2000+i),
			style: "NTCP2",
		}
	}
	info, raw := createTestRouterInfoWithEndpoints(t, bytes.Repeat([]byte{12}, 32), "LR", endpoints, "", 1000)
	tests := []struct {
		name        string
		successAt   int
		wantSuccess bool
	}{
		{name: "last allowed dial succeeds", successAt: MaxProbeAttemptsPerPeer, wantSuccess: true},
		{name: "first excess dial cannot succeed", successAt: MaxProbeAttemptsPerPeer + 1, wantSuccess: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewPeerStore()
			rec, added := store.AddOrUpdate(info, raw)
			if !added || rec == nil {
				t.Fatal("test RouterInfo was not admitted")
			}
			prober := NewProber(store, 1)
			attempts := 0
			prober.SetDialer(func(_ context.Context, _, _ string) (time.Duration, error) {
				attempts++
				if attempts == tt.successAt {
					return 40 * time.Millisecond, nil
				}
				return 0, errMockDialFailed
			})
			success, _ := prober.ProbeSingle(context.Background(), rec.Hash)
			if success != tt.wantSuccess {
				t.Fatalf("probe success = %v, want %v", success, tt.wantSuccess)
			}
			if attempts != MaxProbeAttemptsPerPeer {
				t.Fatalf("dial attempts = %d, want exactly %d", attempts, MaxProbeAttemptsPerPeer)
			}
		})
	}
}

func TestProberChargesRateLimiterPerDial(t *testing.T) {
	info, raw := createTestRouterInfoWithEndpoints(t, bytes.Repeat([]byte{13}, 32), "LR", []testRouterEndpoint{
		{host: "198.51.100.20", port: "1201", style: "NTCP2"},
		{host: "198.51.100.21", port: "1202", style: "NTCP2"},
	}, "", 1000)
	tests := []struct {
		name string
		run  func(context.Context, *Prober, foundation.Hash)
	}{
		{name: "ProbeAll", run: func(ctx context.Context, p *Prober, _ foundation.Hash) {
			p.ProbeAll(ctx)
		}},
		{name: "ProbeSingle", run: func(ctx context.Context, p *Prober, hash foundation.Hash) {
			p.ProbeSingle(ctx, hash)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewPeerStore()
			rec, added := store.AddOrUpdate(info, raw)
			if !added || rec == nil {
				t.Fatal("test RouterInfo was not admitted")
			}
			prober := NewProber(store, 1)
			prober.limiter = NewTokenBucketRateLimiter(1, 1)
			var attempts atomic.Int32
			prober.SetDialer(func(_ context.Context, _, _ string) (time.Duration, error) {
				attempts.Add(1)
				return 0, errMockDialFailed
			})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			tt.run(ctx, prober, rec.Hash)
			if got := attempts.Load(); got != 1 {
				t.Fatalf("dial attempts with only one rate-limit token = %d, want 1", got)
			}
			if ctx.Err() != context.DeadlineExceeded {
				t.Fatalf("second dial must wait for a token until deadline; ctx error = %v", ctx.Err())
			}
		})
	}
}

func TestProberRebuildsCachedEndpointsFromRouterInfo(t *testing.T) {
	info, raw := createTestRouterInfoWithEndpoint(t, bytes.Repeat([]byte{14}, 32), "LR", "198.51.100.30", "3333", "", 1000)
	store := NewPeerStore()
	rec, added := store.AddOrUpdate(info, raw)
	if !added || rec == nil {
		t.Fatal("test RouterInfo was not admitted")
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.30:3333")}
	for _, tt := range []struct {
		name      string
		endpoints []netip.AddrPort
	}{
		{name: "old cache without endpoints"},
		{name: "cache with forged targets", endpoints: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9000")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cached := *rec
			cached.ProbeEndpoints = tt.endpoints
			data, err := json.Marshal([]PeerRecord{cached})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "peers.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			loaded := NewPeerStore()
			if err := loaded.LoadFromFile(path); err != nil {
				t.Fatal(err)
			}
			snapshot := loaded.Snapshot()
			if len(snapshot) != 1 || !slices.Equal(snapshot[0].ProbeEndpoints, want) {
				t.Fatalf("recovered endpoints = %v, want %v", snapshot, want)
			}
		})
	}
}
