package main

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestProberPreservesRouterAddressPairs(t *testing.T) {
	info, raw := createTestRouterInfoWithEndpoints(t, bytes.Repeat([]byte{23}, 32), "LR", []testRouterAddress{
		{style: "NTCP2", host: "198.51.100.10", port: "1001"},
		{style: "SSU2", host: "198.51.100.20", port: "2002"},
		{style: "NTCP2", host: "198.51.100.11", port: "1003"},
		{style: "NTCP2", host: "2001:db8::10", port: "3003"},
	}, "", 1000)

	store := NewPeerStore()
	rec, admitted := store.AddOrUpdate(info, raw)
	if !admitted || rec == nil {
		t.Fatal("expected peer to be admitted")
	}

	want := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.10:1001"),
		netip.MustParseAddrPort("198.51.100.11:1003"),
		netip.MustParseAddrPort("[2001:db8::10]:3003"),
	}
	if !slices.Equal(rec.ProbeEndpoints, want) {
		t.Fatalf("retained endpoints = %v, want %v", rec.ProbeEndpoints, want)
	}

	p := NewProber(store, 1)
	var dialed []string
	p.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
		if network != "tcp" {
			t.Fatalf("unexpected network: %s", network)
		}
		dialed = append(dialed, address)
		return 0, errMockDialFailed
	})
	p.limiter = nil

	_, _ = p.ProbeSingle(context.Background(), info.Hash())
	wantDials := []string{"198.51.100.10:1001", "198.51.100.11:1003"}
	if !slices.Equal(dialed, wantDials) {
		t.Fatalf("dialed = %v, want only declared IPv4 TCP endpoints %v", dialed, wantDials)
	}
}

func TestProbePeerAttemptCap(t *testing.T) {
	for _, tc := range []struct {
		name       string
		endpoints  int
		wantDials  int
	}{
		{name: "none", endpoints: 0, wantDials: 0},
		{name: "at-limit", endpoints: maxProbeAttemptsPerPeer, wantDials: maxProbeAttemptsPerPeer},
		{name: "above-limit", endpoints: maxProbeAttemptsPerPeer + 1, wantDials: maxProbeAttemptsPerPeer},
		{name: "many", endpoints: 40, wantDials: maxProbeAttemptsPerPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := PeerRecord{}
			for i := range tc.endpoints {
				ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
				rec.ProbeEndpoints = append(rec.ProbeEndpoints, netip.AddrPortFrom(ip, 1234))
			}

			p := NewProber(nil, 1)
			p.limiter = nil
			dials := 0
			p.SetDialer(func(_ context.Context, _, _ string) (time.Duration, error) {
				dials++
				return 0, errMockDialFailed
			})

			success, _ := p.probePeer(context.Background(), rec)
			if success || dials != tc.wantDials {
				t.Fatalf("success = %v, dials = %d, want %d", success, dials, tc.wantDials)
			}
		})
	}
}

func TestProberChargesLimiterPerDial(t *testing.T) {
	for _, single := range []bool{false, true} {
		name := "batch"
		if single {
			name = "single"
		}
		t.Run(name, func(t *testing.T) {
			store := NewPeerStore()
			info, raw := createTestRouterInfo(t, "LR")
			rec, _ := store.AddOrUpdate(info, raw)
			rec.ProbeEndpoints = []netip.AddrPort{
				netip.MustParseAddrPort("198.51.100.1:1234"),
				netip.MustParseAddrPort("198.51.100.2:5678"),
				netip.MustParseAddrPort("198.51.100.3:9000"),
			}

			p := NewProber(store, 1)
			p.limiter = NewTokenBucketRateLimiter(0.01, 1)
			dials := 0
			p.SetDialer(func(_ context.Context, _, _ string) (time.Duration, error) {
				dials++
				return 0, errMockDialFailed
			})

			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			if single {
				_, _ = p.ProbeSingle(ctx, info.Hash())
			} else {
				_ = p.ProbeAll(ctx)
			}
			if dials != 1 {
				t.Fatalf("dials = %d with one token, want 1", dials)
			}
		})
	}
}

func TestProberRejectsInvalidEndpointPairs(t *testing.T) {
	p := NewProber(nil, 1)
	p.SetDialer(func(_ context.Context, _, address string) (time.Duration, error) {
		t.Fatalf("invalid endpoint was dialed: %s", address)
		return 0, errMockDialFailed
	})
	rec := PeerRecord{ProbeEndpoints: []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:8000"),
		netip.MustParseAddrPort("0.0.0.0:8000"),
		netip.MustParseAddrPort("169.254.1.1:8000"),
		netip.MustParseAddrPort("[::ffff:127.0.0.1]:8000"),
		netip.MustParseAddrPort("198.51.100.1:0"),
	}}
	success, _ := p.probePeer(context.Background(), rec)
	if success {
		t.Fatal("invalid endpoints must not make the peer reachable")
	}
}

func TestPeerStoreLegacyCacheRestoresProbePairs(t *testing.T) {
	info, raw := createTestRouterInfoWithEndpoint(t, bytes.Repeat([]byte{19}, 32), "LR", "198.51.100.8", "4242", "", 1000)
	store := NewPeerStore()
	rec, admitted := store.AddOrUpdate(info, raw)
	if !admitted || rec == nil {
		t.Fatal("expected peer to be admitted")
	}
	rec.ProbeEndpoints = nil // Simulate a cache saved before endpoint pairs existed.

	path := filepath.Join(t.TempDir(), "peers.json")
	if err := store.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	restored := NewPeerStore()
	if err := restored.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	peers := restored.Snapshot()
	want := netip.MustParseAddrPort("198.51.100.8:4242")
	if len(peers) != 1 || len(peers[0].ProbeEndpoints) != 1 || peers[0].ProbeEndpoints[0] != want {
		t.Fatalf("restored endpoints = %v, want [%s]", peers, want)
	}
}
