package main

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

type probeDialRecorder struct {
	mu      sync.Mutex
	targets []string
	rtt     time.Duration
	err     error
}

func (d *probeDialRecorder) dial(_ context.Context, _, address string) (time.Duration, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets = append(d.targets, address)
	return d.rtt, d.err
}

func (d *probeDialRecorder) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

func TestIsProbeableAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"203.0.113.7", true},
		{"8.8.8.8", true},
		{"2a00:1450:4001::1", true},
		{"10.0.0.5", false},
		{"172.16.0.10", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"169.254.169.254", false},
		{"192.0.0.8", false},
		{"198.18.0.1", false},
		{"224.0.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"::", false},
		{"fe80::1", false},
		{"fec0::1", false},
		{"fd00::1", false},
		{"fc00::1", false},
		{"ff02::1", false},
		{"::ffff:10.1.2.3", false},
		{"::ffff:127.0.0.1", false},
		{"64:ff9b::a00:1", false},
		{"64:ff9b:1::1", false},
	} {
		if got := isProbeableAddr(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("isProbeableAddr(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if isProbeableAddr(netip.Addr{}) {
		t.Error("isProbeableAddr(zero Addr) = true, want false")
	}
}

// RouterInfos are attacker-controlled, so the prober must never dial internal
// or non-unicast addresses they advertise.
func TestProberSkipsNonPublicAdvertisedAddresses(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	store := NewPeerStore()
	hosts := []struct{ host, port string }{
		{"10.0.0.5", "22"},
		{"192.168.1.1", "80"},
		{"172.16.0.10", "6379"},
		{"100.64.0.1", "2375"},
		{"fd00::1", "8500"},
		{"::ffff:10.1.2.3", "5432"},
		{"0.1.2.3", "80"},
		{"224.0.0.1", "80"},
		{"ff02::1", "80"},
		{"203.0.113.9", "12345"},
	}
	for i, h := range hosts {
		info, raw := createTestRouterInfoWithEndpoint(t, bytes.Repeat([]byte{byte(40 + i)}, 32), "R", h.host, h.port, "", now)
		if _, ok := store.AddOrUpdateWithSeen(info, raw, now); !ok {
			t.Fatalf("store refused RouterInfo advertising %s", h.host)
		}
	}
	d := &probeDialRecorder{rtt: 80 * time.Millisecond}
	prober := NewProber(store, 4)
	prober.SetDialer(d.dial)
	prober.ProbeAll(context.Background())

	got := d.dialed()
	if len(got) != 1 || got[0] != "203.0.113.9:12345" {
		t.Fatalf("dialed %v, want only the public peer 203.0.113.9:12345", got)
	}
}

// One RouterInfo may list many addresses; a single probe must not expand them
// into an IP x port cross-product of dials.
func TestProberCapsDialsPerPeer(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "R")
	rec, _ := store.AddOrUpdate(info, raw)
	rec.IPv4, rec.TCPPorts, rec.UDPPorts, rec.Ports = nil, nil, nil, nil
	for i := range 60 {
		rec.IPv4 = append(rec.IPv4, netip.MustParseAddr("45.20."+strconv.Itoa(i)+".1"))
		rec.TCPPorts = append(rec.TCPPorts, uint16(1000+i))
	}

	d := &probeDialRecorder{err: errMockDialFailed}
	prober := NewProber(store, 1)
	prober.SetDialer(d.dial)
	if ok, _ := prober.ProbeSingle(context.Background(), rec.Hash); ok {
		t.Fatal("probe succeeded with a failing dialer")
	}
	if got := len(d.dialed()); got > maxProbeDialsPerPeer {
		t.Fatalf("one probe made %d dials, want at most %d", got, maxProbeDialsPerPeer)
	}
}

// Duplicate addresses (the same IP published for NTCP2 and SSU2) must not
// spend the per-peer dial budget on repeated targets.
func TestProberDeduplicatesTargets(t *testing.T) {
	store := NewPeerStore()
	info, raw := createTestRouterInfo(t, "R")
	rec, _ := store.AddOrUpdate(info, raw)
	ip := netip.MustParseAddr("203.0.113.20")
	rec.IPv4 = []netip.Addr{ip, ip, ip}
	rec.TCPPorts = []uint16{4567, 4567}
	rec.UDPPorts = nil

	d := &probeDialRecorder{err: errMockDialFailed}
	prober := NewProber(store, 1)
	prober.SetDialer(d.dial)
	prober.ProbeSingle(context.Background(), rec.Hash)
	if got := d.dialed(); len(got) != 1 || got[0] != "203.0.113.20:4567" {
		t.Fatalf("dialed %v, want a single dial to 203.0.113.20:4567", got)
	}
}
