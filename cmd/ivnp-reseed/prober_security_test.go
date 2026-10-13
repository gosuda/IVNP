package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPublicProbeAddress(t *testing.T) {
	tests := []struct {
		address string
		allowed bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"100.63.255.255", true},
		{"100.128.0.1", true},
		{"2001:4860:4860::8888", true},
		{"2606:4700:4700::1111", true},
		{"0.0.0.0", false},
		{"10.0.0.1", false},
		{"100.64.0.0", false},
		{"100.127.255.255", false},
		{"127.0.0.1", false},
		{"169.254.1.2", false},
		{"172.16.0.1", false},
		{"192.0.0.1", false},
		{"192.0.2.1", false},
		{"192.88.99.1", false},
		{"192.168.1.1", false},
		{"198.18.0.1", false},
		{"198.19.255.255", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"224.0.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::", false},
		{"::1", false},
		{"64:ff9b::192.168.1.1", false},
		{"100::1", false},
		{"2001::1", false},
		{"2001:db8::1", false},
		{"2002::1", false},
		{"3ffe::1", false},
		{"3fff::1", false},
		{"fc00::1", false},
		{"fd00::1", false},
		{"fe80::1", false},
		{"ff02::1", false},
		{"::ffff:8.8.8.8", false},
		{"2001:4860::1%eth0", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got := isPublicProbeAddress(netip.MustParseAddr(tt.address))
			if got != tt.allowed {
				t.Fatalf("isPublicProbeAddress(%q) = %t, want %t", tt.address, got, tt.allowed)
			}
		})
	}
	if isPublicProbeAddress(netip.Addr{}) {
		t.Fatal("invalid address must be rejected")
	}
}

func TestProbePeerRejectsNonPublicTargets(t *testing.T) {
	prober := NewProber(nil, 1)
	prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
		t.Fatalf("unexpected %s dial to %s", network, address)
		return 0, nil
	})
	rec := PeerRecord{
		IPv4: []netip.Addr{
			netip.MustParseAddr("10.1.2.3"),
			netip.MustParseAddr("172.16.0.1"),
			netip.MustParseAddr("192.168.1.1"),
			netip.MustParseAddr("100.64.0.1"),
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("198.18.0.1"),
			netip.MustParseAddr("198.51.100.1"),
			netip.MustParseAddr("224.0.0.1"),
		},
		IPv6: []netip.Addr{
			netip.MustParseAddr("fc00::1"),
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("2002::1"),
			netip.MustParseAddr("3fff::1"),
			netip.MustParseAddr("::ffff:8.8.8.8"),
		},
		TCPPorts: []uint16{80, 443},
	}
	success, rtt := prober.probePeer(context.Background(), rec)
	if success || rtt != 0 {
		t.Fatalf("non-public peer probe = (%t, %s), want (false, 0)", success, rtt)
	}
}

func TestProbePeerRejectsZeroPort(t *testing.T) {
	prober := NewProber(nil, 1)
	prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
		t.Fatalf("unexpected %s dial to %s", network, address)
		return 0, nil
	})
	rec := PeerRecord{
		IPv4:     []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		TCPPorts: []uint16{0},
	}
	success, _ := prober.probePeer(context.Background(), rec)
	if success {
		t.Fatal("zero-port peer must not be probed")
	}
}

func TestProbePeerDialsOnlyPublicTargets(t *testing.T) {
	tests := []struct {
		name     string
		ipv4     []string
		ipv6     []string
		ports    []uint16
		wantDial string
	}{
		{
			name:     "skip private IPv4",
			ipv4:     []string{"10.0.0.1", "8.8.8.8"},
			ports:    []uint16{443},
			wantDial: "8.8.8.8:443",
		},
		{
			name:     "fall back to public IPv6",
			ipv4:     []string{"198.51.100.1"},
			ipv6:     []string{"fc00::1", "2001:4860:4860::8888"},
			ports:    []uint16{443},
			wantDial: "[2001:4860:4860::8888]:443",
		},
		{
			name:     "skip zero port",
			ipv4:     []string{"1.1.1.1"},
			ports:    []uint16{0, 443},
			wantDial: "1.1.1.1:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := PeerRecord{TCPPorts: tt.ports}
			for _, address := range tt.ipv4 {
				rec.IPv4 = append(rec.IPv4, netip.MustParseAddr(address))
			}
			for _, address := range tt.ipv6 {
				rec.IPv6 = append(rec.IPv6, netip.MustParseAddr(address))
			}

			prober := NewProber(nil, 1)
			var dialed []string
			prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
				if network != "tcp" {
					t.Fatalf("network = %s, want tcp", network)
				}
				dialed = append(dialed, address)
				return 35 * time.Millisecond, nil
			})
			success, rtt := prober.probePeer(context.Background(), rec)
			if !success || rtt != 35*time.Millisecond {
				t.Fatalf("public peer probe = (%t, %s), want (true, 35ms)", success, rtt)
			}
			if len(dialed) != 1 || dialed[0] != tt.wantDial {
				t.Fatalf("dialed %v, want only %q", dialed, tt.wantDial)
			}
		})
	}
}
