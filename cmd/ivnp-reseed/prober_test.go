package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProbePeerFiltersNonPublicDestinations(t *testing.T) {
	tests := []struct {
		name     string
		ip       netip.Addr
		wantDial bool
	}{
		{"invalid", netip.Addr{}, false},
		{"unspecified IPv4", netip.MustParseAddr("0.0.0.0"), false},
		{"current-network IPv4", netip.MustParseAddr("0.1.2.3"), false},
		{"private IPv4 10", netip.MustParseAddr("10.1.2.3"), false},
		{"private IPv4 172", netip.MustParseAddr("172.16.0.1"), false},
		{"private IPv4 192", netip.MustParseAddr("192.168.1.1"), false},
		{"shared address start", netip.MustParseAddr("100.64.0.0"), false},
		{"shared address end", netip.MustParseAddr("100.127.255.255"), false},
		{"shared address next", netip.MustParseAddr("100.128.0.1"), true},
		{"loopback IPv4", netip.MustParseAddr("127.0.0.1"), false},
		{"link-local IPv4", netip.MustParseAddr("169.254.1.1"), false},
		{"protocol IPv4", netip.MustParseAddr("192.0.0.8"), false},
		{"documentation IPv4 1", netip.MustParseAddr("192.0.2.1"), false},
		{"deprecated anycast IPv4", netip.MustParseAddr("192.88.99.1"), false},
		{"benchmark IPv4 start", netip.MustParseAddr("198.18.0.1"), false},
		{"benchmark IPv4 end", netip.MustParseAddr("198.19.255.254"), false},
		{"documentation IPv4 2", netip.MustParseAddr("198.51.100.1"), false},
		{"documentation IPv4 3", netip.MustParseAddr("203.0.113.1"), false},
		{"multicast IPv4", netip.MustParseAddr("224.0.0.1"), false},
		{"reserved IPv4", netip.MustParseAddr("240.0.0.1"), false},
		{"broadcast IPv4", netip.MustParseAddr("255.255.255.255"), false},
		{"public IPv4 cloudflare", netip.MustParseAddr("1.1.1.1"), true},
		{"public IPv4 google", netip.MustParseAddr("8.8.8.8"), true},
		{"unspecified IPv6", netip.MustParseAddr("::"), false},
		{"loopback IPv6", netip.MustParseAddr("::1"), false},
		{"mapped private IPv4", netip.MustParseAddr("::ffff:10.1.2.3"), false},
		{"mapped public IPv4", netip.MustParseAddr("::ffff:8.8.8.8"), false},
		{"NAT64 IPv6", netip.MustParseAddr("64:ff9b::a00:1"), false},
		{"discard-only IPv6", netip.MustParseAddr("100::1"), false},
		{"Teredo IPv6", netip.MustParseAddr("2001::1"), false},
		{"documentation IPv6", netip.MustParseAddr("2001:db8::1"), false},
		{"6to4 IPv6", netip.MustParseAddr("2002::1"), false},
		{"documentation IPv6 3fff", netip.MustParseAddr("3fff::1"), false},
		{"unique local IPv6", netip.MustParseAddr("fd00::1"), false},
		{"unique local IPv6 second", netip.MustParseAddr("fc00::1"), false},
		{"site-local IPv6", netip.MustParseAddr("fec0::1"), false},
		{"link-local IPv6 zone", netip.MustParseAddr("fe80::1%eth0"), false},
		{"multicast IPv6", netip.MustParseAddr("ff02::1"), false},
		{"public IPv6 google", netip.MustParseAddr("2001:4860:4860::8888"), true},
		{"public IPv6 cloudflare", netip.MustParseAddr("2606:4700:4700::1111"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := PeerRecord{TCPPorts: []uint16{443}}
			if tt.ip.Is6() {
				rec.IPv6 = []netip.Addr{tt.ip}
			} else {
				rec.IPv4 = []netip.Addr{tt.ip}
			}

			prober := NewProber(nil, 1)
			calls := 0
			var dialAddress string
			prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
				if network != "tcp" {
					t.Fatalf("unexpected probe network: %s", network)
				}
				calls++
				dialAddress = address
				return 25 * time.Millisecond, nil
			})

			success, rtt := prober.probePeer(context.Background(), rec)
			if success != tt.wantDial {
				t.Fatalf("probe success = %v, want %v", success, tt.wantDial)
			}
			if !tt.wantDial {
				if calls != 0 || rtt != 0 {
					t.Fatalf("non-public endpoint was dialed: calls=%d, RTT=%v", calls, rtt)
				}
				return
			}
			wantAddress := net.JoinHostPort(tt.ip.String(), "443")
			if calls != 1 || dialAddress != wantAddress || rtt != 25*time.Millisecond {
				t.Fatalf("public probe: calls=%d, address=%q, RTT=%v; want one dial to %q at 25ms",
					calls, dialAddress, rtt, wantAddress)
			}
		})
	}
}

func TestProbePeerDialsOnlyPublicEndpoints(t *testing.T) {
	privateIPv4 := netip.MustParseAddr("10.0.0.1")
	publicIPv4 := netip.MustParseAddr("1.1.1.1")
	privateIPv6 := netip.MustParseAddr("fd00::1")
	publicIPv6 := netip.MustParseAddr("2606:4700:4700::1111")

	tests := []struct {
		name        string
		ipv4        []netip.Addr
		ipv6        []netip.Addr
		ports       []uint16
		wantAddress string
	}{
		{"mixed IPv4", []netip.Addr{privateIPv4, publicIPv4}, nil, []uint16{0, 443}, "1.1.1.1:443"},
		{"IPv6 fallback", []netip.Addr{privateIPv4}, []netip.Addr{privateIPv6, publicIPv6}, []uint16{443}, "[2606:4700:4700::1111]:443"},
		{"private only", []netip.Addr{privateIPv4}, []netip.Addr{privateIPv6}, []uint16{443}, ""},
		{"zero port", []netip.Addr{publicIPv4}, nil, []uint16{0}, ""},
		{"highest port", []netip.Addr{publicIPv4}, nil, []uint16{65535}, "1.1.1.1:65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober := NewProber(nil, 1)
			calls := 0
			var dialAddress string
			prober.SetDialer(func(_ context.Context, network, address string) (time.Duration, error) {
				if network != "tcp" {
					t.Fatalf("unexpected probe network: %s", network)
				}
				calls++
				dialAddress = address
				return 25 * time.Millisecond, nil
			})
			rec := PeerRecord{IPv4: tt.ipv4, IPv6: tt.ipv6, TCPPorts: tt.ports}
			success, rtt := prober.probePeer(context.Background(), rec)
			if tt.wantAddress == "" {
				if success || calls != 0 || rtt != 0 {
					t.Fatalf("non-public probe succeeded or dialed: success=%v, calls=%d, RTT=%v", success, calls, rtt)
				}
				return
			}
			if !success || calls != 1 || dialAddress != tt.wantAddress || rtt != 25*time.Millisecond {
				t.Fatalf("probe: success=%v, calls=%d, address=%q, RTT=%v; want one successful dial to %q",
					success, calls, dialAddress, rtt, tt.wantAddress)
			}
		})
	}
}
