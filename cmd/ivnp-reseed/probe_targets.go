package main

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
)

// maxProbeDialsPerPeer bounds the TCP dials one probe may spend on a single
// RouterInfo, which an untrusted publisher can fill with many addresses.
const maxProbeDialsPerPeer = 4

// nonPublicProbePrefixes lists globally unicast-looking ranges that are not
// reachable public Internet hosts and must never be probed.
var nonPublicProbePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT shared space
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking, often internal
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use prefix
}

// isProbeableAddr reports whether ip is a public global unicast address. RouterInfo
// addresses are attacker-controlled, so private, loopback, link-local, CGNAT,
// ULA, multicast, and reserved targets are rejected, including IPv4-mapped
// IPv6 forms of them.
func isProbeableAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicProbePrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// probeTargets returns up to maxProbeDialsPerPeer distinct "ip:port" TCP
// targets built from the public addresses in ips and the given ports.
func probeTargets(ips []netip.Addr, ports []uint16) []string {
	var targets []string
	for _, ip := range ips {
		if !isProbeableAddr(ip) {
			continue
		}
		ip = ip.Unmap()
		for _, port := range ports {
			if port == 0 {
				continue
			}
			target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			if slices.Contains(targets, target) {
				continue
			}
			targets = append(targets, target)
			if len(targets) == maxProbeDialsPerPeer {
				return targets
			}
		}
	}
	return targets
}
