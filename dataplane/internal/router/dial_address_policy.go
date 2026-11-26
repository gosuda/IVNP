package router

import (
	"net/netip"
)

// dialAddressPolicy selects which peer-supplied transport addresses may be
// dialed. The zero value permits any unicast IP literal.
type dialAddressPolicy uint8

const (
	// dialAnyAddress admits private and loopback hosts for dedicated and
	// direct networks that run on LANs, VPCs, or a single host.
	dialAnyAddress dialAddressPolicy = iota
	// dialPublicAddresses admits only globally routable unicast hosts, so a
	// RouterInfo cannot point the router at internal services.
	dialPublicAddresses
)

func dialAddressPolicyFor(requirePublic bool) dialAddressPolicy {
	if requirePublic {
		return dialPublicAddresses
	}
	return dialAnyAddress
}

// allows reports whether ip, parsed from an IP literal, may be dialed.
func (p dialAddressPolicy) allows(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	return p != dialPublicAddresses || publicDialAddress(ip)
}

// publicDialAddress rejects unspecified, loopback, link-local, multicast,
// broadcast, private (RFC 1918 and fc00::/7), CGNAT (100.64.0.0/10), and
// "this network" (0.0.0.0/8) addresses, including their IPv4-mapped forms.
func publicDialAddress(ip netip.Addr) bool {
	if ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.Is4() {
		octets := ip.As4()
		if octets[0] == 0 || octets[0] == 100 && octets[1]&0xc0 == 64 {
			return false
		}
	}
	return true
}
