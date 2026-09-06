package router

import (
	"bytes"
	"net/netip"
	"time"

	"gosuda.org/ivnp/foundation"
)

type SSU2Introducer struct {
	Peer       foundation.Hash
	RelayTag   uint32
	Expiration time.Time
}

type SSU2PeerCapabilities struct {
	Direct     bool
	IPv6       bool
	Introducer bool
	Introduced bool
}

func InspectSSU2Peer(info foundation.NetworkDatabaseRouterInfo, now uint64) SSU2PeerCapabilities {
	return inspectSSU2Peer(info, now, true)
}

func (m *SSU2Manager) InspectPeer(info foundation.NetworkDatabaseRouterInfo, now uint64) SSU2PeerCapabilities {
	return inspectSSU2Peer(info, now, m.ipv6Available.Load())
}

func inspectSSU2Peer(info foundation.NetworkDatabaseRouterInfo, now uint64, allowIPv6 bool) SSU2PeerCapabilities {
	if _, err := selectSSU2Keys(info); err != nil {
		return SSU2PeerCapabilities{}
	}
	result := SSU2PeerCapabilities{Introduced: len(selectSSU2Introducers(info, now)) != 0}
	if address, err := selectSSU2AddressForNetwork(info, allowIPv6); err == nil {
		result.Direct = hasCurrentTransportAddress(info, now*1000, []byte("SSU"), []byte("SSU2"))
		ip, _ := netip.ParseAddr(address.host)
		result.IPv6 = ip.Is6()
		result.Introducer = address.introducer
	}
	return result
}

func (m *NTCP2Manager) PeerReachable(info foundation.NetworkDatabaseRouterInfo) bool {
	_, err := selectNTCP2AddressForNetwork(info, ntcp2AddressSelection(m.currentBindings().NTCP2))
	return err == nil
}

func (m *SSU2Manager) IntroducerStatus(ipv6 bool) (required bool, count int) {
	return m.introducersRequired(ipv6), m.introducerCount(ipv6)
}

func SSU2PeerEndpointMatches(info foundation.NetworkDatabaseRouterInfo, endpoint netip.AddrPort) bool {
	return peerTestInfoEndpointApproved(info, endpoint)
}

func routerHashDiagnostic(hash foundation.Hash) string {
	return foundation.EncodeI2PBase64(hash[:])
}
func NTCP2PeerCapable(info foundation.NetworkDatabaseRouterInfo, nowMillis uint64) bool {
	if _, err := selectNTCP2Address(info); err != nil {
		return false
	}
	return hasCurrentTransportAddress(info, nowMillis, []byte("NTCP"), []byte("NTCP2"))
}

func SSU2DirectPeerCapable(info foundation.NetworkDatabaseRouterInfo, now uint64) bool {
	if _, err := selectSSU2Keys(info); err != nil {
		return false
	}
	_, err := selectSSU2Address(info)
	return err == nil && hasCurrentTransportAddress(info, now*1000, []byte("SSU"), []byte("SSU2"))
}

func SSU2PeerCapable(info foundation.NetworkDatabaseRouterInfo, now uint64) bool {
	if SSU2DirectPeerCapable(info, now) {
		return true
	}
	if _, err := selectSSU2Keys(info); err != nil {
		return false
	}
	return len(selectSSU2Introducers(info, now)) != 0
}

func hasCurrentTransportAddress(info foundation.NetworkDatabaseRouterInfo, nowMillis uint64, first, second []byte) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		if !bytes.Equal(address.TransportStyle, first) && !bytes.Equal(address.TransportStyle, second) {
			continue
		}
		if address.Expiration == 0 || address.Expiration > nowMillis {
			return true
		}
	}
}
