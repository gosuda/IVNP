package router

import (
	"net/netip"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type transportPeerSource struct {
	database *controlplanenetdb.Database
}

func NewTransportPeerSource(database *controlplanenetdb.Database) dataplane.RouterTransportPeerSource {
	if database == nil {
		return nil
	}
	return transportPeerSource{database: database}
}

func (s transportPeerSource) RouterInfo(peer foundation.Hash) (foundation.NetworkDatabaseRouterInfo, bool) {
	ref, ok := s.database.Routers().Get(peer)
	return ref.Info, ok
}

func (s transportPeerSource) DialRouterInfo(peer foundation.Hash, now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	info, ok := s.RouterInfo(peer)
	if !ok {
		return foundation.NetworkDatabaseRouterInfo{}, ErrTransportUnavailable
	}
	if err := controlplanenetdb.ReseedRouterInfoFresh(info, now); err != nil {
		return foundation.NetworkDatabaseRouterInfo{}, err
	}
	return info, nil
}
func (s transportPeerSource) AdmitRouterInfo(info foundation.NetworkDatabaseRouterInfo, now uint64) error {
	return s.database.AdmitRouterInfo(info, false, now)
}

func (s transportPeerSource) PeerAtEndpoint(source netip.AddrPort) (foundation.Hash, bool) {
	if !source.IsValid() {
		return foundation.Hash{}, false
	}
	_, peers := s.database.Routers().Snapshot()
	var matched foundation.Hash
	found := false
	for _, peer := range peers {
		if !dataplane.RouterSSU2PeerEndpointMatches(peer.Info, source) {
			continue
		}
		if found && matched != peer.Hash {
			return foundation.Hash{}, false
		}
		matched, found = peer.Hash, true
	}
	return matched, found
}
