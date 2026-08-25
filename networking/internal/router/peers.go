package router

import (
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/network_database"
)

// PeerSelector exposes bounded RouterInfo bootstrap candidates without leaking
// netdb maps or allocating a sort buffer on each connection attempt.
type PeerSelector struct{ Database *networkdatabase.Database }

func (s PeerSelector) Candidates(dst []networkdatabase.RouterRef, target foundation.Hash, floodfillOnly bool) []networkdatabase.RouterRef {
	if s.Database == nil {
		return dst[:0]
	}
	if floodfillOnly {
		return s.Database.FloodTargets(dst, target)
	}
	return s.Database.Routers().ClosestRoutingInto(dst, target)
}
