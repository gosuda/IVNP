package router

import (
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/network_database"
)

// PeerSelector exposes bounded RouterInfo bootstrap candidates without leaking
// netdb maps or allocating a sort buffer on each connection attempt.
type PeerSelector struct{ Database *netdb.Database }

func (s PeerSelector) Candidates(dst []netdb.RouterRef, target ivnp.Hash, floodfillOnly bool) []netdb.RouterRef {
	if s.Database == nil {
		return dst[:0]
	}
	if floodfillOnly {
		return s.Database.FloodTargets(dst, target)
	}
	return s.Database.Routers().ClosestRoutingInto(dst, target)
}
