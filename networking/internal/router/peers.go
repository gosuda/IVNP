package router

import (
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/netdb"
)

// PeerSelector exposes bounded RouterInfo bootstrap candidates without leaking
// netdb maps or allocating a sort buffer on each connection attempt.
type PeerSelector struct{ Database *netdb.Database }

func (s PeerSelector) Candidates(dst []netdb.RouterRef, target foundation.Hash, floodfillOnly bool) []netdb.RouterRef {
	if s.Database == nil {
		return dst[:0]
	}
	if floodfillOnly {
		return s.Database.FloodTargets(dst, target)
	}
	return s.Database.Routers().ClosestRoutingInto(dst, target)
}
