package router

import (
	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
)

// PeerSelector exposes bounded RouterInfo bootstrap candidates without leaking
// netdb maps or allocating a sort buffer on each connection attempt.
type PeerSelector struct{ Database *controlplanenetdb.Database }

func (s PeerSelector) Candidates(dst []controlplanenetdb.RouterRef, target foundation.Hash, floodfillOnly bool) []controlplanenetdb.RouterRef {
	if s.Database == nil {
		return dst[:0]
	}
	if floodfillOnly {
		return s.Database.FloodTargets(dst, target)
	}
	return s.Database.Routers().ClosestRoutingInto(dst, target)
}
