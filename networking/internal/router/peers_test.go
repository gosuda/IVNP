package router

import (
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/network_database"
	"testing"
)

func TestPeerSelectorNilDatabase(t *testing.T) {
	var target ivnp.Hash
	selector := PeerSelector{}
	if candidates := selector.Candidates(make([]netdb.RouterRef, 0, 2), target, false); len(candidates) != 0 {
		t.Fatalf("candidates=%#v", candidates)
	}
}
