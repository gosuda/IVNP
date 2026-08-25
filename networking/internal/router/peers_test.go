package router

import (
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/network_database"
	"testing"
)

func TestPeerSelectorNilDatabase(t *testing.T) {
	var target foundation.Hash
	selector := PeerSelector{}
	if candidates := selector.Candidates(make([]networkdatabase.RouterRef, 0, 2), target, false); len(candidates) != 0 {
		t.Fatalf("candidates=%#v", candidates)
	}
}
