package router

import (
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/netdb"
)

func TestPeerSelectorNilDatabase(t *testing.T) {
	var target foundation.Hash
	selector := PeerSelector{}
	if candidates := selector.Candidates(make([]netdb.RouterRef, 0, 2), target, false); len(candidates) != 0 {
		t.Fatalf("candidates=%#v", candidates)
	}
}
