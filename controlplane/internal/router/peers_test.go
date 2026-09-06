package router

import (
	"testing"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/foundation"
)

func TestPeerSelectorNilDatabase(t *testing.T) {
	var target foundation.Hash
	selector := PeerSelector{}
	if candidates := selector.Candidates(make([]controlplanenetdb.RouterRef, 0, 2), target, false); len(candidates) != 0 {
		t.Fatalf("candidates=%#v", candidates)
	}
}
