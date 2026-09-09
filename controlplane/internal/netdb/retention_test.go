package netdb

import (
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestRouterRetentionLimitEvictsOldestIndependentOfRoutingBuckets(t *testing.T) {
	table := NewTable(foundation.Hash{}, 24)
	table.SetRouterLimit(2)
	first := signedPersistenceRouter(t, 1)
	second := signedPersistenceRouter(t, 2)
	third := signedPersistenceRouter(t, 3)
	table.StoreVerified(first, false, 1)
	table.StoreVerified(second, false, 2)
	table.StoreVerified(third, false, 3)
	if _, retained := table.Get(first.Hash()); retained {
		t.Fatal("oldest RouterInfo survived bounded admission")
	}
	for _, hash := range []foundation.Hash{second.Hash(), third.Hash()} {
		if _, retained := table.Get(hash); !retained {
			t.Fatal("bounded admission lost a newer RouterInfo")
		}
	}
	if got := table.Len(); got != 2 {
		t.Fatalf("retained RouterInfos = %d, want 2", got)
	}
}
