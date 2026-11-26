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

// The daemon builds its Database exactly like this: no SetRouterLimit call.
// Unsolicited RouterInfo stores from arbitrary peers must still stay bounded
// by the KBucketSet-derived default.
func TestDaemonDatabaseBoundsUnsolicitedRouterInfoRetention(t *testing.T) {
	const capacity = 5
	const now = uint64(10_000_000_000)
	database := NewDatabaseForNetwork(foundation.Hash{1}, capacity, 0)
	limit := BucketCount * database.Routers().BucketCapacity()
	for range limit + 16 {
		info := signedPersistenceRouter(t, now)
		payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(info.Hash(), foundation.I2NPStoreRouterInfo, gzipBytes(t, info.Bytes()), 0, foundation.Hash{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		store, err := foundation.I2NPParseDatabaseStore(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.HandleDatabaseStore(store, false, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := database.Routers().Len(); got != limit {
		t.Fatalf("retained RouterInfos = %d, want default bound %d", got, limit)
	}
}

func TestRouterRetentionEvictsLeastUsefulBeforeEstablishedRouters(t *testing.T) {
	table := NewTable(foundation.Hash{}, 24)
	table.SetRouterLimit(4)
	trustedFloodfill, trustedRouter := routerWithSeed(1), routerWithSeed(2)
	untrustedRouter, untrustedFloodfill := routerWithSeed(3), routerWithSeed(4)
	table.StoreVerified(trustedFloodfill, true, 1)
	table.StoreVerified(trustedRouter, false, 2)
	table.storeVerified(untrustedRouter, false, 3, routerUntrusted)
	table.storeVerified(untrustedFloodfill, true, 4, routerUntrusted)
	for seed := byte(10); seed < 60; seed++ {
		table.storeVerified(routerWithSeed(seed), false, 100+uint64(seed), routerUntrusted)
	}
	assertRetained := func(want bool, infos ...foundation.NetworkDatabaseRouterInfo) {
		t.Helper()
		for _, info := range infos {
			hash := info.Hash()
			if _, ok := table.Get(hash); ok != want {
				t.Fatalf("RouterInfo %x retained = %t, want %t", hash[:4], ok, want)
			}
		}
	}
	assertRetained(true, trustedFloodfill, trustedRouter, untrustedFloodfill, routerWithSeed(59))
	assertRetained(false, untrustedRouter, routerWithSeed(10))
	if got := table.Len(); got != 4 {
		t.Fatalf("retained RouterInfos = %d, want 4", got)
	}

	// Trusted admissions consume untrusted slots first, non-floodfill first.
	table.StoreVerified(routerWithSeed(200), false, 200)
	assertRetained(false, routerWithSeed(59))
	table.StoreVerified(routerWithSeed(201), false, 201)
	assertRetained(false, untrustedFloodfill)
	// With only trusted records left, the oldest non-floodfill goes first.
	table.StoreVerified(routerWithSeed(202), false, 202)
	assertRetained(false, trustedRouter)
	assertRetained(true, trustedFloodfill, routerWithSeed(200), routerWithSeed(201), routerWithSeed(202))
}

func TestRouterRetentionUnsolicitedFloodHoldsOneTrustedSlot(t *testing.T) {
	table := NewTable(foundation.Hash{}, 24)
	table.SetRouterLimit(3)
	established := []foundation.NetworkDatabaseRouterInfo{routerWithSeed(1), routerWithSeed(2), routerWithSeed(3)}
	for i, info := range established {
		table.StoreVerified(info, false, uint64(i+1))
	}
	for seed := byte(10); seed < 200; seed++ {
		table.storeVerified(routerWithSeed(seed), true, 1000+uint64(seed), routerUntrusted)
	}
	for _, info := range established[1:] {
		if _, ok := table.Get(info.Hash()); !ok {
			t.Fatal("unsolicited flood displaced more than one trusted RouterInfo")
		}
	}
	if got := table.Len(); got != 3 {
		t.Fatalf("retained RouterInfos = %d, want 3", got)
	}
}

func TestSolicitedRouterInfoPromotesUnsolicitedEntry(t *testing.T) {
	const now = uint64(10_000_000_000)
	database := NewDatabase(foundation.Hash{1}, DefaultBucketCapacity)
	info := signedPersistenceRouter(t, now)
	if err := database.AdmitUnsolicitedRouterInfo(info, now); err != nil {
		t.Fatal(err)
	}
	if ref, _ := database.Routers().Get(info.Hash()); ref.Trusted {
		t.Fatal("unsolicited RouterInfo admitted as trusted")
	}
	payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(info.Hash(), foundation.I2NPStoreRouterInfo, gzipBytes(t, info.Bytes()), 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store, err := foundation.I2NPParseDatabaseStore(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.HandleDatabaseStoreAsPublished(store, false, now, false); err != nil {
		t.Fatal(err)
	}
	if ref, _ := database.Routers().Get(info.Hash()); !ref.Trusted {
		t.Fatal("RouterInfo answering a local lookup was not promoted to trusted")
	}
}
