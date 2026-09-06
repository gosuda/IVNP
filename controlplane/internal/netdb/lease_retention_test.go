package netdb

import (
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestLeaseRetentionEvictsAndExpires(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	database.maxLeases = 1
	var first, second foundation.Hash
	first[0], second[0] = 1, 2
	database.leasesMu.Lock()
	database.storeLeaseEntry(first, leaseEntry{expires: 10})
	database.storeLeaseEntry(second, leaseEntry{expires: 20})
	database.leasesMu.Unlock()
	if len(database.leases) != 1 {
		t.Fatalf("lease cap len=%d", len(database.leases))
	}
	if removed := database.ExpireLeases(21); removed != 1 || len(database.leases) != 0 {
		t.Fatalf("expiry removed=%d len=%d", removed, len(database.leases))
	}
}

func TestLeaseRetentionUpdateAtCapacityDoesNotEvictSibling(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	database.maxLeases = 2
	first, second := foundation.Hash{1}, foundation.Hash{2}
	database.leasesMu.Lock()
	database.storeLeaseEntry(first, leaseEntry{expires: 10, version: 1})
	database.storeLeaseEntry(second, leaseEntry{expires: 20, version: 1})
	database.storeLeaseEntry(second, leaseEntry{expires: 30, version: 2})
	database.leasesMu.Unlock()

	if len(database.leases) != 2 {
		t.Fatalf("lease count after update = %d, want 2", len(database.leases))
	}
	if _, ok := database.leases[first]; !ok {
		t.Fatal("updating an existing key evicted its sibling")
	}
	if got := database.leases[second]; got.version != 2 || got.expires != 30 {
		t.Fatalf("updated lease = %+v", got)
	}
}

func TestLeaseExpiryIndexTracksUpdatesAndEarliestEviction(t *testing.T) {
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	database.maxLeases = 2
	first, second, third := foundation.Hash{1}, foundation.Hash{2}, foundation.Hash{3}
	database.leasesMu.Lock()
	database.storeLeaseEntry(first, leaseEntry{expires: 10})
	database.storeLeaseEntry(second, leaseEntry{expires: 20})
	database.storeLeaseEntry(first, leaseEntry{expires: 30})
	database.storeLeaseEntry(third, leaseEntry{expires: 40})
	database.leasesMu.Unlock()

	if _, ok := database.leases[second]; ok {
		t.Fatal("full store retained the earliest-expiring key")
	}
	if _, ok := database.leases[first]; !ok {
		t.Fatal("updated later expiry was evicted using stale index state")
	}
	if removed := database.ExpireLeases(31); removed != 1 {
		t.Fatalf("indexed expiry removed %d leases, want 1", removed)
	}
	if _, ok := database.leases[first]; ok {
		t.Fatal("indexed expiry retained elapsed updated key")
	}
	if _, ok := database.leases[third]; !ok {
		t.Fatal("indexed expiry removed unexpired key")
	}
}
