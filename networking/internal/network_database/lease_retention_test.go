package netdb

import (
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestLeaseRetentionEvictsAndExpires(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	database.maxLeases = 1
	var first, second ivnp.Hash
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
