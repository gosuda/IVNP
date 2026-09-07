package netdb

import (
	"encoding/binary"
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

func TestExpiredLeaseSet2TriggersLookupBeforeMaintenance(t *testing.T) {
	now := uint64(1_750_000_000_000)
	leaseExpiry := now + 60000
	destination, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.ReleaseSensitive)
	local, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: foundation.Hash{1}, TunnelID: 7, EndDate: leaseExpiry}}); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	n, err := local.MarshalTo(raw, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	// A signed LS2 header may outlive every advertised tunnel.
	binary.BigEndian.PutUint16(raw[len(local.identity.Bytes())+4:], 120)
	signatureLen, _ := local.identity.SigningKeyType().SignatureLen()
	unsigned := append([]byte{byte(foundation.I2NPStoreLeaseSet2)}, raw[:n-signatureLen]...)
	signature, err := destination.Sign(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	copy(raw[n-signatureLen:n], signature)
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	store := foundation.I2NPDatabaseStoreMessage{Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: raw[:n]}
	if err := database.HandleDatabaseStore(store, false, now); err != nil {
		t.Fatal(err)
	}
	addRequestTestFloodfill(database, foundation.Hash{2})
	sender := new(requestTestSender)
	manager, err := NewRequestManager(database, sender, requestTestRoute{gateway: foundation.Hash{3}, tunnel: 4, viaTunnel: true}, RequestManagerConfig{Capacity: 1, TimeoutMillis: 60000, Now: func() uint64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	now = leaseExpiry
	result, err := manager.LookupLeaseSet(t.Context(), destination.Hash())
	if err != nil {
		t.Fatal(err)
	}
	manager.active.Wait()
	if len(sender.snapshot()) != 1 {
		t.Fatal("expired tunnels were accepted from cache instead of issuing a lookup")
	}
	select {
	case outcome := <-result:
		t.Fatalf("lookup completed from expired cache before receiving a reply: %+v", outcome)
	default:
	}
}
