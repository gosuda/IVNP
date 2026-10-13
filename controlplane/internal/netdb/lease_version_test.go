package netdb

import (
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestLeaseSetVersionPrecedence(t *testing.T) {
	const published = uint64(1_750_000_000)
	const legacyExpiry = published*1000 + 120_000

	legacy := foundation.I2NPStoreLeaseSet
	modern := []struct {
		name   string
		typeID foundation.I2NPStoreType
	}{
		{"LS2", foundation.I2NPStoreLeaseSet2},
		{"Meta", foundation.I2NPStoreMetaLeaseSet},
		{"Encrypted", foundation.I2NPStoreEncryptedLeaseSet},
	}
	for _, variant := range modern {
		t.Run(variant.name, func(t *testing.T) {
			oldLegacy := leaseEntry{typeID: legacy, version: legacyExpiry}
			oldModern := leaseEntry{typeID: variant.typeID, version: published}
			if !leaseSetSupersedes(oldLegacy, variant.typeID, published) {
				t.Fatal("modern LeaseSet could not replace legacy LeaseSet")
			}
			if leaseSetSupersedes(oldModern, legacy, legacyExpiry+60_000) {
				t.Fatal("legacy replay replaced a modern LeaseSet")
			}
			if leaseSetSupersedes(oldModern, variant.typeID, published-1) ||
				leaseSetSupersedes(oldModern, variant.typeID, published) {
				t.Fatal("older or equal publication replaced a modern LeaseSet")
			}
			if !leaseSetSupersedes(oldModern, variant.typeID, published+1) {
				t.Fatal("newer publication did not replace a modern LeaseSet")
			}
		})
	}

	oldLegacy := leaseEntry{typeID: legacy, version: legacyExpiry}
	if leaseSetSupersedes(oldLegacy, legacy, legacyExpiry-1) ||
		leaseSetSupersedes(oldLegacy, legacy, legacyExpiry) ||
		!leaseSetSupersedes(oldLegacy, legacy, legacyExpiry+1) {
		t.Fatal("legacy LeaseSet version ordering changed")
	}

	oldLS2 := leaseEntry{typeID: foundation.I2NPStoreLeaseSet2, version: published}
	if leaseSetSupersedes(oldLS2, foundation.I2NPStoreMetaLeaseSet, published) ||
		leaseSetSupersedes(oldLS2, foundation.I2NPStoreEncryptedLeaseSet, published-1) ||
		!leaseSetSupersedes(oldLS2, foundation.I2NPStoreMetaLeaseSet, published+1) {
		t.Fatal("cross-type modern LeaseSet publication ordering changed")
	}
}

func TestDatabaseLeaseSet2MigrationRejectsLegacyReplay(t *testing.T) {
	const now = uint64(1_750_000_000_000)
	destination, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.ReleaseSensitive)
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	leases := []foundation.NetworkDatabaseLease{
		{Gateway: foundation.Hash{1}, TunnelID: 7, EndDate: now + 120_000},
	}

	legacyLocal, err := NewLocalLeaseSet(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyLocal.ReplaceInboundLeases(leases); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := legacyLocal.Snapshot(now)
	if !ok {
		t.Fatal("could not snapshot legacy LeaseSet")
	}
	legacyPayload := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	identityBytes := identity.Bytes()
	legacyLen, err := snapshot.MarshalLegacy(legacyPayload, identityBytes[:256], identityBytes[352:384], destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	legacyStore := foundation.I2NPDatabaseStoreMessage{
		Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet, Data: legacyPayload[:legacyLen],
	}

	modernLocal, err := NewLocalLeaseSet2(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := modernLocal.ReplaceInboundLeases(leases); err != nil {
		t.Fatal(err)
	}
	modernPayload := make([]byte, foundation.NetworkDatabaseMaxLeaseSetBytes)
	modernLen, err := modernLocal.MarshalTo(modernPayload, now, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	modernStore := foundation.I2NPDatabaseStoreMessage{
		Key: destination.Hash(), Type: foundation.I2NPStoreLeaseSet2, Data: modernPayload[:modernLen],
	}

	db := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	if err := db.HandleDatabaseStore(legacyStore, false, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.LeaseSet(destination.Hash()); !ok {
		t.Fatal("initial legacy LeaseSet was not stored")
	}
	if err := db.HandleDatabaseStoreAsPublished(modernStore, false, now, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.LeaseSet2(destination.Hash()); !ok {
		t.Fatal("signed LeaseSet2 failed to replace a legacy LeaseSet")
	}
	if err := db.HandleDatabaseStore(legacyStore, false, now); err != nil {
		t.Fatal(err)
	}
	if entry := db.leases[destination.Hash()]; entry.typeID != foundation.I2NPStoreLeaseSet2 || entry.published {
		t.Fatalf("legacy replay replaced or marked unpublished LS2 as published: type=%d, published=%t", entry.typeID, entry.published)
	}
	if err := db.HandleDatabaseStore(modernStore, false, now); err != nil {
		t.Fatal(err)
	}
	if entry := db.leases[destination.Hash()]; entry.typeID != foundation.I2NPStoreLeaseSet2 || !entry.published {
		t.Fatal("identical published LS2 failed to update publication state")
	}
}
