package netdb

import (
	"gosuda.org/ivnp/foundation"
)

// StoredLeaseSet returns an immutable copy of the currently retained lease
// object so responders never retain or expose mutable database storage.
func (d *Database) StoredLeaseSet(key foundation.Hash) (foundation.I2NPStoreType, []byte, bool) {
	return d.storedLeaseSet(key, 0, false)
}

// StoredPublishedLeaseSet returns only an unsolicited or flooded LeaseSet that
// remains current at now. Lookup-derived entries stay private to local routing.
func (d *Database) StoredPublishedLeaseSet(key foundation.Hash, now uint64) (foundation.I2NPStoreType, []byte, bool) {
	return d.storedLeaseSet(key, now, true)
}

func (d *Database) storedLeaseSet(key foundation.Hash, now uint64, publishedOnly bool) (foundation.I2NPStoreType, []byte, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	unavailable := !ok
	if publishedOnly {
		unavailable = unavailable || !entry.published || leaseEntryExpired(entry, now)
	}
	if unavailable {
		d.leasesMu.RUnlock()
		return 0, nil, false
	}
	var data []byte
	switch entry.typeID {
	case foundation.I2NPStoreLeaseSet:
		data = entry.legacy.Bytes()
	case foundation.I2NPStoreLeaseSet2:
		data = entry.v2.Bytes()
	case foundation.I2NPStoreMetaLeaseSet:
		data = entry.meta.Bytes()
	case foundation.I2NPStoreEncryptedLeaseSet:
		data = entry.encrypted.Bytes()
	}
	owned := append([]byte(nil), data...)
	typeID := entry.typeID
	d.leasesMu.RUnlock()
	return typeID, owned, len(owned) != 0
}

func leaseEntryExpired(entry leaseEntry, now uint64) bool {
	var offline foundation.NetworkDatabaseOfflineSignature
	switch entry.typeID {
	case foundation.I2NPStoreLeaseSet2:
		offline = entry.v2.Header.Offline
	case foundation.I2NPStoreMetaLeaseSet:
		offline = entry.meta.Header.Offline
	case foundation.I2NPStoreEncryptedLeaseSet:
		offline = entry.encrypted.Offline
	}
	// Lease clock skew tolerance must not extend signing-key authorization.
	if offline.Present() && uint64(offline.Expires)*1000 < now {
		return true
	}
	cutoff := uint64(0)
	if now > LeaseSetClockFudgeMillis {
		cutoff = now - LeaseSetClockFudgeMillis
	}
	return entry.expires != 0 && entry.expires <= cutoff
}
