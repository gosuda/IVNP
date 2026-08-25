package netdb

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

var ErrInvalidDatabaseStore = errors.New("netdb: invalid database store")

// MarshalDatabaseStore serializes the only DatabaseStore layout emitted by
// NetDB control-plane producers. Data is copied so a published generation is
// immutable while it is awaiting acknowledgements.
func MarshalDatabaseStore(key foundation.Hash, typeID i2np.StoreType, data []byte, token uint32, gateway foundation.Hash, tunnelID uint32) ([]byte, error) {
	if len(data) == 0 || token != 0 && gateway == (foundation.Hash{}) {
		return nil, ErrInvalidDatabaseStore
	}
	if typeID != i2np.StoreRouterInfo && typeID != i2np.StoreLeaseSet && typeID != i2np.StoreLeaseSet2 && typeID != i2np.StoreMetaLeaseSet && typeID != i2np.StoreEncryptedLeaseSet {
		return nil, ErrInvalidDatabaseStore
	}
	if typeID == i2np.StoreRouterInfo && len(data) > 0xffff {
		return nil, ErrInvalidDatabaseStore
	}
	length := 37 + len(data)
	if token != 0 {
		length += 36
	}
	if typeID == i2np.StoreRouterInfo {
		length += 2
	}
	if length > i2np.I2PDMaxPayload {
		return nil, ErrInvalidDatabaseStore
	}
	payload := make([]byte, length)
	copy(payload, key[:])
	payload[32] = byte(typeID)
	binary.BigEndian.PutUint32(payload[33:37], token)
	off := 37
	if token != 0 {
		binary.BigEndian.PutUint32(payload[off:off+4], tunnelID)
		off += 4
		copy(payload[off:off+32], gateway[:])
		off += 32
	}
	if typeID == i2np.StoreRouterInfo {
		binary.BigEndian.PutUint16(payload[off:off+2], uint16(len(data)))
		off += 2
	}
	copy(payload[off:], data)
	if _, err := i2np.ParseDatabaseStore(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// CompressRouterInfo returns the deterministic gzip representation used in
// RouterInfo stores. The explicit header avoids publication-generation drift.
func CompressRouterInfo(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > i2np.MaxRouterInfoBytes {
		return nil, ErrInvalidDatabaseStore
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err = writer.Write(raw); err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, err
	}
	if compressed.Len() == 0 || compressed.Len() > 0xffff {
		return nil, ErrInvalidDatabaseStore
	}
	return compressed.Bytes(), nil
}

// StoredLeaseSet returns an immutable copy of the currently retained lease
// object so responders never retain or expose mutable database storage.
func (d *Database) StoredLeaseSet(key foundation.Hash) (i2np.StoreType, []byte, bool) {
	d.leasesMu.RLock()
	entry, ok := d.leases[key]
	if !ok {
		d.leasesMu.RUnlock()
		return 0, nil, false
	}
	var data []byte
	switch entry.typeID {
	case i2np.StoreLeaseSet:
		data = entry.legacy.Bytes()
	case i2np.StoreLeaseSet2:
		data = entry.v2.Bytes()
	case i2np.StoreMetaLeaseSet:
		data = entry.meta.Bytes()
	case i2np.StoreEncryptedLeaseSet:
		data = entry.encrypted.Bytes()
	}
	owned := append([]byte(nil), data...)
	typeID := entry.typeID
	d.leasesMu.RUnlock()
	return typeID, owned, len(owned) != 0
}
