package netdb

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation/internal/i2np"
	foundation "gosuda.org/ivnp/foundation/internal/identity"
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

// routerInfoCompressorPool caches compressor instances across concurrent callers
// while allowing the garbage collector to reclaim retained deflate state when idle.
var routerInfoCompressorPool sync.Pool

type routerInfoCompressorEntry struct {
	writer *gzip.Writer
	buffer bytes.Buffer
}

// CompressRouterInfo returns the deterministic gzip representation used in
// RouterInfo stores. The explicit header avoids publication-generation drift.
func CompressRouterInfo(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > i2np.MaxRouterInfoBytes {
		return nil, ErrInvalidDatabaseStore
	}
	entry, ok := routerInfoCompressorPool.Get().(*routerInfoCompressorEntry)
	if !ok || entry == nil {
		entry = new(routerInfoCompressorEntry)
		var err error
		entry.writer, err = gzip.NewWriterLevel(&entry.buffer, gzip.BestCompression)
		if err != nil {
			return nil, err
		}
	} else {
		entry.buffer.Reset()
		entry.writer.Reset(&entry.buffer)
	}
	defer routerInfoCompressorPool.Put(entry)

	entry.writer.Header.ModTime = time.Unix(0, 0)
	entry.writer.Header.OS = 255
	_, err := entry.writer.Write(raw)
	err = errors.Join(err, entry.writer.Close())
	if err != nil {
		return nil, err
	}
	if entry.buffer.Len() == 0 || entry.buffer.Len() > 0xffff {
		return nil, ErrInvalidDatabaseStore
	}
	return bytes.Clone(entry.buffer.Bytes()), nil
}
