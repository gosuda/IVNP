package netdb

import (
	"gosuda.org/ivnp/state"

	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"

	"os"
	"sync"
)

const (
	routerSnapshotVersion = uint16(1)
	routerSnapshotHeader  = 8 + 2 + 4 + foundation.HashLength + 4
	routerSnapshotDigest  = sha256.Size
)

var (
	ErrRouterSnapshotConfig   = errors.New("netdb: invalid router snapshot configuration")
	ErrRouterSnapshotHeader   = errors.New("netdb: invalid router snapshot header")
	ErrRouterSnapshotRecord   = errors.New("netdb: invalid router snapshot record")
	ErrRouterSnapshotOverflow = errors.New("netdb: router snapshot exceeds configured bounds")
)

var routerSnapshotMagic = [8]byte{'I', 'V', 'N', 'P', 'N', 'D', 'B', 0}

// RouterInfoStore persists only verified remote RouterInfos. Its complete file
// replacement format is intentionally independent of private router state.
type RouterInfoStore struct {
	path      string
	database  *Database
	networkID uint32
	local     foundation.Hash
	max       int

	mu              sync.Mutex
	savedGeneration uint64
}

// RouterInfoStoreConfig supplies the durable snapshot identity and its bounded
// location. Path should normally be StateDir/netdb.routers.
type RouterInfoStoreConfig struct {
	Path      string
	Database  *Database
	NetworkID uint32
}

// RouterInfoLoadResult reports records restored and safely rejected. A bad
// record never prevents already-delimited later records from being considered.
type RouterInfoLoadResult struct {
	Loaded   int
	Rejected int
}

func NewRouterInfoStore(config RouterInfoStoreConfig) (*RouterInfoStore, error) {
	if config.Path == "" || config.Database == nil {
		return nil, ErrRouterSnapshotConfig
	}
	capacity := config.Database.Routers().BucketCapacity()
	if capacity <= 0 || capacity > int(^uint16(0)) {
		return nil, ErrRouterSnapshotConfig
	}
	return &RouterInfoStore{
		path: config.Path, database: config.Database, networkID: config.NetworkID,
		local: config.Database.Routers().Local(), max: BucketCount * capacity,
	}, nil
}

func (s *RouterInfoStore) Path() string { return s.path }

// MaxBytes is the largest accepted complete snapshot for this table capacity.
func (s *RouterInfoStore) MaxBytes() int {
	return routerSnapshotHeader + s.max*(8+2+MaxRouterInfoBytes+routerSnapshotDigest)
}

// Dirty reports whether table state has changed since the last complete save.
func (s *RouterInfoStore) Dirty() bool {
	s.mu.Lock()
	dirty := s.database.Routers().Generation() != s.savedGeneration
	s.mu.Unlock()
	return dirty
}

// Load restores valid, fresh, signature-verified records before network work
// begins. A missing snapshot is empty state. Header identity mismatches are
// ignored as foreign state; malformed records are rejected individually when
// their framing permits recovery.
func (s *RouterInfoStore) Load(nowMillis uint64) (RouterInfoLoadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, _, err := state.FilesystemStoreOpenRegular(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.savedGeneration = s.database.Routers().Generation()
		return RouterInfoLoadResult{}, nil
	}
	if err != nil {
		return RouterInfoLoadResult{}, err
	}
	defer file.Close()
	data, err := state.FilesystemStoreReadBoundedFile(file, int64(s.MaxBytes()))
	if err != nil {
		return RouterInfoLoadResult{}, err
	}
	result, err := s.loadLocked(data, nowMillis)
	// The durable file, even if it contains rejected records, is the baseline;
	// a future network admission makes the table dirty again.
	s.savedGeneration = s.database.Routers().Generation()
	return result, err
}

func (s *RouterInfoStore) loadLocked(data []byte, nowMillis uint64) (RouterInfoLoadResult, error) {
	if len(data) < routerSnapshotHeader || !bytes.Equal(data[:8], routerSnapshotMagic[:]) || binary.BigEndian.Uint16(data[8:10]) != routerSnapshotVersion || binary.BigEndian.Uint32(data[10:14]) != s.networkID || !bytes.Equal(data[14:14+foundation.HashLength], s.local[:]) {
		return RouterInfoLoadResult{}, ErrRouterSnapshotHeader
	}
	count := int(binary.BigEndian.Uint32(data[14+foundation.HashLength : routerSnapshotHeader]))
	if count > s.max {
		return RouterInfoLoadResult{}, ErrRouterSnapshotOverflow
	}
	cursor := routerSnapshotHeader
	var result RouterInfoLoadResult
	for range count {
		if len(data)-cursor < 10 {
			return result, ErrRouterSnapshotRecord
		}
		seenAt := binary.BigEndian.Uint64(data[cursor : cursor+8])
		wireLen := int(binary.BigEndian.Uint16(data[cursor+8 : cursor+10]))
		cursor += 10
		if wireLen == 0 || wireLen > MaxRouterInfoBytes || len(data)-cursor < wireLen+routerSnapshotDigest {
			return result, ErrRouterSnapshotRecord
		}
		wire := data[cursor : cursor+wireLen]
		digest := data[cursor+wireLen : cursor+wireLen+routerSnapshotDigest]
		cursor += wireLen + routerSnapshotDigest
		if !snapshotRecordDigestMatches(seenAt, wire, digest) {
			result.Rejected++
			continue
		}
		info, parseErr := ParseRouterInfo(wire)
		if parseErr != nil {
			result.Rejected++
			continue
		}
		if seenAt > nowMillis {
			seenAt = nowMillis
		}
		if admitErr := s.database.AdmitRouterInfo(info, false, seenAt); admitErr != nil {
			result.Rejected++
			continue
		}
		result.Loaded++
	}
	if cursor != len(data) {
		return result, ErrRouterSnapshotRecord
	}
	return result, nil
}

// Save writes one atomic, mode-0600 snapshot if the table changed. A mutation
// racing encoding remains dirty and is saved by the next maintenance pass.
func (s *RouterInfoStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	generation, peers := s.database.Routers().Snapshot()
	if generation == s.savedGeneration {
		return nil
	}
	if len(peers) > s.max {
		return ErrRouterSnapshotOverflow
	}
	data, err := s.encode(peers)
	if err != nil {
		return err
	}
	if err := state.FilesystemStoreWriteAtomic(s.path, data, 0o600, s.MaxBytes()); err != nil {
		return err
	}
	if s.database.Routers().Generation() == generation {
		s.savedGeneration = generation
	}
	return nil
}

func (s *RouterInfoStore) encode(peers []RouterRef) ([]byte, error) {
	n := routerSnapshotHeader
	for _, peer := range peers {
		wire := peer.Info.Bytes()
		if len(wire) == 0 || len(wire) > MaxRouterInfoBytes || len(wire) > int(^uint16(0)) {
			return nil, ErrRouterSnapshotRecord
		}
		n += 8 + 2 + len(wire) + routerSnapshotDigest
		if n > s.MaxBytes() {
			return nil, ErrRouterSnapshotOverflow
		}
	}
	data := make([]byte, n)
	copy(data[:8], routerSnapshotMagic[:])
	binary.BigEndian.PutUint16(data[8:10], routerSnapshotVersion)
	binary.BigEndian.PutUint32(data[10:14], s.networkID)
	copy(data[14:14+foundation.HashLength], s.local[:])
	binary.BigEndian.PutUint32(data[14+foundation.HashLength:routerSnapshotHeader], uint32(len(peers)))
	cursor := routerSnapshotHeader
	for _, peer := range peers {
		wire := peer.Info.Bytes()
		binary.BigEndian.PutUint64(data[cursor:cursor+8], peer.LastSeen)
		binary.BigEndian.PutUint16(data[cursor+8:cursor+10], uint16(len(wire)))
		copy(data[cursor+10:cursor+10+len(wire)], wire)
		digest := snapshotRecordDigest(peer.LastSeen, wire)
		copy(data[cursor+10+len(wire):cursor+10+len(wire)+routerSnapshotDigest], digest[:])
		cursor += 10 + len(wire) + routerSnapshotDigest
	}
	return data, nil
}

func snapshotRecordDigest(seenAt uint64, wire []byte) [sha256.Size]byte {
	var header [10]byte
	binary.BigEndian.PutUint64(header[:8], seenAt)
	binary.BigEndian.PutUint16(header[8:], uint16(len(wire)))
	hash := sha256.New()
	_, _ = hash.Write(header[:])
	_, _ = hash.Write(wire)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func snapshotRecordDigestMatches(seenAt uint64, wire, expected []byte) bool {
	digest := snapshotRecordDigest(seenAt, wire)
	return len(expected) == len(digest) && bytes.Equal(expected, digest[:])
}
