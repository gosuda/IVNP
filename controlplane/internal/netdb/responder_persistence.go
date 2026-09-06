package netdb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

const (
	responderSnapshotVersion = uint16(1)
	responderSnapshotHeader  = 8 + 2 + 4 + foundation.HashLength + 4
	responderSnapshotRecord  = foundation.HashLength + 8
)

var (
	responderSnapshotMagic     = [8]byte{'I', 'V', 'N', 'P', 'R', 'S', 'P', 0}
	ErrResponderSnapshotConfig = errors.New("netdb: invalid responder snapshot configuration")
	ErrResponderSnapshot       = errors.New("netdb: invalid responder snapshot")
)

type ResponderProfileStoreConfig struct {
	Path      string
	Profiles  *ResponderProfiles
	Database  *Database
	NetworkID uint32
	Now       func() uint64
}

// ResponderProfileStore persists authenticated reply history, bound to the local
// router and network. The checksum detects corruption, not malicious local writes.
type ResponderProfileStore struct {
	mu          sync.Mutex
	path        string
	profiles    *ResponderProfiles
	database    *Database
	networkID   uint32
	local       foundation.Hash
	now         func() uint64
	savedDigest [sha256.Size]byte
}

func NewResponderProfileStore(config ResponderProfileStoreConfig) (*ResponderProfileStore, error) {
	if config.Path == "" || config.Profiles == nil || config.Database == nil || config.Now == nil {
		return nil, ErrResponderSnapshotConfig
	}
	return &ResponderProfileStore{
		path: config.Path, profiles: config.Profiles, database: config.Database,
		networkID: config.NetworkID, local: config.Database.Routers().Local(), now: config.Now,
	}, nil
}

func (s *ResponderProfileStore) maxBytes() int {
	return responderSnapshotHeader + s.profiles.maxPeers*responderSnapshotRecord + sha256.Size
}

// Load runs after verified RouterInfos are restored and before request workers start.
// No record is applied until the entire snapshot framing and checksum are valid.
func (s *ResponderProfileStore) Load() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, _, err := state.FilesystemStoreOpenRegular(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := state.FilesystemStoreReadBoundedFile(file, int64(s.maxBytes()))
	if err != nil {
		return err
	}
	if len(data) < responderSnapshotHeader+sha256.Size || !bytes.Equal(data[:8], responderSnapshotMagic[:]) || binary.BigEndian.Uint16(data[8:10]) != responderSnapshotVersion || binary.BigEndian.Uint32(data[10:14]) != s.networkID || !bytes.Equal(data[14:14+foundation.HashLength], s.local[:]) {
		return ErrResponderSnapshot
	}
	count := uint64(binary.BigEndian.Uint32(data[14+foundation.HashLength : responderSnapshotHeader]))
	if count > uint64(s.profiles.maxPeers) || uint64(len(data)) != responderSnapshotHeader+count*responderSnapshotRecord+sha256.Size {
		return ErrResponderSnapshot
	}
	payload := data[:len(data)-sha256.Size]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], data[len(payload):]) {
		return ErrResponderSnapshot
	}
	observations := make([]responderObservation, 0, int(count))
	seen := make(map[foundation.Hash]struct{}, int(count))
	now := s.now()
	for cursor := responderSnapshotHeader; cursor < len(payload); cursor += responderSnapshotRecord {
		var peer foundation.Hash
		copy(peer[:], data[cursor:cursor+foundation.HashLength])
		if _, duplicate := seen[peer]; duplicate || peer == (foundation.Hash{}) {
			return ErrResponderSnapshot
		}
		seen[peer] = struct{}{}
		seenAt := binary.BigEndian.Uint64(data[cursor+foundation.HashLength : cursor+responderSnapshotRecord])
		if responderObservationFresh(seenAt, now) && responderEligible(s.database, peer, now) {
			observations = append(observations, responderObservation{peer: peer, seenAt: seenAt, success: true})
		}
	}
	s.profiles.mu.Lock()
	s.profiles.expireLocked(now)
	for _, observation := range observations {
		s.profiles.recordLocked(observation)
	}
	s.profiles.mu.Unlock()
	s.savedDigest = digest
	return nil
}

// Save compares the filtered snapshot, so clock-driven expiry is durable even
// when no new replies arrive. Concurrent replies are retained for the next save.
func (s *ResponderProfileStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	observations := s.profiles.snapshot(now)
	data := make([]byte, responderSnapshotHeader, responderSnapshotHeader+len(observations)*responderSnapshotRecord+sha256.Size)
	copy(data[:8], responderSnapshotMagic[:])
	binary.BigEndian.PutUint16(data[8:10], responderSnapshotVersion)
	binary.BigEndian.PutUint32(data[10:14], s.networkID)
	copy(data[14:14+foundation.HashLength], s.local[:])
	count := uint32(0)
	for _, observation := range observations {
		if !responderEligible(s.database, observation.peer, now) {
			continue
		}
		data = append(data, observation.peer[:]...)
		data = binary.BigEndian.AppendUint64(data, observation.seenAt)
		count++
	}
	binary.BigEndian.PutUint32(data[14+foundation.HashLength:responderSnapshotHeader], count)
	digest := sha256.Sum256(data)
	if digest == s.savedDigest {
		return nil
	}
	data = append(data, digest[:]...)
	if err := state.FilesystemStoreWriteAtomic(s.path, data, 0o600, s.maxBytes()); err != nil {
		return err
	}
	s.savedDigest = digest
	return nil
}
