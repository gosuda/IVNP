package garlic

import (
	"encoding/binary"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	garlicecies "gosuda.org/ivnp/networking/internal/garlic/ecies"
)

type RatchetConfig = garlicecies.RatchetConfig
type RatchetOptions = garlicecies.RatchetOptions
type RatchetResult = garlicecies.RatchetResult
type RatchetACK = garlicecies.ACK
type RatchetStats = garlicecies.RatchetStats

var (
	ErrRatchet          = garlicecies.ErrRatchet
	ErrRatchetClosed    = garlicecies.ErrRatchetClosed
	ErrRatchetReplay    = garlicecies.ErrRatchetReplay
	ErrRatchetExpired   = garlicecies.ErrRatchetExpired
	ErrRatchetNoSession = garlicecies.ErrRatchetNoSession
)

// RatchetManager shards independent peer sessions across CPU-scaled ECIES
// managers. Packet tags route established and pending inbound work directly to
// its owner; deterministic packet hashing routes new sessions and replays.
type RatchetManager struct {
	routeMu sync.RWMutex
	shards  []*garlicecies.RatchetManager
	once    sync.Once
}

// NewRatchetManager binds sharded ECIES garlic state to one LocalDestination.
func NewRatchetManager(local *foundation.LocalDestination, config RatchetConfig) (*RatchetManager, error) {
	maxSessions := config.MaxSessions
	if maxSessions <= 0 {
		maxSessions = 256
	}
	maxTags := config.MaxInboundTags
	if maxTags <= 0 {
		maxTags = 8192
	}
	lookahead := config.TagLookahead
	if lookahead <= 0 {
		lookahead = 32
	}
	shardCount := min(parallelism.Workers(maxSessions), max(1, maxTags/lookahead))
	config.MaxSessions = (maxSessions + shardCount - 1) / shardCount
	config.MaxInboundTags = (maxTags + shardCount - 1) / shardCount
	manager := &RatchetManager{shards: make([]*garlicecies.RatchetManager, 0, shardCount)}
	for range shardCount {
		shard, err := garlicecies.NewRatchetManager(local, config)
		if err != nil {
			manager.ReleaseSensitive()
			return nil, err
		}
		manager.shards = append(manager.shards, shard)
	}
	return manager, nil
}

func (m *RatchetManager) locatePeerLocked(peer foundation.Hash) (int, bool) {
	for index, shard := range m.shards {
		if shard.HasPeer(peer) {
			return index, true
		}
	}
	return 0, false
}
func (m *RatchetManager) ownsPeerOutsideLocked(peer foundation.Hash, owner int) bool {
	for index, shard := range m.shards {
		if index != owner && shard.HasPeer(peer) {
			return true
		}
	}
	return false
}

func (m *RatchetManager) peerShardLocked(peer foundation.Hash) (int, *garlicecies.RatchetManager) {
	if index, ok := m.locatePeerLocked(peer); ok {
		return index, m.shards[index]
	}
	index := int(binary.LittleEndian.Uint64(peer[:8]) % uint64(len(m.shards)))
	return index, m.shards[index]
}

func (m *RatchetManager) packetShardLocked(packet []byte) (int, *garlicecies.RatchetManager) {
	for index, shard := range m.shards {
		if shard.OwnsTag(packet) {
			return index, shard
		}
	}
	index := uint64(0)
	if len(packet) >= 8 {
		index = binary.LittleEndian.Uint64(packet[:8])
	}
	shardIndex := int(index % uint64(len(m.shards)))
	return shardIndex, m.shards[shardIndex]
}

func (m *RatchetManager) BindPeer(observed, peer foundation.Hash) error {
	if m == nil || observed == (foundation.Hash{}) || peer == (foundation.Hash{}) {
		return ErrRatchet
	}
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	observedIndex, observedExists := m.locatePeerLocked(observed)
	if !observedExists {
		return ErrRatchetNoSession
	}
	if m.ownsPeerOutsideLocked(peer, observedIndex) {
		return ErrRatchet
	}
	if err := m.shards[observedIndex].BindPeer(observed, peer); err != nil {
		return err
	}
	return nil
}

func (m *RatchetManager) Stats() RatchetStats {
	var stats RatchetStats
	if m == nil {
		return stats
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	for _, shard := range m.shards {
		current := shard.Stats()
		stats.Sessions += current.Sessions
		stats.Pending += current.Pending
		stats.InboundTags += current.InboundTags
		stats.NewSessions += current.NewSessions
		stats.NewSessionReplies += current.NewSessionReplies
		stats.ExistingSessions += current.ExistingSessions
	}
	return stats
}

func (m *RatchetManager) Encrypt(dst []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrRatchetClosed
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	_, shard := m.peerShardLocked(peer)
	return shard.Encrypt(dst, peer, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) EncryptWithScratch(dst, plain []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrRatchetClosed
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	_, shard := m.peerShardLocked(peer)
	return shard.EncryptWithScratch(dst, plain, peer, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) EncryptUnbound(dst []byte, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrRatchetClosed
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	index := uint64(0)
	if len(remotePublic) >= 8 {
		index = binary.LittleEndian.Uint64(remotePublic[:8])
	}
	return m.shards[index%uint64(len(m.shards))].EncryptUnbound(dst, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) EncryptExisting(dst []byte, peer foundation.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrRatchetClosed
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	_, shard := m.peerShardLocked(peer)
	return shard.EncryptExisting(dst, peer, payload, options, now)
}

func (m *RatchetManager) EncryptExistingWithScratch(dst, plain []byte, peer foundation.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrRatchetClosed
	}
	m.routeMu.RLock()
	defer m.routeMu.RUnlock()
	_, shard := m.peerShardLocked(peer)
	return shard.EncryptExistingWithScratch(dst, plain, peer, payload, options, now)
}

func (m *RatchetManager) Receive(dst, replyDst, packet []byte, now uint64) (RatchetResult, error) {
	if m == nil || len(m.shards) == 0 {
		return RatchetResult{}, ErrRatchetClosed
	}
	m.routeMu.RLock()
	index, shard := m.packetShardLocked(packet)
	result, err := shard.Receive(dst, replyDst, packet, now)
	m.routeMu.RUnlock()
	if err != nil || result.Peer == (foundation.Hash{}) {
		return result, err
	}
	m.routeMu.Lock()
	if m.ownsPeerOutsideLocked(result.Peer, index) {
		shard.DiscardPeer(result.Peer)
		m.routeMu.Unlock()
		return RatchetResult{}, ErrRatchet
	}
	m.routeMu.Unlock()
	return result, nil
}

func (m *RatchetManager) ReleaseSensitive() {
	if m == nil {
		return
	}
	m.once.Do(func() {
		m.routeMu.Lock()
		defer m.routeMu.Unlock()
		for _, shard := range m.shards {
			shard.ReleaseSensitive()
		}
	})
}

func (m *RatchetManager) Close() error {
	m.ReleaseSensitive()
	return nil
}
