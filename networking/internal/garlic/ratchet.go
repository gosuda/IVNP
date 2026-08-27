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
type NewSessionCandidate = garlicecies.NewSessionCandidate
type NewSessionCommit = garlicecies.NewSessionCommit

const (
	NewSessionInstalled = garlicecies.NewSessionInstalled
	NewSessionRetained  = garlicecies.NewSessionRetained
	NewSessionReplaced  = garlicecies.NewSessionReplaced
)

var (
	ErrRatchet          = garlicecies.ErrRatchet
	ErrRatchetClosed    = garlicecies.ErrRatchetClosed
	ErrRatchetReplay    = garlicecies.ErrRatchetReplay
	ErrRatchetExpired   = garlicecies.ErrRatchetExpired
	ErrRatchetNoSession = garlicecies.ErrRatchetNoSession
)

// RatchetManager coordinates sharded ECIES ratchet sessions across worker routines.
type RatchetManager struct {
	routeMu   sync.RWMutex
	tagMu     sync.RWMutex
	tagRoutes map[garlicecies.SessionTag]int
	shards    []*garlicecies.RatchetManager
	once      sync.Once
}

type ratchetTagObserver struct {
	manager *RatchetManager
	shard   int
}

func (o ratchetTagObserver) TagAdded(tag garlicecies.SessionTag) {
	o.manager.tagMu.Lock()
	if owner, exists := o.manager.tagRoutes[tag]; !exists || owner == o.shard {
		o.manager.tagRoutes[tag] = o.shard
	} else {
		o.manager.tagRoutes[tag] = -1
	}
	o.manager.tagMu.Unlock()
}

func (o ratchetTagObserver) TagRemoved(tag garlicecies.SessionTag) {
	o.manager.tagMu.Lock()
	if o.manager.tagRoutes[tag] == o.shard {
		delete(o.manager.tagRoutes, tag)
	}
	o.manager.tagMu.Unlock()
}

// NewRatchetManager creates a sharded RatchetManager for a local destination.
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
	manager := &RatchetManager{
		tagRoutes: make(map[garlicecies.SessionTag]int, maxTags),
		shards:    make([]*garlicecies.RatchetManager, 0, shardCount),
	}
	for index := range shardCount {
		observer := ratchetTagObserver{manager: manager, shard: index}
		shard, err := garlicecies.NewRatchetManagerWithTagObserver(local, config, observer)
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

func (m *RatchetManager) peerShardLocked(peer foundation.Hash) (int, *garlicecies.RatchetManager) {
	if index, ok := m.locatePeerLocked(peer); ok {
		return index, m.shards[index]
	}
	index := int(binary.LittleEndian.Uint64(peer[:8]) % uint64(len(m.shards)))
	return index, m.shards[index]
}

func (m *RatchetManager) packetShard(packet []byte) (int, *garlicecies.RatchetManager) {
	if len(packet) >= 8 {
		var tag garlicecies.SessionTag
		copy(tag[:], packet[:8])
		m.tagMu.RLock()
		owner, indexed := m.tagRoutes[tag]
		m.tagMu.RUnlock()
		if indexed && owner >= 0 {
			return owner, m.shards[owner]
		}
		if indexed {
			for index, shard := range m.shards {
				if shard.OwnsTag(packet) {
					return index, shard
				}
			}
		}
	}
	index := uint64(0)
	if len(packet) >= 8 {
		index = binary.LittleEndian.Uint64(packet[:8])
	}
	shardIndex := int(index % uint64(len(m.shards)))
	return shardIndex, m.shards[shardIndex]
}

// CommitNew admits an authenticated bound New Session only after its
// Destination has been verified. Admission and shard selection are serialized
// so retained duplicates cannot consume session or tag capacity.
func (m *RatchetManager) CommitNew(candidate *NewSessionCandidate, peer foundation.Hash, now uint64) (NewSessionCommit, error) {
	if m == nil || candidate == nil || peer == (foundation.Hash{}) {
		return 0, ErrRatchet
	}
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	_, shard := m.peerShardLocked(peer)
	return shard.CommitNewSession(candidate, peer, now)
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
	_, shard := m.packetShard(packet)
	return shard.Receive(dst, replyDst, packet, now)
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
		m.tagMu.Lock()
		clear(m.tagRoutes)
		m.tagMu.Unlock()
	})
}

func (m *RatchetManager) Close() error {
	m.ReleaseSensitive()
	return nil
}
