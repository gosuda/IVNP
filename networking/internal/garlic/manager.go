package garlic

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"io"
	"sync"
)

const (
	defaultSessionManagerPeers       = 1024
	defaultSessionManagerTagsPerPeer = 128
	defaultSessionManagerTagsMessage = 40
	defaultSessionTagLifetime        = 12 * 60 * 1000 // milliseconds
)

// ErrSessionManagerClosed reports use after Close.
var ErrSessionManagerClosed = errors.New("garlic: session manager closed")

// SessionManagerConfig bounds all state retained by a SessionManager. Times
// passed to Encrypt, Receive, and Expire are Unix milliseconds, matching I2NP
// expiration fields and TagStore.
type SessionManagerConfig struct {
	// InboundTags is the one-use tag store used for received existing-session
	// packets. If nil, the manager creates a bounded store. The manager clears
	// this store on Close, including when it was supplied by the caller.
	InboundTags *TagStore
	// MaxInboundTags is used only when InboundTags is nil.
	MaxInboundTags int
	// MaxPeers and MaxTagsPerPeer bound outgoing peer state.
	MaxPeers       int
	MaxTagsPerPeer int
	// TagsPerMessage is the number of fresh tags delivered with each outbound
	// packet. It must not exceed MaxSessionTags or MaxTagsPerPeer.
	TagsPerMessage int
	// TagLifetime is the lifetime of generated tags in milliseconds.
	TagLifetime uint64
	// Random supplies generated session tags. Nil uses crypto/rand.Reader.
	// Legacy ElGamal and CBC padding retain the codecs' crypto/rand source.
	Random io.Reader
}

type outboundTag struct {
	key      [32]byte
	expires  uint64
	reserved bool
}

type outboundPeer struct {
	confirmed map[[32]byte]outboundTag
	pending   map[[32]byte]outboundTag
}

// SessionManager is a bounded, peer-sharded manager for legacy ElGamal/AES
// Garlic sessions. All packet results alias the caller-provided dst buffer.
type SessionManager struct {
	lifecycleMu sync.RWMutex
	randomMu    sync.Mutex
	inbound     *TagStore
	shards      []sessionManagerShard
	closed      bool

	maxTagsPerPeer int
	tagsPerMessage int
	tagLifetime    uint64
	random         io.Reader
}

type sessionManagerShard struct {
	mu       sync.Mutex
	peers    map[ivnp.Hash]*outboundPeer
	maxPeers int
}

// NewSessionManager constructs a manager with bounded defaults matching Java
// I2P's legacy session-tag policy: 40 tags per message, at most 128 per peer,
// and a twelve-minute tag lifetime.
func NewSessionManager(config SessionManagerConfig) *SessionManager {
	if config.MaxPeers <= 0 {
		config.MaxPeers = defaultSessionManagerPeers
	}
	if config.MaxTagsPerPeer <= 0 {
		config.MaxTagsPerPeer = defaultSessionManagerTagsPerPeer
	}
	if config.TagsPerMessage <= 0 {
		config.TagsPerMessage = defaultSessionManagerTagsMessage
	}
	if config.TagsPerMessage > config.MaxTagsPerPeer {
		config.TagsPerMessage = config.MaxTagsPerPeer
	}
	if config.TagsPerMessage > MaxSessionTags {
		config.TagsPerMessage = MaxSessionTags
	}
	if config.TagLifetime == 0 {
		config.TagLifetime = defaultSessionTagLifetime
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.InboundTags == nil {
		maxInbound := config.MaxInboundTags
		if maxInbound <= 0 {
			maxInt := int(^uint(0) >> 1)
			if config.MaxPeers > maxInt/config.MaxTagsPerPeer {
				maxInbound = maxInt
			} else {
				maxInbound = config.MaxPeers * config.MaxTagsPerPeer
			}
		}
		config.InboundTags = NewTagStore(maxInbound)
	}
	shardCount := parallelism.Workers(config.MaxPeers)
	peersPerShard := (config.MaxPeers + shardCount - 1) / shardCount
	manager := &SessionManager{
		inbound: config.InboundTags, shards: make([]sessionManagerShard, shardCount),
		maxTagsPerPeer: config.MaxTagsPerPeer, tagsPerMessage: config.TagsPerMessage,
		tagLifetime: config.TagLifetime, random: config.Random,
	}
	for index := range manager.shards {
		manager.shards[index] = sessionManagerShard{peers: make(map[ivnp.Hash]*outboundPeer), maxPeers: peersPerShard}
	}
	return manager
}

// InboundTags returns the manager's one-use inbound tag store. Callers must not
// retain keys from it; tags are intentionally consumed before CBC validation.
func (m *SessionManager) InboundTags() *TagStore {
	if m == nil {
		return nil
	}
	return m.inbound
}
func (m *SessionManager) peerShard(peer ivnp.Hash) *sessionManagerShard {
	return &m.shards[binary.LittleEndian.Uint64(peer[:8])%uint64(len(m.shards))]
}

// Encrypt writes a legacy ElGamal/AES Garlic packet for peer into dst. It uses
// an available confirmed peer-scoped tag for an existing session, otherwise
// starts a new ElGamal session. Tags delivered by this packet remain pending
// until ConfirmOutboundTags records transport confirmation. The returned packet
// aliases dst.
func (m *SessionManager) Encrypt(dst []byte, peer ivnp.Hash, recipient cryptx.ElGamalPublicKey, payload []byte, now uint64) ([]byte, error) {
	if m == nil {
		return nil, ErrSessionManagerClosed
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return nil, ErrSessionManagerClosed
	}
	var delivered [MaxSessionTags * 32]byte
	fresh := delivered[:m.tagsPerMessage*32]
	var tag, key [32]byte
	var existing bool
	shard := m.peerShard(peer)
	shard.mu.Lock()
	m.expireOutboundShardLocked(shard, now)
	if state := shard.peers[peer]; state != nil {
		for candidate, entry := range state.confirmed {
			if !entry.reserved {
				tag, key = candidate, entry.key
				entry.reserved = true
				state.confirmed[candidate] = entry
				existing = true
				break
			}
		}
	}
	shard.mu.Unlock()
	if err := m.readTags(fresh); err != nil {
		m.releaseReserved(shard, peer, tag, existing)
		return nil, err
	}
	if existing {
		packet, err := EncryptExisting(dst, tag[:], key[:], payload, fresh)
		if err != nil {
			m.releaseReserved(shard, peer, tag, true)
			return nil, err
		}
		shard.mu.Lock()
		if state := shard.peers[peer]; state != nil {
			if consumed, ok := state.confirmed[tag]; ok {
				clear(consumed.key[:])
				state.confirmed[tag] = consumed
				delete(state.confirmed, tag)
			}
			m.installPendingOutboundLocked(shard, peer, key, fresh, m.expiresAt(now))
		}
		shard.mu.Unlock()
		return packet, nil
	}
	packet, sessionKey, err := EncryptNew(dst, recipient, payload, fresh)
	if err != nil {
		return nil, err
	}
	shard.mu.Lock()
	m.installPendingOutboundLocked(shard, peer, sessionKey, fresh, m.expiresAt(now))
	shard.mu.Unlock()
	clear(sessionKey[:])
	return packet, nil
}

// Receive classifies packet as a known existing session or a new ElGamal/AES
// session and decrypts it into dst. A matching existing tag is consumed before
// decryption and is never retried as new-session input, even if CBC validation
// fails. payload and deliveredTags alias dst.
func (m *SessionManager) Receive(dst, packet []byte, private cryptx.ElGamalPrivateKey, now uint64) (payload, deliveredTags []byte, isNew bool, err error) {
	if m == nil {
		return nil, nil, false, ErrSessionManagerClosed
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return nil, nil, false, ErrSessionManagerClosed
	}
	if len(packet) >= 32 {
		if key, ok := m.inbound.Take(packet[:32], now); ok {
			var replacement [32]byte
			var replaceKey bool
			payload, deliveredTags, replacement, replaceKey, err = decryptExisting(dst, packet[:32], key[:], packet[32:])
			if err != nil {
				clear(key[:])
				clear(replacement[:])
				return nil, nil, false, err
			}
			if replaceKey {
				clear(key[:])
				key = replacement
			}
			m.installInbound(deliveredTags, key, now)
			clear(key[:])
			clear(replacement[:])
			return payload, deliveredTags, false, nil
		}
	}
	payload, deliveredTags, key, err := ReceiveNew(dst, packet, private)
	if err != nil {
		return nil, nil, false, err
	}
	m.installInbound(deliveredTags, key, now)
	clear(key[:])
	return payload, deliveredTags, true, nil
}

// Expire removes tags and peer state whose expiry is strictly before now,
// matching TagStore's boundary semantics. It returns the number of removed
// inbound and outbound tags.
func (m *SessionManager) Expire(now uint64) int {
	if m == nil {
		return 0
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return 0
	}
	removed := 0
	for index := range m.shards {
		shard := &m.shards[index]
		shard.mu.Lock()
		removed += m.expireOutboundShardLocked(shard, now)
		shard.mu.Unlock()
	}
	return removed + m.inbound.Expire(now)
}

// ConfirmOutboundTags moves every unexpired tag pending for peer into the
// confirmed pool. Call it only after the transport confirms delivery of the
// packet(s) that carried those tags. It returns the number of promoted tags.
// Pending and confirmed tags share MaxTagsPerPeer capacity.
func (m *SessionManager) ConfirmOutboundTags(peer ivnp.Hash, now uint64) int {
	if m == nil {
		return 0
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return 0
	}
	shard := m.peerShard(peer)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	m.expireOutboundShardLocked(shard, now)
	state := shard.peers[peer]
	if state == nil {
		return 0
	}
	confirmed := 0
	for tag, entry := range state.pending {
		state.confirmed[tag] = entry
		delete(state.pending, tag)
		confirmed++
	}
	if len(state.confirmed) == 0 {
		delete(shard.peers, peer)
	}
	return confirmed
}

// Close drops all inbound and outbound keys. It is idempotent; later Encrypt
// and Receive calls return ErrSessionManagerClosed.
func (m *SessionManager) Close() error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for index := range m.shards {
		shard := &m.shards[index]
		shard.mu.Lock()
		for peer, state := range shard.peers {
			for tag, entry := range state.confirmed {
				clear(entry.key[:])
				state.confirmed[tag] = entry
				delete(state.confirmed, tag)
			}
			for tag, entry := range state.pending {
				clear(entry.key[:])
				state.pending[tag] = entry
				delete(state.pending, tag)
			}
			delete(shard.peers, peer)
		}
		shard.mu.Unlock()
	}
	m.inbound.Clear()
	return nil
}

func (m *SessionManager) installInbound(tags []byte, key [32]byte, now uint64) {
	if len(tags) == 0 {
		return
	}
	expires := m.expiresAt(now)
	for len(tags) != 0 {
		m.inbound.Put(tags[:32], key[:], expires)
		tags = tags[32:]
	}
}

func (m *SessionManager) releaseReserved(shard *sessionManagerShard, peer ivnp.Hash, tag [32]byte, reserved bool) {
	if !reserved {
		return
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if state := shard.peers[peer]; state != nil {
		if entry, ok := state.confirmed[tag]; ok {
			entry.reserved = false
			state.confirmed[tag] = entry
		}
	}
}

func (m *SessionManager) readTags(dst []byte) error {
	m.randomMu.Lock()
	defer m.randomMu.Unlock()
	_, err := io.ReadFull(m.random, dst)
	return err
}

func (m *SessionManager) expiresAt(now uint64) uint64 {
	if ^uint64(0)-now < m.tagLifetime {
		return ^uint64(0)
	}
	return now + m.tagLifetime
}

func (m *SessionManager) installPendingOutboundLocked(shard *sessionManagerShard, peer ivnp.Hash, key [32]byte, tags []byte, expires uint64) {
	state := shard.peers[peer]
	if state == nil {
		if len(shard.peers) >= shard.maxPeers && !m.evictPeerLocked(shard) {
			// Every retained peer has an in-flight selected tag. Do not evict
			// one: a later sealing failure must leave that tag usable.
			return
		}
		state = &outboundPeer{
			confirmed: make(map[[32]byte]outboundTag),
			pending:   make(map[[32]byte]outboundTag),
		}
		shard.peers[peer] = state
	}
	for len(tags) != 0 {
		var tag [32]byte
		copy(tag[:], tags[:32])
		if entry, ok := state.confirmed[tag]; ok {
			clear(entry.key[:])
			state.confirmed[tag] = entry
			delete(state.confirmed, tag)
		}
		if entry, ok := state.pending[tag]; ok {
			clear(entry.key[:])
			state.pending[tag] = entry
			delete(state.pending, tag)
		}
		for len(state.confirmed)+len(state.pending) >= m.maxTagsPerPeer {
			if !m.evictTagLocked(state) {
				// All capacity is reserved by in-flight sends. Keeping those
				// tags is more important than retaining extra delivered tags.
				return
			}
		}
		state.pending[tag] = outboundTag{key: key, expires: expires}
		tags = tags[32:]
	}
}

func (m *SessionManager) expireOutboundShardLocked(shard *sessionManagerShard, now uint64) int {
	removed := 0
	for peer, state := range shard.peers {
		for tag, entry := range state.confirmed {
			if entry.expires < now && !entry.reserved {
				clear(entry.key[:])
				state.confirmed[tag] = entry
				delete(state.confirmed, tag)
				removed++
			}
		}
		for tag, entry := range state.pending {
			if entry.expires < now {
				clear(entry.key[:])
				state.pending[tag] = entry
				delete(state.pending, tag)
				removed++
			}
		}
		if len(state.confirmed) == 0 && len(state.pending) == 0 {
			delete(shard.peers, peer)
		}
	}
	return removed
}

func (m *SessionManager) evictPeerLocked(shard *sessionManagerShard) bool {
	var oldestPeer ivnp.Hash
	var oldest uint64 = ^uint64(0)
	found := false
	for peer, state := range shard.peers {
		hasReserved := false
		for _, entry := range state.confirmed {
			if entry.reserved {
				hasReserved = true
				break
			}
		}
		if hasReserved {
			continue
		}
		for _, entry := range state.confirmed {
			if !found || entry.expires < oldest {
				oldest, oldestPeer, found = entry.expires, peer, true
			}
		}
		for _, entry := range state.pending {
			if !found || entry.expires < oldest {
				oldest, oldestPeer, found = entry.expires, peer, true
			}
		}
	}
	if !found {
		return false
	}
	state := shard.peers[oldestPeer]
	for tag, entry := range state.confirmed {
		clear(entry.key[:])
		state.confirmed[tag] = entry
		delete(state.confirmed, tag)
	}
	for tag, entry := range state.pending {
		clear(entry.key[:])
		state.pending[tag] = entry
		delete(state.pending, tag)
	}
	delete(shard.peers, oldestPeer)
	return true
}

func (m *SessionManager) evictTagLocked(state *outboundPeer) bool {
	var oldest [32]byte
	var deadline uint64 = ^uint64(0)
	var pending bool
	found := false
	for tag, entry := range state.confirmed {
		if !entry.reserved && (!found || entry.expires < deadline) {
			oldest, deadline, pending, found = tag, entry.expires, false, true
		}
	}
	for tag, entry := range state.pending {
		if !found || entry.expires < deadline {
			oldest, deadline, pending, found = tag, entry.expires, true, true
		}
	}
	if !found {
		return false
	}
	if pending {
		entry := state.pending[oldest]
		clear(entry.key[:])
		state.pending[oldest] = entry
		delete(state.pending, oldest)
		return true
	}
	entry := state.confirmed[oldest]
	clear(entry.key[:])
	state.confirmed[oldest] = entry
	delete(state.confirmed, oldest)
	return true
}
