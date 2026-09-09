package garlicecies

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

const (
	ratchetTagLen              = 8
	ratchetBlockHeader         = 3
	ratchetDateTime            = 0
	ratchetTermination         = 4
	ratchetPrevious            = 6
	ratchetNextKey             = 7
	ratchetACK                 = 8
	ratchetACKRequest          = 9
	ratchetGarlicClove         = 11
	ratchetPadding             = 254
	DefaultTagLookahead        = 512
	defaultMaxSessions         = 256
	defaultMaxTags             = 8192
	defaultSessionLife         = 10 * 60 * 1000
	defaultReplayLife          = 5 * 60 * 1000
	previousSetLife            = 3 * 60 * 1000
	automaticDHRatchetMessages = 4096
	newSessionRestartAge       = 2 * 60 * 1000
)

var (
	ErrRatchet             = errors.New("garlic/ecies: invalid ratchet packet")
	ErrRatchetClosed       = errors.New("garlic/ecies: ratchet manager is closed")
	ErrRatchetReplay       = errors.New("garlic/ecies: replayed new session")
	ErrRatchetExpired      = errors.New("garlic/ecies: ratchet session expired")
	ErrRatchetNoSession    = errors.New("garlic/ecies: no ratchet session")
	ErrRatchetTagExhausted = errors.New("garlic/ecies: ratchet tag set exhausted")
)

// RatchetConfig limits destination-local ratchet state. SessionLifetime is an
// idle timeout. Times are Unix milliseconds; durations are milliseconds.
// CryptoTypes orders the accepted New Session formats. An empty set enables
// ML-KEM-1024/X25519, ML-KEM-768/X25519, then X25519.
type RatchetConfig struct {
	CryptoTypes []uint16
	MaxSessions int
	// MaxInboundTags bounds registered receive tags, including retained history.
	MaxInboundTags int
	// TagLookahead is the forward window; nonpositive selects DefaultTagLookahead.
	// Up to the same number of earlier indices are retained when the tag budget allows.
	TagLookahead    int
	SessionLifetime uint64
	ReplayLifetime  uint64
	Metrics         *observability.Registry
}

// ACK identifies an Existing Session message acknowledged in-band.
type ACK struct{ TagSet, Message uint16 }

// RatchetOptions controls protocol blocks on an Existing Session message.
type RatchetOptions struct {
	ACKs       []ACK
	ACKRequest bool
	Terminate  bool
	RequestDH  bool
}

// RatchetResult aliases caller buffers. A non-nil Candidate owns an
// authenticated bound New Session until CommitNewSession or Discard consumes
// it. Callers must consume every candidate before releasing the aliased buffers.
type RatchetResult struct {
	Payload     []byte
	Reply       []byte
	Peer        foundation.Hash
	Candidate   *NewSessionCandidate
	NewSession  bool
	Terminated  bool
	ACKs        []ACK
	ACKRequests []ACK
	// ReplyRequested covers NSR confirmation, ACKRequest, and forward NextKey.
	ReplyRequested bool
	DHStep         bool
}

// SessionTag is the non-secret routing prefix of an ECIES ratchet packet.
type SessionTag [ratchetTagLen]byte

// TagObserver mirrors live one-time receive tags into the destination-level
// shard index. Callbacks run while the owning RatchetManager is locked.
type TagObserver interface {
	TagAdded(SessionTag)
	TagRemoved(SessionTag)
}

// NewSessionCommit reports the final admission decision for an authenticated
// bound New Session.
type NewSessionCommit uint8

const (
	newSessionCommitInvalid NewSessionCommit = iota
	NewSessionInstalled
	NewSessionRetained
	NewSessionReplaced
)

// NewSessionCandidate owns derived ratchet state outside the session and tag
// maps. Discard is idempotent and is a no-op after commit or retention.
type NewSessionCandidate struct {
	mu      sync.Mutex
	owner   foundation.Hash
	session *session
}

// Discard clears an uncommitted New Session candidate.
func (c *NewSessionCandidate) Discard() {
	if c == nil {
		return
	}
	c.mu.Lock()
	session := c.session
	c.session = nil
	c.owner = foundation.Hash{}
	c.mu.Unlock()
	releaseSession(session)
}

func (c *NewSessionCandidate) take(owner foundation.Hash) (*session, error) {
	if c == nil || owner == (foundation.Hash{}) {
		return nil, ErrRatchet
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil || c.owner != owner {
		return nil, ErrRatchet
	}
	session := c.session
	c.session = nil
	c.owner = foundation.Hash{}
	return session, nil
}

type tagEntry struct {
	tag [ratchetTagLen]byte
	set *tagSet
	n   uint16
	key [32]byte
}

type tagSet struct {
	id                uint16
	root              [32]byte
	nextRoot          [32]byte
	tagChain          [32]byte
	tagConst          [32]byte
	keyChain          [32]byte
	next              uint32
	receivedHighWater uint32
	receiveFloor      uint32
	receiveTags       []receiveTag
	previous          *tagSet

	expires  uint64
	oldUntil uint64
	owner    *session
}

type session struct {
	peer       foundation.Hash
	outbound   *tagSet
	inbound    *tagSet
	forwardDH  dhRatchet
	reverseDH  dhRatchet
	created    uint64
	expires    uint64
	terminated bool
}

// Each traffic direction has its own key pair and NextKey exchange.
type dhRatchet struct {
	localKey    *cryptography.X25519PrivateKey
	remoteKey   *ecdh.PublicKey
	localKeyID  int
	remoteKeyID int
	received    nextKey
	pending     nextKey
	send        bool
}

type nextKey struct {
	flags byte
	id    uint16
	key   [32]byte
}

func (k nextKey) size() int {
	if k.flags&1 != 0 {
		return ratchetNextKeyBlockLen
	}
	return 6
}

func (k nextKey) appendTo(dst []byte) int {
	size := k.size()
	dst[0] = ratchetNextKey
	binary.BigEndian.PutUint16(dst[1:3], uint16(size-3))
	dst[3] = k.flags
	binary.BigEndian.PutUint16(dst[4:6], k.id)
	if k.flags&1 != 0 {
		copy(dst[6:38], k.key[:])
	}
	return size
}

type pendingInitiator struct {
	handshake *Initiator
	peer      foundation.Hash
	expires   uint64
}

// RatchetStats is a consistent, non-sensitive snapshot of one destination's
// ECIES session state and authenticated receive transitions.
type RatchetStats struct {
	Sessions          int
	Pending           int
	InboundTags       int
	NewSessions       uint64
	NewSessionReplies uint64
	ExistingSessions  uint64
}

// RatchetManager owns all ECIES state for exactly one LocalDestination. It is
// safe for concurrent send/receive calls; packet buffers always remain owned by
// the caller. Session tags are removed before AEAD verification, so a replay or
// forgery can never be retried as either an Existing or New Session.
type RatchetManager struct {
	mu            sync.Mutex
	owner         foundation.Hash
	private       [32]byte
	cryptoTypes   [3]uint16
	cryptoCount   int
	config        RatchetConfig
	closed        bool
	sessions      map[foundation.Hash]*session
	inbound       map[[ratchetTagLen]byte]tagEntry
	pending       map[[ratchetTagLen]byte]pendingInitiator
	replays       map[[32]byte]uint64
	metrics       *observability.Registry
	tagObserver   TagObserver
	windowScratch []tagEntry
	windowTags    map[[ratchetTagLen]byte]struct{}

	newSessions       uint64
	newSessionReplies uint64
	existingSessions  uint64
}

// NewRatchetManager creates destination-scoped ECIES state. The local private
// key is copied from LocalDestination and never retained by reference.
func NewRatchetManager(local *foundation.LocalDestination, config RatchetConfig) (*RatchetManager, error) {
	return newRatchetManager(local, config, nil)
}

// NewRatchetManagerWithTagObserver creates a manager whose live receive tags
// are mirrored into a caller-owned routing index.
func NewRatchetManagerWithTagObserver(local *foundation.LocalDestination, config RatchetConfig, observer TagObserver) (*RatchetManager, error) {
	if observer == nil {
		return nil, ErrRatchet
	}
	return newRatchetManager(local, config, observer)
}

func newRatchetManager(local *foundation.LocalDestination, config RatchetConfig, observer TagObserver) (*RatchetManager, error) {
	if local == nil {
		return nil, ErrRatchet
	}
	if len(config.CryptoTypes) == 0 {
		config.CryptoTypes = []uint16{7, 6, 4}
	}
	if len(config.CryptoTypes) > 3 {
		return nil, ErrRatchet
	}
	var cryptoTypes [3]uint16
	for i, cryptoType := range config.CryptoTypes {
		if cryptoType != 4 && cryptoType != 6 && cryptoType != 7 {
			return nil, ErrRatchet
		}
		for j := range i {
			if cryptoTypes[j] == cryptoType {
				return nil, ErrRatchet
			}
		}
		cryptoTypes[i] = cryptoType
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.MaxInboundTags <= 0 {
		config.MaxInboundTags = defaultMaxTags
	}
	if config.TagLookahead <= 0 {
		config.TagLookahead = DefaultTagLookahead
	}
	if config.TagLookahead > config.MaxInboundTags || config.TagLookahead > 65536 {
		return nil, ErrRatchet
	}
	if config.SessionLifetime == 0 {
		config.SessionLifetime = defaultSessionLife
	}
	if config.ReplayLifetime == 0 {
		config.ReplayLifetime = defaultReplayLife
	}
	var private [32]byte
	if err := local.CopyCryptoPrivate(foundation.CryptoX25519, private[:]); err != nil {
		return nil, err
	}
	cryptoCount := len(config.CryptoTypes)
	config.CryptoTypes = nil
	return &RatchetManager{owner: local.Hash(), private: private, cryptoTypes: cryptoTypes, cryptoCount: cryptoCount, config: config, metrics: config.Metrics, tagObserver: observer, sessions: make(map[foundation.Hash]*session), inbound: make(map[[ratchetTagLen]byte]tagEntry), pending: make(map[[ratchetTagLen]byte]pendingInitiator), replays: make(map[[32]byte]uint64), windowScratch: make([]tagEntry, config.TagLookahead), windowTags: make(map[[ratchetTagLen]byte]struct{}, config.TagLookahead)}, nil
}
func (m *RatchetManager) addInboundTagLocked(entry tagEntry) {
	m.inbound[entry.tag] = entry
	entry.set.recordInbound(entry.tag, entry.n, m.config.TagLookahead)
	if m.tagObserver != nil {
		m.tagObserver.TagAdded(SessionTag(entry.tag))
	}
}

func (m *RatchetManager) removeInboundTagLocked(tag [ratchetTagLen]byte) {
	entry, exists := m.inbound[tag]
	if !exists {
		return
	}
	entry.set.forgetInbound(tag, entry.n)
	clear(entry.key[:])
	m.inbound[tag] = entry
	delete(m.inbound, tag)
	if m.tagObserver != nil {
		m.tagObserver.TagRemoved(SessionTag(tag))
	}
}

func (m *RatchetManager) addPendingTagLocked(tag [ratchetTagLen]byte, pending pendingInitiator) {
	m.pending[tag] = pending
	if m.tagObserver != nil {
		m.tagObserver.TagAdded(SessionTag(tag))
	}
}

func (m *RatchetManager) removePendingTagLocked(tag [ratchetTagLen]byte) {
	if _, exists := m.pending[tag]; !exists {
		return
	}
	delete(m.pending, tag)
	if m.tagObserver != nil {
		m.tagObserver.TagRemoved(SessionTag(tag))
	}
}

// CommitNewSession atomically retains a recent session or installs the
// authenticated candidate under peer. The candidate is consumed on every
// decision made for a matching local destination.
func (m *RatchetManager) CommitNewSession(candidate *NewSessionCandidate, peer foundation.Hash, now uint64) (NewSessionCommit, error) {
	if m == nil || candidate == nil || peer == (foundation.Hash{}) {
		return newSessionCommitInvalid, ErrRatchet
	}
	session, err := candidate.take(m.owner)
	if err != nil {
		return newSessionCommitInvalid, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err = m.checkLocked(now); err != nil {
		releaseSession(session)
		return newSessionCommitInvalid, err
	}
	old := m.sessions[peer]
	if recentSession(old, now) {
		releaseSession(session)
		return NewSessionRetained, nil
	}
	session.peer = peer
	if err = m.installSessionLocked(session, now); err != nil {
		releaseSession(session)
		return newSessionCommitInvalid, err
	}
	if old != nil {
		return NewSessionReplaced, nil
	}
	return NewSessionInstalled, nil
}

// RetainNewSession consumes the candidate only when a recent peer session can
// be kept without installing keys or sending another New Session Reply.
func (m *RatchetManager) RetainNewSession(candidate *NewSessionCandidate, peer foundation.Hash, now uint64) (bool, error) {
	if m == nil || candidate == nil || peer == (foundation.Hash{}) {
		return false, ErrRatchet
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return false, err
	}
	if !recentSession(m.sessions[peer], now) {
		return false, nil
	}
	session, err := candidate.take(m.owner)
	if err != nil {
		return false, err
	}
	releaseSession(session)
	return true, nil
}

func recentSession(current *session, now uint64) bool {
	return current != nil && now >= current.created && now-current.created <= newSessionRestartAge
}

// OwnsTag reports whether tag currently addresses an inbound or pending
// session. It enables destination-level lock sharding without exposing keys.
func (m *RatchetManager) OwnsTag(tag []byte) bool {
	if m == nil || len(tag) < ratchetTagLen {
		return false
	}
	var key [ratchetTagLen]byte
	copy(key[:], tag[:ratchetTagLen])
	m.mu.Lock()
	_, inbound := m.inbound[key]
	_, pending := m.pending[key]
	owned := !m.closed && (inbound || pending)
	m.mu.Unlock()
	return owned
}

// HasPeer reports whether this shard owns an established peer session.
func (m *RatchetManager) HasPeer(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	session := m.sessions[peer]
	owned := !m.closed && session != nil && !session.terminated
	m.mu.Unlock()
	return owned
}

// Stats returns bounded state counts without exposing ratchet keys or tags.
func (m *RatchetManager) Stats() RatchetStats {
	if m == nil {
		return RatchetStats{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return RatchetStats{
		Sessions:          len(m.sessions),
		Pending:           len(m.pending),
		InboundTags:       len(m.inbound),
		NewSessions:       m.newSessions,
		NewSessionReplies: m.newSessionReplies,
		ExistingSessions:  m.existingSessions,
	}
}

// Encrypt starts a bound New Session when no established session exists for
// peer, otherwise emits an Existing Session. remotePublic is the selected LS2
// encryption key and cryptoType must be 4, 6, or 7.
func (m *RatchetManager) Encrypt(dst []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	return m.encryptLocked(dst, nil, peer, remotePublic, cryptoType, payload, now)
}

// EncryptWithScratch is Encrypt with caller-owned steady-state plaintext
// storage. New Session handshakes may still use their handshake workspace;
// established sessions do not allocate a per-message block buffer.
func (m *RatchetManager) EncryptWithScratch(dst, plain []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	return m.encryptLocked(dst, plain, peer, remotePublic, cryptoType, payload, now)
}

// RatchetEncryptBufferSizes bounds EncryptWithScratch output and plaintext
// workspace across new sessions and automatic DH rotation. Unbound encryption
// needs only the output buffer. Bounds include partial-error writes.
func RatchetEncryptBufferSizes(payloadLen int, cryptoType uint16) (packet, plain int, err error) {
	if payloadLen < 0 || payloadLen > foundation.I2NPI2PDMaxPayload {
		return 0, 0, ErrRatchet
	}
	hybridLen := 0
	if cryptoType != 4 {
		params, known := cryptography.Parameters(cryptoType)
		if !known || (cryptoType != 6 && cryptoType != 7) {
			return 0, 0, ErrRatchet
		}
		hybridLen = params.PublicKeySize + cryptography.ChaChaTagSize
	}
	plain = payloadLen + 2*ratchetNextKeyBlockLen
	newSessionLen := newSessionEphemeralLen + hybridLen + staticSectionLen + minNewSessionPayload + payloadLen + cryptography.ChaChaTagSize
	return max(newSessionLen, ratchetTagLen+plain+cryptography.ChaChaTagSize), plain, nil
}

const ratchetNextKeyBlockLen = 3 + 35

func (m *RatchetManager) encryptLocked(dst, scratch []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if established := m.sessions[peer]; established != nil && !established.terminated && established.expires >= now {
		options := RatchetOptions{}
		if established.outbound != nil && established.outbound.next >= automaticDHRatchetMessages && !established.forwardDH.send {
			options.RequestDH = true
		}
		packet, err := m.encryptExistingLocked(dst, scratch, established, payload, options, now)
		if !errors.Is(err, ErrRatchetTagExhausted) && !errors.Is(err, ErrRatchetExpired) {
			return packet, err
		}
		// Expired directions and an exhausted unacknowledged DH step require a
		// fresh handshake with the current LeaseSet key.
		m.discardSessionLocked(peer, established)
	}
	return m.encryptNewLocked(dst, peer, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) encryptNewLocked(dst []byte, peer foundation.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	encryptNewLockedRejected := len(remotePublic) != 32
	if !encryptNewLockedRejected {
		encryptNewLockedRejected = (cryptoType != 4 && cryptoType != 6 && cryptoType != 7)
	}
	if encryptNewLockedRejected {
		return nil, ErrRatchet
	}
	initiator, err := NewInitiator(m.private[:], remotePublic, cryptoType, true)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 7+len(payload))
	plain[0] = ratchetDateTime
	binary.BigEndian.PutUint16(plain[1:3], 4)
	binary.BigEndian.PutUint32(plain[3:7], uint32(now/1000))
	copy(plain[7:], payload)
	n, err := initiator.CreateNewSession(dst, plain)
	clear(plain)
	if err != nil {
		initiator.ReleaseSensitive()
		return nil, err
	}
	tag, err := initiator.ReplyTag()
	if err != nil {
		initiator.ReleaseSensitive()
		return nil, err
	}
	if len(m.pending) >= m.config.MaxSessions {
		initiator.ReleaseSensitive()
		return nil, ErrRatchet
	}
	if _, exists := m.pending[tag]; exists {
		initiator.ReleaseSensitive()
		return nil, ErrRatchet
	}
	if _, exists := m.inbound[tag]; exists {
		initiator.ReleaseSensitive()
		return nil, ErrRatchet
	}
	m.addPendingTagLocked(tag, pendingInitiator{handshake: initiator, peer: peer, expires: now + m.config.ReplayLifetime})
	if m.metrics != nil {
		m.metrics.IncGarlicECIESNewSessionSent()
	}
	return dst[:n], nil
}

// EncryptUnbound emits a one-way New Session for payloads such as raw
// datagrams which neither identify the sender nor require a reply session.
func (m *RatchetManager) EncryptUnbound(dst []byte, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	encryptUnboundRejected := len(remotePublic) != 32
	if !encryptUnboundRejected {
		encryptUnboundRejected = (cryptoType != 4 && cryptoType != 6 && cryptoType != 7)
	}
	if encryptUnboundRejected {
		return nil, ErrRatchet
	}
	initiator, err := NewInitiator(m.private[:], remotePublic, cryptoType, false)
	if err != nil {
		return nil, err
	}
	defer initiator.ReleaseSensitive()
	plain := make([]byte, 7+len(payload))
	plain[0] = ratchetDateTime
	binary.BigEndian.PutUint16(plain[1:3], 4)
	binary.BigEndian.PutUint32(plain[3:7], uint32(now/1000))
	copy(plain[7:], payload)
	n, err := initiator.CreateNewSession(dst, plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	if m.metrics != nil {
		m.metrics.IncGarlicECIESNewSessionSent()
	}
	return dst[:n], nil
}

// EncryptExisting emits a one-time-tag Existing Session message. A peer is the
// exact identifier used to create the session (for a responder, RatchetResult's
// Peer); no state is ever shared between destination managers.
func (m *RatchetManager) EncryptExisting(dst []byte, peer foundation.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	s := m.sessions[peer]
	if s == nil || s.terminated {
		return nil, ErrRatchetNoSession
	}
	return m.encryptExistingLocked(dst, nil, s, payload, options, now)
}

// EncryptExistingWithScratch is the allocation-free steady-state send path.
// plain must have capacity for the authenticated ratchet blocks and remains
// caller-owned. Its used portion is cleared before return.
func (m *RatchetManager) EncryptExistingWithScratch(dst, plain []byte, peer foundation.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	s := m.sessions[peer]
	if s == nil || s.terminated {
		return nil, ErrRatchetNoSession
	}
	return m.encryptExistingLocked(dst, plain, s, payload, options, now)
}

func (m *RatchetManager) encryptExistingLocked(dst, scratch []byte, s *session, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
	if s.expires < now || s.outbound.expires < now || s.inbound.expires < now {
		return nil, ErrRatchetExpired
	}
	if options.RequestDH && !s.forwardDH.send {
		if err := s.beginForwardDH(); err != nil {
			return nil, err
		}
	}
	sentDH := s.forwardDH.send || s.reverseDH.send
	blocksLen := len(payload)
	if len(options.ACKs) != 0 {
		blocksLen += 3 + 4*len(options.ACKs)
	}
	if options.ACKRequest {
		blocksLen += 4
	}
	if options.Terminate {
		blocksLen += 4
	}
	if s.forwardDH.send {
		blocksLen += s.forwardDH.pending.size()
	}
	if s.reverseDH.send {
		blocksLen += s.reverseDH.pending.size()
	}
	if blocksLen > 65519 {
		return nil, ErrRatchet
	}
	var plain []byte
	if len(scratch) >= blocksLen {
		plain = scratch[:blocksLen]
		clear(plain)
	} else {
		plain = make([]byte, blocksLen)
	}
	off := 0
	copy(plain[off:], payload)
	off += len(payload)
	if len(options.ACKs) != 0 {
		plain[off] = ratchetACK
		binary.BigEndian.PutUint16(plain[off+1:off+3], uint16(4*len(options.ACKs)))
		off += 3
		for _, ack := range options.ACKs {
			binary.BigEndian.PutUint16(plain[off:off+2], ack.TagSet)
			binary.BigEndian.PutUint16(plain[off+2:off+4], ack.Message)
			off += 4
		}
	}
	if options.ACKRequest {
		plain[off] = ratchetACKRequest
		binary.BigEndian.PutUint16(plain[off+1:off+3], 1)
		off += 3
		plain[off] = 0
		off++
	}
	if s.forwardDH.send {
		off += s.forwardDH.pending.appendTo(plain[off:])
	}
	if s.reverseDH.send {
		off += s.reverseDH.pending.appendTo(plain[off:])
	}
	if options.Terminate {
		plain[off] = ratchetTermination
		binary.BigEndian.PutUint16(plain[off+1:off+3], 1)
		plain[off+3] = 0
		off += 4
	}
	entry, err := s.outbound.nextEntry()
	if err != nil {
		clear(plain)
		return nil, err
	}
	if len(dst) < ratchetTagLen+len(plain)+cryptography.ChaChaTagSize {
		clear(plain)
		return nil, cryptography.ErrDestination
	}
	copy(dst[:ratchetTagLen], entry.tag[:])
	var nonce [cryptography.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(entry.n))
	_, err = cryptography.SealChaCha20Poly1305To(dst[ratchetTagLen:], entry.key[:], nonce[:], plain, dst[:ratchetTagLen])
	clear(plain)
	if err != nil {
		return nil, err
	}

	if options.Terminate {
		s.terminated = true
	}
	s.outbound.expires = max(s.outbound.expires, now+m.config.SessionLifetime)
	s.expires = max(s.expires, s.outbound.expires)
	if m.metrics != nil {
		m.metrics.IncGarlicECIESExistingSessionSent()
		if sentDH {
			m.metrics.IncGarlicECIESDHStepsSent()
		}
	}
	return dst[:ratchetTagLen+blocksLen+cryptography.ChaChaTagSize], nil
}

// Receive authenticates New Session, New Session Reply, or Existing Session.
// dst receives plaintext and replyDst receives a required NSR reply. Bound New
// Sessions return an uninstalled Candidate which the caller must commit or
// discard; Receive never evicts live session capacity for that candidate.
func (m *RatchetManager) Receive(dst, replyDst, packet []byte, now uint64) (RatchetResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return RatchetResult{}, err
	}
	if len(packet) < ratchetTagLen+cryptography.ChaChaTagSize {
		return RatchetResult{}, ErrRatchet
	}
	var tag [ratchetTagLen]byte
	copy(tag[:], packet[:ratchetTagLen])
	if entry, ok := m.inbound[tag]; ok {
		result, err := m.receiveExistingLocked(dst, packet, tag, entry, now)
		if err == nil {
			m.existingSessions++
			if m.metrics != nil {
				m.metrics.IncGarlicECIESExistingSessionReceived()
				if result.DHStep {
					m.metrics.IncGarlicECIESDHStepsReceived()
				}
			}
		}
		return result, err
	}
	if pending, ok := m.pending[tag]; ok {
		result, err := m.receiveReplyLocked(dst, packet, tag, pending, now)
		if err == nil {
			m.newSessionReplies++
			if m.metrics != nil {
				m.metrics.IncGarlicECIESNewSessionReceived()
			}
		}
		return result, err
	}
	result, err := m.receiveNewLocked(dst, replyDst, packet, now)
	if err == nil {
		m.newSessions++
		if m.metrics != nil {
			m.metrics.IncGarlicECIESNewSessionReceived()
		}
	}
	return result, err
}

func (m *RatchetManager) receiveReplyLocked(dst, packet []byte, tag [ratchetTagLen]byte, pending pendingInitiator, now uint64) (RatchetResult, error) {
	m.removePendingTagLocked(tag)
	defer pending.handshake.ReleaseSensitive()
	payload, err := pending.handshake.ParseReply(packet, dst)
	if err != nil {
		return RatchetResult{}, err
	}
	root, send, recv, err := pending.handshake.SplitWithRoot()
	if err != nil {
		return RatchetResult{}, err
	}
	defer clear(root[:])
	s, err := m.sessionFromCiphers(pending.peer, root, send, recv, now)
	if err != nil {
		return RatchetResult{}, err
	}
	if err = m.installSessionLocked(s, now); err != nil {
		releaseSession(s)
		return RatchetResult{}, err
	}
	return RatchetResult{Payload: payload, Peer: pending.peer, NewSession: true, ReplyRequested: true}, nil
}

func (m *RatchetManager) receiveNewLocked(dst, replyDst, packet []byte, now uint64) (RatchetResult, error) {
	if len(packet) < 32 {
		return RatchetResult{}, ErrRatchet
	}
	var ephemeral [32]byte
	copy(ephemeral[:], packet[:32])
	if until, duplicate := m.replays[ephemeral]; duplicate && until >= now {
		return RatchetResult{}, ErrRatchetReplay
	}

	var responder *Responder
	var payload []byte
	var parseErr error
	for _, cryptoType := range m.cryptoTypes[:m.cryptoCount] {
		candidate, err := NewResponder(m.private[:], cryptoType)
		if err != nil {
			return RatchetResult{}, err
		}
		payload, err = candidate.ParseNewSession(packet, dst)
		if err == nil {
			responder = candidate
			break
		}
		candidate.ReleaseSensitive()
		parseErr = err
	}
	if responder == nil {
		if parseErr ==
			nil {
			parseErr = ErrRatchet

		}

		return RatchetResult{}, parseErr
	}
	defer responder.ReleaseSensitive()

	application, err := validateNewPayload(payload, now)
	if err != nil {
		return RatchetResult{}, err
	}
	if !responder.bound {
		m.replays[ephemeral] = now + m.config.ReplayLifetime
		return RatchetResult{Payload: application, NewSession: true}, nil
	}
	tag, err := responder.ReplyTag()
	if err != nil {
		return RatchetResult{}, err
	}
	peer := foundation.Sum(responderPeerID(responder))
	n, err := responder.CreateReply(replyDst, tag, nil)
	if err != nil {
		return RatchetResult{}, err
	}
	root, send, recv, err := responder.SplitWithRoot()
	if err != nil {
		return RatchetResult{}, err
	}
	defer clear(root[:])
	s, err := m.sessionFromCiphers(peer, root, send, recv, now)
	if err != nil {
		return RatchetResult{}, err
	}
	candidate := &NewSessionCandidate{owner: m.owner, session: s}
	// Authentication and replay reservation complete together, while session
	// and tag admission remain deferred until the authenticated Destination is
	// known to the caller.
	m.replays[ephemeral] = now + m.config.ReplayLifetime
	return RatchetResult{Payload: application, Reply: replyDst[:n], Peer: peer, Candidate: candidate, NewSession: true}, nil
}

func (m *RatchetManager) receiveExistingLocked(dst, packet []byte, tag [ratchetTagLen]byte, entry tagEntry, now uint64) (RatchetResult, error) {
	// One-time removal happens before authentication. The sender cannot make a
	// malformed packet fall through to a New Session parse or retry this tag.
	m.removeInboundTagLocked(tag)
	defer clear(entry.key[:])
	if entry.set.expires < now || entry.set.oldUntil != 0 && entry.set.oldUntil < now {
		return RatchetResult{}, ErrRatchetExpired
	}

	if len(packet) < ratchetTagLen+cryptography.ChaChaTagSize || len(dst) < len(packet)-ratchetTagLen-cryptography.ChaChaTagSize {
		return RatchetResult{}, ErrRatchet
	}
	var nonce [cryptography.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(entry.n))
	plain, err := cryptography.OpenChaCha20Poly1305To(dst, entry.key[:], nonce[:], packet[ratchetTagLen:], packet[:ratchetTagLen])
	if err != nil {
		return RatchetResult{}, ErrRatchet
	}
	if err := m.advanceInboundWindowLocked(entry.set, uint32(entry.n)); err != nil {
		clear(plain)
		return RatchetResult{}, err
	}
	result, err := m.parseExistingLocked(entry, plain, now)
	if err != nil {
		clear(plain)
		return RatchetResult{}, err
	}
	// Only authenticated traffic renews receive keys; old DH sets still obey oldUntil.
	entry.set.expires = max(entry.set.expires, now+m.config.SessionLifetime)
	entry.set.owner.expires = max(entry.set.owner.expires, entry.set.expires)
	if entry.set == entry.set.owner.inbound {
		entry.set.owner.reverseDH.send = false
	}
	result.Payload, result.Peer = plain, sessionPeer(entry.set, m.sessions)
	return result, nil
}

func (m *RatchetManager) parseExistingLocked(entry tagEntry, plain []byte, now uint64) (RatchetResult, error) {
	var out RatchetResult
	for off := 0; off < len(plain); {
		if len(plain)-off < ratchetBlockHeader {
			return RatchetResult{}, ErrRatchet
		}
		kind := plain[off]
		size := int(binary.BigEndian.Uint16(plain[off+1 : off+3]))
		off += ratchetBlockHeader
		if size > len(plain)-off {
			return RatchetResult{}, ErrRatchet
		}
		data := plain[off : off+size]
		off += size
		switch kind {
		case ratchetACK:
			if size == 0 || size%4 != 0 {
				return RatchetResult{}, ErrRatchet
			}
			for len(data) != 0 {
				out.ACKs = append(out.ACKs, ACK{binary.BigEndian.Uint16(data[:2]), binary.BigEndian.Uint16(data[2:4])})
				data = data[4:]
			}
		case ratchetACKRequest:
			if size != 1 {
				return RatchetResult{}, ErrRatchet
			}
			if len(out.ACKRequests) == 0 {
				out.ACKRequests = []ACK{{entry.set.id, entry.n}}
			}
			out.ReplyRequested = true
		case ratchetTermination:
			if size < 1 || off != len(plain) && plain[off] != ratchetPadding {
				return RatchetResult{}, ErrRatchet
			}
			out.Terminated = true
		case ratchetNextKey:
			if err := m.consumeNextKeyLocked(entry.set, data, now); err != nil {
				return RatchetResult{}, err
			}
			out.DHStep = true
			if data[0]&2 == 0 && entry.set.owner.reverseDH.send {
				out.ReplyRequested = true
			}
		case ratchetDateTime, ratchetPrevious, ratchetGarlicClove, ratchetPadding:
			// The payload is delivered intact to the garlic router. DateTime and
			// PN are retained for callers that need their protocol semantics.
		default:
			// Forward-compatible unknown blocks are authenticated and ignored.
		}
	}
	if out.Terminated {
		if s := sessionForSet(entry.set, m.sessions); s != nil {
			s.terminated = true
		}
	}
	return out, nil
}

func (m *RatchetManager) consumeNextKeyLocked(current *tagSet, data []byte, now uint64) error {
	if len(data) != 3 && len(data) != 35 {
		return ErrRatchet
	}
	key := nextKey{flags: data[0], id: binary.BigEndian.Uint16(data[1:3])}
	if key.flags&^byte(7) != 0 || key.flags&6 == 6 || key.id > 32767 || (key.flags&1 != 0) != (len(data) == 35) {
		return ErrRatchet
	}
	copy(key.key[:], data[3:])
	s := current.owner
	if s == nil {
		return ErrRatchet
	}
	if key.flags&2 != 0 {
		return m.receiveReverseKeyLocked(s, key, now)
	}
	return m.receiveForwardKeyLocked(s, current, key, now)
}

func (s *session) beginForwardDH() error {
	if s.outbound.id == 65535 {
		s.terminated = true
		return ErrRatchetTagExhausted
	}
	dh := &s.forwardDH
	key := nextKey{flags: 4}
	if s.outbound.id == 0 || s.outbound.id&1 != 0 {
		if dh.localKeyID == 32767 {
			s.terminated = true
			return ErrRatchetTagExhausted
		}
		private, err := cryptography.GenerateX25519PrivateKey(nil)
		if err != nil {
			return err
		}
		if err := private.PublicKey(&key.key); err != nil {
			private.ReleaseSensitive()
			return err
		}
		dh.localKey.ReleaseSensitive()
		dh.localKey, dh.localKeyID = private, dh.localKeyID+1
		key.flags = 1
		if s.outbound.id == 0 {
			key.flags |= 4
		}
	}
	key.id = uint16(dh.localKeyID)
	dh.pending, dh.send = key, true
	return nil
}

func (dh *dhRatchet) resolveRemote(key nextKey) (*ecdh.PublicKey, error) {
	if key.flags&1 != 0 && int(key.id) == dh.remoteKeyID+1 {
		return ecdh.X25519().NewPublicKey(key.key[:])
	}
	if key.flags&1 == 0 && int(key.id) == dh.remoteKeyID && dh.remoteKey != nil {
		return dh.remoteKey, nil
	}
	return nil, ErrRatchet
}

func (m *RatchetManager) receiveReverseKeyLocked(s *session, key nextKey, now uint64) error {
	dh := &s.forwardDH
	// Reverse keys may be repeated until the peer sees the new tagset.
	if key == dh.received || !dh.send {
		return nil
	}
	if int(key.id) < dh.remoteKeyID || int(key.id) == dh.remoteKeyID && key.flags&1 != 0 {
		return nil
	}
	remote, err := dh.resolveRemote(key)
	if err != nil || dh.localKey == nil || 1+dh.localKeyID+int(key.id) != int(s.outbound.id)+1 {
		return ErrRatchet
	}
	var shared [32]byte
	err = dh.localKey.ECDH(&shared, remote.Bytes())
	if err != nil {
		return ErrRatchet
	}
	defer clear(shared[:])
	next, _, err := m.prepareRatchetDirectionLocked(s, true, shared[:], now)
	if err != nil {
		s.terminated = true
		return err
	}
	m.commitRatchetDirectionLocked(s, true, next, nil, now)
	dh.remoteKey, dh.remoteKeyID, dh.received, dh.send = remote, int(key.id), key, false
	return nil
}

func (m *RatchetManager) receiveForwardKeyLocked(s *session, current *tagSet, key nextKey, now uint64) error {
	dh := &s.reverseDH
	// Old-tagset packets may arrive after the exchange has completed.
	if key == dh.received || current != s.inbound {
		return nil
	}
	remote, err := dh.resolveRemote(key)
	if err != nil {
		return err
	}
	local, localID := dh.localKey, dh.localKeyID
	reply := nextKey{flags: 2}
	if current.id&1 == 0 {
		if localID == 32767 {
			return ErrRatchetTagExhausted
		}
		local, err = cryptography.GenerateX25519PrivateKey(nil)
		if err != nil {
			return err
		}
		defer func() {
			if local != dh.localKey {
				local.ReleaseSensitive()
			}
		}()
		localID++
		reply.flags |= 1
		if err := local.PublicKey(&reply.key); err != nil {
			return err
		}
	}
	if local == nil || 1+localID+int(key.id) != int(current.id)+1 {
		return ErrRatchet
	}
	var shared [32]byte
	err = local.ECDH(&shared, remote.Bytes())
	if err != nil {
		return ErrRatchet
	}
	defer clear(shared[:])
	next, entries, err := m.prepareRatchetDirectionLocked(s, false, shared[:], now)
	if err != nil {
		s.terminated = true
		return err
	}
	m.commitRatchetDirectionLocked(s, false, next, entries, now)
	clearTagEntries(entries)
	reply.id = uint16(localID)
	if local != dh.localKey {
		dh.localKey.ReleaseSensitive()
	}
	dh.localKey, dh.localKeyID = local, localID
	dh.remoteKey, dh.remoteKeyID, dh.received = remote, int(key.id), key
	dh.pending, dh.send = reply, true
	return nil
}

// Inbound lookahead and collision checks finish before the direction advances.
func (m *RatchetManager) prepareRatchetDirectionLocked(s *session, outbound bool, shared []byte, now uint64) (*tagSet, []tagEntry, error) {
	old := s.inbound
	if outbound {
		old = s.outbound
	}
	if old == nil || old.id == 65535 {
		return nil, nil, ErrRatchetTagExhausted
	}
	prk := hmacSHA256(shared, nil, nil, 0, false)
	material := hmacSHA256(prk[:], nil, nil, 1, true, "XDHRatchetTagSet")
	clear(prk[:])
	defer clear(material[:])
	next, err := newTagSet(old.id+1, old.nextRoot, material[:], now+m.config.SessionLifetime)
	if err != nil {
		return nil, nil, err
	}
	next.owner = s
	if outbound {
		return next, nil, nil
	}
	if len(m.inbound)+m.config.TagLookahead > m.config.MaxInboundTags {
		releaseTagSet(next)
		return nil, nil, ErrRatchetTagExhausted
	}
	entries := make([]tagEntry, 0, m.config.TagLookahead)
	for range m.config.TagLookahead {
		entry, entryErr := next.nextEntry()
		if entryErr != nil {
			clearTagEntries(entries)
			releaseTagSet(next)
			return nil, nil, entryErr
		}
		if _, exists := m.inbound[entry.tag]; exists {
			clear(entry.key[:])
			clearTagEntries(entries)
			releaseTagSet(next)
			return nil, nil, ErrRatchet
		}
		if _, exists := m.pending[entry.tag]; exists {
			clear(entry.key[:])
			clearTagEntries(entries)
			releaseTagSet(next)
			return nil, nil, ErrRatchet
		}
		entries = append(entries, entry)
	}
	return next, entries, nil
}

func (m *RatchetManager) commitRatchetDirectionLocked(s *session, outbound bool, next *tagSet, entries []tagEntry, now uint64) {
	if outbound {
		old := s.outbound
		s.outbound = next
		releaseTagSet(old)
		return
	}
	if s.inbound != nil {
		s.inbound.oldUntil = now + previousSetLife
	}
	next.previous = s.inbound
	s.inbound = next
	for _, entry := range entries {
		m.addInboundTagLocked(entry)
	}
}

func clearTagEntries(entries []tagEntry) {
	for index := range entries {
		clear(entries[index].key[:])
	}
}

func (m *RatchetManager) sessionFromCiphers(peer foundation.Hash, root [32]byte, send, recv *cryptography.ChaCha20Poly1305, now uint64) (*session, error) {
	if send == nil || recv == nil {
		return nil, ErrRatchet
	}
	defer send.ReleaseSensitive()
	defer recv.ReleaseSensitive()
	var sendKey, recvKey [32]byte
	if err := send.CopyKey(sendKey[:]); err != nil {
		return nil, err
	}
	if err := recv.CopyKey(recvKey[:]); err != nil {
		return nil, err
	}
	defer clear(sendKey[:])
	defer clear(recvKey[:])
	out, err := newTagSet(0, root, sendKey[:], now+m.config.SessionLifetime)
	if err != nil {
		return nil, err
	}
	in, err := newTagSet(0, root, recvKey[:], now+m.config.SessionLifetime)
	if err != nil {
		return nil, err
	}
	s := &session{
		peer: peer, outbound: out, inbound: in, created: now, expires: now + m.config.SessionLifetime,
		forwardDH: dhRatchet{localKeyID: -1, remoteKeyID: -1},
		reverseDH: dhRatchet{localKeyID: -1, remoteKeyID: -1},
	}
	out.owner, in.owner = s, s
	return s, nil
}

func (m *RatchetManager) installSessionLocked(s *session, now uint64) error {
	if s == nil || s.inbound == nil {
		return ErrRatchet
	}
	old := m.sessions[s.peer]
	var victim *session
	if old == nil && len(m.sessions) >= m.config.MaxSessions {
		victim = m.sessionVictimLocked()
	}
	removed := 0
	for _, entry := range m.inbound {
		if entry.set.owner == old || entry.set.owner == victim {
			removed++
		}
	}
	needed := m.config.TagLookahead
	if len(m.inbound)-removed+needed > m.config.MaxInboundTags {
		return ErrRatchetTagExhausted
	}
	entries := make([]tagEntry, 0, needed)
	defer func() {
		for i := range entries {
			clear(entries[i].key[:])
		}
	}()
	for range needed {
		entry, err := s.inbound.nextEntry()
		if err != nil {
			return err
		}
		if current, exists := m.inbound[entry.tag]; exists && current.set.owner != old && current.set.owner != victim {
			clear(entry.key[:])
			return ErrRatchet
		}
		if _, exists := m.pending[entry.tag]; exists {
			clear(entry.key[:])
			return ErrRatchet
		}
		entries = append(entries, entry)
	}
	if old != nil {
		m.discardSessionLocked(s.peer, old)
	}
	if victim != nil {
		m.discardSessionLocked(victim.peer, victim)
	}
	m.sessions[s.peer] = s
	for _, entry := range entries {
		m.addInboundTagLocked(entry)
	}
	return nil
}

func (m *RatchetManager) checkLocked(now uint64) error {
	if m.closed {
		return ErrRatchetClosed
	}
	for tag, pending := range m.pending {
		if pending.expires < now {
			pending.handshake.ReleaseSensitive()
			m.removePendingTagLocked(tag)
		}
	}
	for eph, expiry := range m.replays {
		if expiry < now {
			delete(m.replays, eph)
		}
	}
	for peer, s := range m.sessions {
		if s.expires < now || s.terminated {
			m.discardSessionLocked(peer, s)
			continue
		}
		m.expireOldTagsLocked(s, now)
	}
	return nil
}

func (m *RatchetManager) expireOldTagsLocked(s *session, now uint64) {
	if s.inbound == nil {
		return
	}
	if s.inbound.expires < now {
		m.removeTagSetTagsLocked(s.inbound)
	}
	previous := s.inbound
	for set := previous.previous; set != nil; set = previous.previous {
		if set.expires >= now && (set.oldUntil == 0 || set.oldUntil >= now) {
			previous = set
			continue
		}
		previous.previous = set.previous
		m.removeTagSetTagsLocked(set)
		releaseTagSet(set)
	}
}
func (m *RatchetManager) removeSessionTagsLocked(s *session) {
	if s == nil {
		return
	}
	for set := s.inbound; set != nil; set = set.previous {
		m.removeTagSetTagsLocked(set)
	}
}

func (m *RatchetManager) sessionVictimLocked() *session {
	var victim *session
	for _, s := range m.sessions {
		if victim == nil || s.expires < victim.expires {
			victim = s
		}
	}
	return victim
}

func (m *RatchetManager) discardSessionLocked(peer foundation.Hash, s *session) {
	if s == nil {
		return
	}
	m.removeSessionTagsLocked(s)
	delete(m.sessions, peer)
	releaseSession(s)
}

// RetirePeer removes an established session and its inbound tags. A subsequent
// send must establish a new session instead of reusing a failed reply exchange.
func (m *RatchetManager) RetirePeer(peer foundation.Hash) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.discardSessionLocked(peer, m.sessions[peer])
}

// ReleaseSensitive clears all local key material and releases unfinished
// handshakes. It is idempotent and all later operations return ErrRatchetClosed.
func (m *RatchetManager) ReleaseSensitive() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for tag, p := range m.pending {
		p.handshake.ReleaseSensitive()
		m.removePendingTagLocked(tag)
	}
	for peer, s := range m.sessions {
		m.discardSessionLocked(peer, s)
	}
	for tag, entry := range m.inbound {
		m.removeInboundTagLocked(tag)
		releaseTagSet(entry.set)
	}
	clear(m.windowScratch)
	clear(m.windowTags)
	clear(m.private[:])
	m.closed = true
}
func (m *RatchetManager) Close() error { m.ReleaseSensitive(); return nil }

func releaseSession(s *session) {
	if s == nil {
		return
	}
	releaseTagSet(s.outbound)
	for set := s.inbound; set != nil; {
		previous := set.previous
		releaseTagSet(set)
		set = previous
	}
	s.forwardDH.localKey.ReleaseSensitive()
	s.reverseDH.localKey.ReleaseSensitive()
	s.forwardDH = dhRatchet{}
	s.reverseDH = dhRatchet{}
	s.terminated = true
}

func releaseTagSet(s *tagSet) {
	if s == nil {
		return
	}
	clear(s.root[:])
	clear(s.nextRoot[:])
	clear(s.tagChain[:])
	clear(s.tagConst[:])
	clear(s.keyChain[:])
	clear(s.receiveTags)
	s.receiveTags = nil
	s.previous = nil
}

func validateNewPayload(payload []byte, now uint64) ([]byte, error) {
	if len(payload) < 7 || payload[0] != ratchetDateTime || binary.BigEndian.Uint16(payload[1:3]) != 4 {
		return nil, ErrRatchet
	}
	timestamp := uint64(binary.BigEndian.Uint32(payload[3:7]))
	seconds := now / 1000
	if timestamp+300 < seconds || timestamp > seconds+120 {
		return nil, ErrRatchetExpired
	}
	return payload[7:], nil
}

func newTagSet(id uint16, root [32]byte, input []byte, expires uint64) (*tagSet, error) {
	step := hkdf64(root[:], input, "KDFDHRatchetStep")
	chains := hkdf64(step[32:], nil, "TagAndKeyGenKeys")
	init := hkdf64(chains[:32], nil, "STInitialization")
	defer clear(step[:])
	defer clear(chains[:])
	defer clear(init[:])
	set := &tagSet{id: id, root: root, expires: expires}
	copy(set.nextRoot[:], step[:32])
	copy(set.tagChain[:], init[:32])
	copy(set.tagConst[:], init[32:])
	copy(set.keyChain[:], chains[32:])
	return set, nil
}

func (s *tagSet) nextEntry() (tagEntry, error) {
	entry, err := s.deriveEntry()
	entry.set = s
	return entry, err
}

func (s *tagSet) deriveEntry() (tagEntry, error) {
	if s == nil || s.next > 65535 {
		return tagEntry{}, ErrRatchetTagExhausted
	}
	tagData := hkdf64(s.tagChain[:], s.tagConst[:], "SessionTagKeyGen")
	keyData := hkdf64(s.keyChain[:], nil, "SymmetricRatchet")
	defer clear(tagData[:])
	defer clear(keyData[:])
	var entry tagEntry
	entry.n = uint16(s.next)
	copy(entry.key[:], keyData[32:])
	copy(entry.tag[:], tagData[32:40])
	copy(s.tagChain[:], tagData[:32])
	copy(s.keyChain[:], keyData[:32])
	s.next++
	return entry, nil
}

func hkdf64(salt, input []byte, info string) [64]byte {
	prk := hmacSHA256(salt, input, nil, 0, false)
	first := hmacSHA256(prk[:], nil, nil, 1, true, info)
	second := hmacSHA256(prk[:], first[:], nil, 2, true, info)
	var result [64]byte
	copy(result[:32], first[:])
	copy(result[32:], second[:])
	clear(prk[:])
	clear(first[:])
	clear(second[:])
	return result
}

// hmacSHA256 is the fixed-size, allocation-free HMAC primitive used by the
// ratchet KDF. Ratchet keys are at most one SHA-256 block and its HKDF info
// strings are bounded constants.
func hmacSHA256(key, prefix, suffix []byte, counter byte, includeCounter bool, info ...string) [32]byte {
	var keyBlock [64]byte
	if len(key) > len(keyBlock) {
		digest := sha256.Sum256(key)
		copy(keyBlock[:], digest[:])
		clear(digest[:])
	} else {
		copy(keyBlock[:], key)
	}
	var inner [256]byte
	for index := range keyBlock {
		inner[index] = keyBlock[index] ^ 0x36
	}
	off := len(keyBlock)
	off += copy(inner[off:], prefix)
	off += copy(inner[off:], suffix)
	for _, value := range info {
		off += copy(inner[off:], value)
	}
	if includeCounter {
		inner[off] = counter
		off++
	}
	innerDigest := sha256.Sum256(inner[:off])
	var outer [96]byte
	for index := range keyBlock {
		outer[index] = keyBlock[index] ^ 0x5c
	}
	copy(outer[64:], innerDigest[:])
	result := sha256.Sum256(outer[:])
	clear(keyBlock[:])
	clear(inner[:off])
	clear(innerDigest[:])
	clear(outer[:])
	return result
}
func deriveReplyTag(chain [32]byte) [replyTagLen]byte {
	material := hkdf64(chain[:], nil, "SessionReplyTags")
	defer clear(material[:])
	step := hkdf64(chain[:], material[:32], "KDFDHRatchetStep")
	defer clear(step[:])
	chains := hkdf64(step[32:], nil, "TagAndKeyGenKeys")
	defer clear(chains[:])
	state := hkdf64(chains[:32], nil, "STInitialization")
	defer clear(state[:])
	entry := hkdf64(state[:32], state[32:], "SessionTagKeyGen")
	defer clear(entry[:])
	var tag [replyTagLen]byte
	copy(tag[:], entry[32:40])
	return tag
}
func responderPeerID(h *Responder) []byte {
	if h == nil || h.aliceStatic == nil {
		return nil
	}
	return h.aliceStatic.Bytes()
}
func sessionForSet(set *tagSet, _ map[foundation.Hash]*session) *session {
	if set == nil {
		return nil
	}
	return set.owner
}
func sessionPeer(set *tagSet, sessions map[foundation.Hash]*session) foundation.Hash {
	if s := sessionForSet(set, sessions); s != nil {
		return s.peer
	}
	return foundation.Hash{}
}
