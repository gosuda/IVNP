package ecies

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/crypto/cryptx"
	"gosuda.org/ivnp/support/observability"
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
	defaultLookahead           = 32
	defaultMaxSessions         = 256
	defaultMaxTags             = 8192
	defaultSessionLife         = 10 * 60 * 1000
	defaultReplayLife          = 5 * 60 * 1000
	previousSetLife            = 3 * 60 * 1000
	automaticDHRatchetMessages = 4096
)

var (
	ErrRatchet             = errors.New("garlic/ecies: invalid ratchet packet")
	ErrRatchetClosed       = errors.New("garlic/ecies: ratchet manager is closed")
	ErrRatchetReplay       = errors.New("garlic/ecies: replayed new session")
	ErrRatchetExpired      = errors.New("garlic/ecies: ratchet session expired")
	ErrRatchetNoSession    = errors.New("garlic/ecies: no ratchet session")
	ErrRatchetTagExhausted = errors.New("garlic/ecies: ratchet tag set exhausted")
)

// RatchetConfig limits all destination-local ratchet state. Times are Unix
// milliseconds. CryptoTypes is the ordered set of New Session formats accepted
// by this destination. An empty set enables every production format in
// preference order: ML-KEM-1024/X25519, ML-KEM-768/X25519, then X25519.
type RatchetConfig struct {
	CryptoTypes     []uint16
	MaxSessions     int
	MaxInboundTags  int
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

// RatchetResult aliases caller buffers. Reply is populated for authenticated
// New Sessions; callers may defer sending it to coalesce higher-layer traffic.
type RatchetResult struct {
	Payload     []byte
	Reply       []byte
	Peer        ivnp.Hash
	NewSession  bool
	Terminated  bool
	ACKs        []ACK
	ACKRequests []ACK
	DHStep      bool
}

type tagEntry struct {
	tag [ratchetTagLen]byte
	set *tagSet
	n   uint16
	key [32]byte
}

type tagSet struct {
	id       uint16
	root     [32]byte
	nextRoot [32]byte
	tagChain [32]byte
	tagConst [32]byte
	keyChain [32]byte
	next     uint32
	consumed uint32

	expires  uint64
	oldUntil uint64
	owner    *session
}

type session struct {
	peer               ivnp.Hash
	outbound           *tagSet
	inbound            *tagSet
	localKey           *ecdh.PrivateKey
	localKeyID         uint16
	pendingKeyID       uint16
	remoteForwardKeyID uint16
	remoteReverseKeyID uint16
	haveRemoteForward  bool
	haveRemoteReverse  bool
	pendingDH          bool
	replyDH            bool
	terminateAfterDH   bool
	dhSecret           [32]byte
	expires            uint64
	terminated         bool
}

type pendingInitiator struct {
	handshake *Initiator
	peer      ivnp.Hash
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
	mu          sync.Mutex
	private     [32]byte
	cryptoTypes [3]uint16
	cryptoCount int
	config      RatchetConfig
	closed      bool
	sessions    map[ivnp.Hash]*session
	inbound     map[[ratchetTagLen]byte]tagEntry
	pending     map[[ratchetTagLen]byte]pendingInitiator
	replays     map[[32]byte]uint64
	metrics     *observability.Registry

	newSessions       uint64
	newSessionReplies uint64
	existingSessions  uint64
}

// NewRatchetManager creates destination-scoped ECIES state. The local private
// key is copied from LocalDestination and never retained by reference.
func NewRatchetManager(local *ivnp.LocalDestination, config RatchetConfig) (*RatchetManager, error) {
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
		for j := 0; j < i; j++ {
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
		config.TagLookahead = defaultLookahead
	}
	if config.TagLookahead > config.MaxInboundTags {
		return nil, ErrRatchet
	}
	if config.SessionLifetime == 0 {
		config.SessionLifetime = defaultSessionLife
	}
	if config.ReplayLifetime == 0 {
		config.ReplayLifetime = defaultReplayLife
	}
	var private [32]byte
	if err := local.CopyCryptoPrivate(ivnp.CryptoX25519, private[:]); err != nil {
		return nil, err
	}
	cryptoCount := len(config.CryptoTypes)
	config.CryptoTypes = nil
	return &RatchetManager{private: private, cryptoTypes: cryptoTypes, cryptoCount: cryptoCount, config: config, metrics: config.Metrics, sessions: make(map[ivnp.Hash]*session), inbound: make(map[[ratchetTagLen]byte]tagEntry), pending: make(map[[ratchetTagLen]byte]pendingInitiator), replays: make(map[[32]byte]uint64)}, nil
}

// BindPeer replaces the encryption-key-derived responder identifier with the
// authenticated Destination hash carried by the first routed clove. This lets
// responder state be reused by callers that address peers by Destination hash.
func (m *RatchetManager) BindPeer(observed, peer ivnp.Hash) error {
	if m == nil || observed == (ivnp.Hash{}) || peer == (ivnp.Hash{}) {
		return ErrRatchet
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(0); err != nil {
		return err
	}
	if observed == peer {
		return nil
	}
	session := m.sessions[observed]
	if session == nil {
		return ErrRatchetNoSession
	}
	if existing := m.sessions[peer]; existing != nil && existing != session {
		return ErrRatchet
	}
	delete(m.sessions, observed)
	session.peer = peer
	m.sessions[peer] = session
	return nil
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
func (m *RatchetManager) HasPeer(peer ivnp.Hash) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	session := m.sessions[peer]
	owned := !m.closed && session != nil && !session.terminated
	m.mu.Unlock()
	return owned
}

// DiscardPeer removes and clears one established peer session.
func (m *RatchetManager) DiscardPeer(peer ivnp.Hash) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if session := m.sessions[peer]; session != nil {
		m.discardSessionLocked(peer, session)
	}
	m.mu.Unlock()
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
func (m *RatchetManager) Encrypt(dst []byte, peer ivnp.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
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
func (m *RatchetManager) EncryptWithScratch(dst, plain []byte, peer ivnp.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return nil, err
	}
	return m.encryptLocked(dst, plain, peer, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) encryptLocked(dst, scratch []byte, peer ivnp.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if established := m.sessions[peer]; established != nil && !established.terminated && established.expires >= now {
		options := RatchetOptions{}
		if established.outbound != nil && established.outbound.next >= automaticDHRatchetMessages && !established.pendingDH {
			options.RequestDH = true
		}
		packet, err := m.encryptExistingLocked(dst, scratch, established, payload, options, now)
		if !errors.Is(err, ErrRatchetTagExhausted) {
			return packet, err
		}
		// A peer which never returns the reverse DH key must not strand the
		// data plane on an exhausted tag set. Retire that session atomically
		// and start a fresh bound session with the current LeaseSet key.
		m.discardSessionLocked(peer, established)
	}
	return m.encryptNewLocked(dst, peer, remotePublic, cryptoType, payload, now)
}

func (m *RatchetManager) encryptNewLocked(dst []byte, peer ivnp.Hash, remotePublic []byte, cryptoType uint16, payload []byte, now uint64) ([]byte, error) {
	if len(remotePublic) != 32 || (cryptoType != 4 && cryptoType != 6 && cryptoType != 7) {
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
	m.pending[tag] = pendingInitiator{handshake: initiator, peer: peer, expires: now + m.config.ReplayLifetime}
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
	if len(remotePublic) != 32 || (cryptoType != 4 && cryptoType != 6 && cryptoType != 7) {
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
func (m *RatchetManager) EncryptExisting(dst []byte, peer ivnp.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
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
func (m *RatchetManager) EncryptExistingWithScratch(dst, plain []byte, peer ivnp.Hash, payload []byte, options RatchetOptions, now uint64) ([]byte, error) {
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
	if s.expires < now {
		return nil, ErrRatchetExpired
	}
	if options.RequestDH && !s.pendingDH {
		if s.localKeyID == 32767 {
			s.terminated = true
			return nil, ErrRatchetTagExhausted
		}
		private, err := ecdh.X25519().GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		s.localKeyID++
		s.pendingKeyID = s.localKeyID
		s.localKey, s.pendingDH = private, true
		s.terminateAfterDH = s.pendingKeyID == 32767
	}
	sentDH := s.pendingDH
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
	if s.pendingDH {
		blocksLen += 38
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
	if s.pendingDH {
		plain[off] = ratchetNextKey
		binary.BigEndian.PutUint16(plain[off+1:off+3], 35)
		if s.replyDH {
			plain[off+3] = 0x03 // key present, reverse
		} else {
			plain[off+3] = 0x05 // key present, forward + request reverse
		}
		binary.BigEndian.PutUint16(plain[off+4:off+6], s.pendingKeyID)
		copy(plain[off+6:off+38], s.localKey.PublicKey().Bytes())
		off += 38
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
	if len(dst) < ratchetTagLen+len(plain)+cryptx.ChaChaTagSize {
		clear(plain)
		return nil, cryptx.ErrDestination
	}
	copy(dst[:ratchetTagLen], entry.tag[:])
	var nonce [cryptx.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(entry.n))
	_, err = cryptx.SealChaCha20Poly1305To(dst[ratchetTagLen:], entry.key[:], nonce[:], plain, dst[:ratchetTagLen])
	clear(plain)
	if err != nil {
		return nil, err
	}
	if s.replyDH {
		nextOutbound, _, ratchetErr := m.prepareRatchetDirectionLocked(s, true, s.dhSecret[:], now)
		if ratchetErr != nil {
			s.terminated = true
			return nil, ratchetErr
		}
		m.commitRatchetDirectionLocked(s, true, nextOutbound, nil, now)
		clear(s.dhSecret[:])
		s.localKey, s.pendingKeyID, s.pendingDH, s.replyDH = nil, 0, false, false
		if s.terminateAfterDH {
			s.terminated = true
		}
	}

	if options.Terminate {
		s.terminated = true
	}
	if m.metrics != nil {
		m.metrics.IncGarlicECIESExistingSessionSent()
		if sentDH {
			m.metrics.IncGarlicECIESDHStepsSent()
		}
	}
	return dst[:ratchetTagLen+blocksLen+cryptx.ChaChaTagSize], nil
}

// Receive authenticates New Session, New Session Reply, or Existing Session.
// dst receives the plaintext and replyDst receives a required NSR reply. A
// duplicate authenticated New Session is rejected before it can create state.
func (m *RatchetManager) Receive(dst, replyDst, packet []byte, now uint64) (RatchetResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(now); err != nil {
		return RatchetResult{}, err
	}
	if len(packet) < ratchetTagLen+cryptx.ChaChaTagSize {
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
	delete(m.pending, tag)
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
	return RatchetResult{Payload: payload, Peer: pending.peer, NewSession: true}, nil
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
		if parseErr == nil {
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
	peer := ivnp.Sum(responderPeerID(responder))
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
	if err = m.installSessionLocked(s, now); err != nil {
		releaseSession(s)
		return RatchetResult{}, err
	}
	// Replay and session state commit together only after every handshake,
	// reply, split, tag-lookahead, and capacity operation has succeeded.
	m.replays[ephemeral] = now + m.config.ReplayLifetime
	return RatchetResult{Payload: application, Reply: replyDst[:n], Peer: peer, NewSession: true}, nil
}

func (m *RatchetManager) receiveExistingLocked(dst, packet []byte, tag [ratchetTagLen]byte, entry tagEntry, now uint64) (RatchetResult, error) {
	// One-time removal happens before authentication. The sender cannot make a
	// malformed packet fall through to a New Session parse or retry this tag.
	delete(m.inbound, tag)
	defer clear(entry.key[:])
	entry.set.consumed++
	if entry.set.expires < now || entry.set.oldUntil != 0 && entry.set.oldUntil < now {
		return RatchetResult{}, ErrRatchetExpired
	}
	if err := m.extendInboundLocked(entry.set); err != nil {
		return RatchetResult{}, err
	}

	if len(packet) < ratchetTagLen+cryptx.ChaChaTagSize || len(dst) < len(packet)-ratchetTagLen-cryptx.ChaChaTagSize {
		return RatchetResult{}, ErrRatchet
	}
	var nonce [cryptx.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(entry.n))
	plain, err := cryptx.OpenChaCha20Poly1305To(dst, entry.key[:], nonce[:], packet[ratchetTagLen:], packet[:ratchetTagLen])
	if err != nil {
		return RatchetResult{}, ErrRatchet
	}
	result, err := m.parseExistingLocked(entry, plain, now)
	if err != nil {
		clear(plain)
		return RatchetResult{}, err
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
			out.ACKRequests = append(out.ACKRequests, ACK{entry.set.id, entry.n})
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
	flags, keyID := data[0], binary.BigEndian.Uint16(data[1:3])
	if flags&^byte(7) != 0 || keyID > 32767 || (flags&1 == 0 && len(data) != 3) || (flags&1 != 0 && len(data) != 35) {
		return ErrRatchet
	}
	s := sessionForSet(current, m.sessions)
	if s == nil {
		return ErrRatchet
	}
	if flags&1 == 0 {
		return nil
	} // acknowledgement of a retained key
	remote, err := ecdh.X25519().NewPublicKey(data[3:])
	if err != nil {
		return ErrRatchet
	}
	if flags&2 != 0 { // reverse key completes a locally initiated exchange
		if s.haveRemoteReverse && keyID <= s.remoteReverseKeyID {
			return ErrRatchet
		}
		if s.localKey == nil || !s.pendingDH || s.replyDH || keyID != s.pendingKeyID {
			return ErrRatchet
		}
		shared, err := s.localKey.ECDH(remote)
		if err != nil {
			return ErrRatchet
		}
		defer clear(shared)
		nextOutbound, _, err := m.prepareRatchetDirectionLocked(s, true, shared, now)
		if err != nil {
			s.terminated = true
			return err
		}
		nextInbound, entries, err := m.prepareRatchetDirectionLocked(s, false, shared, now)
		if err != nil {
			releaseTagSet(nextOutbound)
			s.terminated = true
			return err
		}
		m.commitRatchetDirectionLocked(s, true, nextOutbound, nil, now)
		m.commitRatchetDirectionLocked(s, false, nextInbound, entries, now)
		clearTagEntries(entries)
		s.remoteReverseKeyID, s.haveRemoteReverse = keyID, true
		s.pendingDH, s.localKey, s.pendingKeyID = false, nil, 0
		if s.terminateAfterDH || keyID == 32767 {
			s.terminated = true
		}
		return nil
	}
	// A forward key begins an exchange. Its ID is monotonic independently of
	// our locally initiated direction. Previous inbound tagsets remain usable
	// briefly, so this check is required even though each individual tag is
	// one-time.
	if s.haveRemoteForward && keyID <= s.remoteForwardKeyID {
		// Until our reverse key is sent, the initiator may repeat its forward
		// key on another authenticated old-tag-set packet. Treat the exact key
		// generation as an idempotent retransmission; once the reply commits,
		// old-tag-set repeats remain invalid.
		if keyID == s.remoteForwardKeyID && s.pendingDH && s.replyDH {
			return nil
		}
		return ErrRatchet
	}
	if s.pendingDH {
		return ErrRatchet
	}
	local, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return err
	}
	shared, err := local.ECDH(remote)
	if err != nil {
		return ErrRatchet
	}
	defer clear(shared)
	nextInbound, entries, err := m.prepareRatchetDirectionLocked(s, false, shared, now)
	if err != nil {
		s.terminated = true
		return err
	}
	m.commitRatchetDirectionLocked(s, false, nextInbound, entries, now)
	clearTagEntries(entries)
	copy(s.dhSecret[:], shared)
	s.remoteForwardKeyID, s.haveRemoteForward = keyID, true
	s.localKey, s.pendingKeyID, s.pendingDH, s.replyDH = local, keyID, true, true
	s.terminateAfterDH = keyID == 32767
	return nil
}

// prepareRatchetDirectionLocked derives a replacement tagset without changing
// the live session. Inbound lookahead and collision checks are completed before
// either half of a DH exchange is committed, so bounded-capacity failure cannot
// leave only one direction advanced.
func (m *RatchetManager) prepareRatchetDirectionLocked(s *session, outbound bool, shared []byte, now uint64) (*tagSet, []tagEntry, error) {
	old := s.inbound
	if outbound {
		old = s.outbound
	}
	if old == nil || old.id == 65535 {
		return nil, nil, ErrRatchetTagExhausted
	}
	material := hkdf64(old.nextRoot[:], shared, "XDHRatchetTagSet")
	defer clear(material[:])
	next, err := newTagSet(old.id+1, old.nextRoot, material[:32], now+m.config.SessionLifetime)
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
	s.inbound = next
	for _, entry := range entries {
		m.inbound[entry.tag] = entry
	}
}

func clearTagEntries(entries []tagEntry) {
	for index := range entries {
		clear(entries[index].key[:])
	}
}

func (m *RatchetManager) sessionFromCiphers(peer ivnp.Hash, root [32]byte, send, recv *cryptx.ChaCha20Poly1305, now uint64) (*session, error) {
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
	s := &session{peer: peer, outbound: out, inbound: in, expires: now + m.config.SessionLifetime}
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
		m.inbound[entry.tag] = entry
	}
	return nil
}

func (m *RatchetManager) extendInboundLocked(set *tagSet) error {
	for set.next-set.consumed < uint32(m.config.TagLookahead) {
		if len(m.inbound) >= m.config.MaxInboundTags {
			return ErrRatchetTagExhausted
		}
		entry, err := set.nextEntry()
		if err != nil {
			return err
		}
		m.inbound[entry.tag] = entry
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
			delete(m.pending, tag)
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
	var expired map[*tagSet]struct{}
	for tag, entry := range m.inbound {
		if entry.set.owner == s && (entry.set.expires < now || entry.set.oldUntil != 0 && entry.set.oldUntil < now) {
			clear(entry.key[:])
			delete(m.inbound, tag)
			if entry.set != s.inbound {
				if expired == nil {
					expired = make(map[*tagSet]struct{})
				}
				expired[entry.set] = struct{}{}
			}
		}
	}
	for set := range expired {
		releaseTagSet(set)
	}
}
func (m *RatchetManager) removeSessionTagsLocked(s *session) {
	for tag, entry := range m.inbound {
		if entry.set.owner == s {
			clear(entry.key[:])
			delete(m.inbound, tag)
		}
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

func (m *RatchetManager) discardSessionLocked(peer ivnp.Hash, s *session) {
	if s == nil {
		return
	}
	m.removeSessionTagsLocked(s)
	delete(m.sessions, peer)
	releaseSession(s)
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
		delete(m.pending, tag)
	}
	for tag, entry := range m.inbound {
		clear(entry.key[:])
		releaseTagSet(entry.set)

		delete(m.inbound, tag)
	}
	for peer, s := range m.sessions {
		releaseSession(s)
		delete(m.sessions, peer)
	}
	clear(m.private[:])
	m.closed = true
}
func (m *RatchetManager) Close() error { m.ReleaseSensitive(); return nil }

func releaseSession(s *session) {
	if s == nil {
		return
	}
	releaseTagSet(s.outbound)
	releaseTagSet(s.inbound)
	clear(s.dhSecret[:])
	s.localKey = nil
	s.localKeyID = 0
	s.pendingKeyID = 0
	s.remoteForwardKeyID = 0
	s.remoteReverseKeyID = 0
	s.haveRemoteForward = false
	s.haveRemoteReverse = false
	s.pendingDH = false
	s.replyDH = false
	s.terminateAfterDH = false
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
	if s == nil || s.next > 65535 {
		return tagEntry{}, ErrRatchetTagExhausted
	}
	tagData := hkdf64(s.tagChain[:], s.tagConst[:], "SessionTagKeyGen")
	keyData := hkdf64(s.keyChain[:], nil, "SymmetricRatchet")
	defer clear(tagData[:])
	defer clear(keyData[:])
	var entry tagEntry
	entry.set, entry.n = s, uint16(s.next)
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
func sessionForSet(set *tagSet, _ map[ivnp.Hash]*session) *session {
	if set == nil {
		return nil
	}
	return set.owner
}
func sessionPeer(set *tagSet, sessions map[ivnp.Hash]*session) ivnp.Hash {
	if s := sessionForSet(set, sessions); s != nil {
		return s.peer
	}
	return ivnp.Hash{}
}
