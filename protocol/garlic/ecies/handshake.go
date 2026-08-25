package ecies

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"io"

	"gosuda.org/ivnp/crypto/cryptx"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/network/transport/noise"
)

const (
	newSessionEphemeralLen = 32
	staticSectionLen       = 32 + 16
	replyTagLen            = 8
	replyKeySectionLen     = 16
	minNewSessionPayload   = 7 // DateTime block header and timestamp
)

var (
	ErrHandshake       = errors.New("garlic/ecies: invalid ECIES handshake")
	ErrHandshakeClosed = errors.New("garlic/ecies: handshake already consumed")
)

// Initiator is a one-use ECIES IK or IKhfs new-session state. It deliberately
// contains no shared registry; a destination-scoped session manager owns one
// instance per concurrent handshake.
type Initiator struct {
	state        *noise.SymmetricState
	static       *ecdh.PrivateKey
	remoteStatic *ecdh.PublicKey
	ephemeral    *ecdh.PrivateKey
	ephemeralEnc [32]byte
	hybrid       *HybridInitiator
	bound        bool
	created      bool
	closed       bool
	splitRoot    [32]byte
	splitSend    *cryptx.ChaCha20Poly1305
	splitReceive *cryptx.ChaCha20Poly1305
	splitReady   bool
}

// Responder is the one-use peer state retained between a valid New Session and
// the corresponding New Session Reply.
type Responder struct {
	state          *noise.SymmetricState
	static         *ecdh.PrivateKey
	aliceEphemeral *ecdh.PublicKey
	aliceStatic    *ecdh.PublicKey
	hybrid         *HybridResponder
	bound          bool
	parsed         bool
	closed         bool
	splitRoot      [32]byte
	splitSend      *cryptx.ChaCha20Poly1305
	splitReceive   *cryptx.ChaCha20Poly1305
	splitReady     bool
}

// ReleaseSensitive discards all IVNP-owned ECIES handshake state.
func (h *Initiator) ReleaseSensitive() {
	if h == nil || h.closed {
		return
	}
	if h.state != nil {
		h.state.ReleaseSensitive()
		h.state = nil
	}
	if h.splitSend != nil {
		h.splitSend.ReleaseSensitive()
	}
	if h.splitReceive != nil {
		h.splitReceive.ReleaseSensitive()
	}
	if h.hybrid != nil {
		h.hybrid.ReleaseSensitive()
		h.hybrid = nil
	}
	clear(h.ephemeralEnc[:])
	clear(h.splitRoot[:])
	h.static, h.remoteStatic, h.ephemeral, h.splitSend, h.splitReceive = nil, nil, nil, nil, nil
	h.closed = true
}

// ReleaseSensitive discards all IVNP-owned ECIES handshake state.
func (h *Responder) ReleaseSensitive() {
	if h == nil || h.closed {
		return
	}
	if h.state != nil {
		h.state.ReleaseSensitive()
		h.state = nil
	}
	if h.splitSend != nil {
		h.splitSend.ReleaseSensitive()
	}
	if h.splitReceive != nil {
		h.splitReceive.ReleaseSensitive()
	}
	if h.hybrid != nil {
		h.hybrid.ReleaseSensitive()
		h.hybrid = nil
	}
	clear(h.splitRoot[:])
	h.static, h.aliceEphemeral, h.aliceStatic, h.splitSend, h.splitReceive = nil, nil, nil, nil, nil
	h.closed = true
}

// NewInitiator prepares a bound IK session when bound is true, otherwise the
// unbound N-style variation. cryptoType is X25519 (4) or a registered hybrid
// LeaseSet2 type (6/7).
func NewInitiator(staticPrivate, remoteStatic []byte, cryptoType uint16, bound bool) (*Initiator, error) {
	return newInitiator(staticPrivate, remoteStatic, cryptoType, bound, nil)
}

func newInitiator(staticPrivate, remoteStatic []byte, cryptoType uint16, bound bool, random io.Reader) (*Initiator, error) {
	curve := ecdh.X25519()
	static, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, err
	}
	remote, err := curve.NewPublicKey(remoteStatic)
	if err != nil {
		return nil, err
	}
	state, hybrid, err := initializeInitiatorState(cryptoType)
	if err != nil {
		return nil, err
	}
	handshake := &Initiator{state: state, static: static, remoteStatic: remote, hybrid: hybrid, bound: bound}
	keep := false
	defer func() {
		if !keep {
			handshake.ReleaseSensitive()
		}
	}()
	// Java's IKelg2+hs2 engine mixes the raw responder static key here. The
	// hs2 name does not change this pre-message input in Java I2P.
	state.MixHash(remote.Bytes())
	ephemeral, encoded, err := cryptx.GenerateElligator2X25519(random)
	if err != nil {
		return nil, err
	}
	handshake.ephemeral, handshake.ephemeralEnc = ephemeral, encoded
	keep = true
	return handshake, nil
}

// NewResponder prepares a local ECIES receive context. The received New
// Session determines whether it is bound; callers should discard this value on
// any ParseNewSession error rather than retry it with attacker-controlled data.
func NewResponder(staticPrivate []byte, cryptoType uint16) (*Responder, error) {
	curve := ecdh.X25519()
	static, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, err
	}
	state, hybrid, err := initializeResponderState(cryptoType)
	if err != nil {
		return nil, err
	}
	state.MixHash(static.PublicKey().Bytes())
	return &Responder{state: state, static: static, hybrid: hybrid}, nil
}

// CreateNewSession writes an NS message: encoded Alice ephemeral, optional
// encrypted e1, encrypted binding/static section, then encrypted payload.
// payload must begin with a valid ECIES DateTime block; this layer enforces the
// minimum structural size while block-level validation remains its caller's job.
func (h *Initiator) CreateNewSession(dst, payload []byte) (int, error) {
	if h == nil || h.closed || h.created {
		return 0, ErrHandshakeClosed
	}
	if len(payload) < minNewSessionPayload {
		return 0, ErrHandshake
	}
	hybridLen := 0
	if h.hybrid != nil {
		hybridLen = h.hybrid.params.PublicKeySize + 16
	}
	total := newSessionEphemeralLen + hybridLen + staticSectionLen + len(payload) + 16
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	copy(dst[:newSessionEphemeralLen], h.ephemeralEnc[:])
	h.state.MixHash(h.ephemeral.PublicKey().Bytes())
	if err := mixDH(h.state, h.ephemeral, h.remoteStatic); err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	off := newSessionEphemeralLen
	if h.hybrid != nil {
		section, err := h.hybrid.EncryptE1(h.state, dst[off:off+hybridLen])
		if err != nil || len(section) != hybridLen {
			h.ReleaseSensitive()
			return 0, handshakeError(err)
		}
		off += hybridLen
	}
	var binding [32]byte
	if h.bound {
		copy(binding[:], h.static.PublicKey().Bytes())
	}
	section, err := h.state.EncryptAndHash(dst[off:off+staticSectionLen], binding[:])
	if err != nil || len(section) != staticSectionLen {
		h.ReleaseSensitive()
		return 0, handshakeError(err)
	}
	off += staticSectionLen
	if h.bound {
		if err = mixDH(h.state, h.static, h.remoteStatic); err != nil {
			h.ReleaseSensitive()
			return 0, err
		}
	}
	section, err = h.state.EncryptAndHash(dst[off:total], payload)
	if err != nil || len(section) != len(payload)+16 {
		h.ReleaseSensitive()
		return 0, handshakeError(err)
	}
	h.created = true
	return total, nil
}

// ReplyTag returns the first destination-scoped NSR dispatch tag for this
// created New Session. It is derived from the authenticated handshake chain,
// never chosen by the caller or sent in the New Session.
func (h *Initiator) ReplyTag() ([replyTagLen]byte, error) {
	if h == nil || h.closed || !h.created || h.state == nil {
		return [replyTagLen]byte{}, ErrHandshakeClosed
	}
	return deriveReplyTag(h.state.ChainingKey()), nil
}

// ParseNewSession authenticates an NS message and returns its plaintext
// payload. payloadDst remains caller-owned and the returned view aliases it.
func (h *Responder) ParseNewSession(src, payloadDst []byte) ([]byte, error) {
	if h == nil || h.closed || h.parsed || len(src) < newSessionEphemeralLen+staticSectionLen+16+minNewSessionPayload {
		return nil, ErrHandshake
	}
	curve := ecdh.X25519()
	var decoded [32]byte
	if err := cryptx.DecodeElligator2(decoded[:], src[:newSessionEphemeralLen]); err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	aliceEphemeral, err := curve.NewPublicKey(decoded[:])
	if err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	h.aliceEphemeral = aliceEphemeral
	h.state.MixHash(aliceEphemeral.Bytes())
	if err = mixDH(h.state, h.static, aliceEphemeral); err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	off := newSessionEphemeralLen
	if h.hybrid != nil {
		hybridLen := h.hybrid.params.PublicKeySize + 16
		if len(src)-off < hybridLen+staticSectionLen+16+minNewSessionPayload {
			h.ReleaseSensitive()
			return nil, ErrHandshake
		}
		if err = h.hybrid.ConsumeE1(h.state, make([]byte, h.hybrid.params.PublicKeySize), src[off:off+hybridLen]); err != nil {
			h.ReleaseSensitive()
			return nil, handshakeError(err)
		}
		off += hybridLen
	}
	var binding [32]byte
	plain, err := h.state.DecryptAndHash(binding[:], src[off:off+staticSectionLen])
	if err != nil || len(plain) != len(binding) {
		h.ReleaseSensitive()
		return nil, handshakeError(err)
	}
	off += staticSectionLen
	if !bytes.Equal(binding[:], make([]byte, len(binding))) {
		h.aliceStatic, err = curve.NewPublicKey(binding[:])
		if err != nil {
			h.ReleaseSensitive()
			return nil, err
		}
		h.bound = true
		if err = mixDH(h.state, h.static, h.aliceStatic); err != nil {
			h.ReleaseSensitive()
			return nil, err
		}
	}
	if len(src)-off < 16 || len(payloadDst) < len(src)-off-16 {
		h.ReleaseSensitive()
		return nil, wire.ErrShortBuffer
	}
	payload, err := h.state.DecryptAndHash(payloadDst, src[off:])
	if err != nil || len(payload) < minNewSessionPayload {
		h.ReleaseSensitive()
		return nil, handshakeError(err)
	}
	h.parsed = true
	return payload, nil
}

// ReplyTag returns the first destination-scoped NSR dispatch tag for this
// parsed New Session. It is available only after authentication succeeds.
func (h *Responder) ReplyTag() ([replyTagLen]byte, error) {
	if h == nil || h.closed || !h.parsed || h.state == nil {
		return [replyTagLen]byte{}, ErrHandshakeClosed
	}
	return deriveReplyTag(h.state.ChainingKey()), nil
}

// CreateReply writes an NSR message for a successfully parsed bound session.
func (h *Responder) CreateReply(dst []byte, tag [replyTagLen]byte, payload []byte) (int, error) {
	if h == nil || h.closed || !h.parsed || !h.bound || h.aliceStatic == nil || h.aliceEphemeral == nil || h.splitReady {
		return 0, ErrHandshakeClosed
	}
	hybridLen := 0
	if h.hybrid != nil {
		hybridLen = h.hybrid.params.CiphertextSize + 16
	}
	total := replyTagLen + newSessionEphemeralLen + hybridLen + replyKeySectionLen + len(payload) + 16
	if len(dst) < total {
		return 0, wire.ErrShortBuffer
	}
	copy(dst[:replyTagLen], tag[:])
	h.state.MixHash(tag[:])
	ephemeral, encoded, err := cryptx.GenerateElligator2X25519(nil)
	if err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	off := replyTagLen
	copy(dst[off:off+newSessionEphemeralLen], encoded[:])
	off += newSessionEphemeralLen
	h.state.MixHash(ephemeral.PublicKey().Bytes())
	if err = mixDH(h.state, ephemeral, h.aliceEphemeral); err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	if h.hybrid != nil {
		section, hybridErr := h.hybrid.EncryptEKEM(h.state, dst[off:off+hybridLen])
		if hybridErr != nil || len(section) != hybridLen {
			h.ReleaseSensitive()
			return 0, handshakeError(hybridErr)
		}
		off += hybridLen
	}
	if err = mixDH(h.state, ephemeral, h.aliceStatic); err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	section, err := h.state.EncryptAndHash(dst[off:off+replyKeySectionLen], nil)
	if err != nil || len(section) != replyKeySectionLen {
		h.ReleaseSensitive()
		return 0, handshakeError(err)
	}
	off += replyKeySectionLen
	hash := h.state.Hash()
	h.splitRoot = h.state.ChainingKey()
	first, second, err := h.state.Split()
	h.state = nil
	if err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	h.splitReceive, h.splitSend, h.splitReady = first, second, true
	attachKey, err := deriveAttachPayloadKey(h.splitSend)
	if err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	defer clear(attachKey[:])
	var nonce [cryptx.ChaChaNonceSize]byte
	if _, err = cryptx.SealChaCha20Poly1305To(dst[off:total], attachKey[:], nonce[:], payload, hash[:]); err != nil {
		h.ReleaseSensitive()
		return 0, err
	}
	return total, nil
}

// ParseReply authenticates an NSR produced for this bound initiator and
// returns its plaintext payload. The returned view aliases payloadDst.
func (h *Initiator) ParseReply(src, payloadDst []byte) ([]byte, error) {
	if h == nil || h.closed || !h.created || !h.bound || h.splitReady || len(src) < replyTagLen+newSessionEphemeralLen+replyKeySectionLen+16 {
		return nil, ErrHandshake
	}
	tag := src[:replyTagLen]
	h.state.MixHash(tag)
	var decoded [32]byte
	if err := cryptx.DecodeElligator2(decoded[:], src[replyTagLen:replyTagLen+newSessionEphemeralLen]); err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	bobEphemeral, err := ecdh.X25519().NewPublicKey(decoded[:])
	if err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	h.state.MixHash(bobEphemeral.Bytes())
	if err = mixDH(h.state, h.ephemeral, bobEphemeral); err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	off := replyTagLen + newSessionEphemeralLen
	if h.hybrid != nil {
		hybridLen := h.hybrid.params.CiphertextSize + 16
		if len(src)-off < hybridLen+replyKeySectionLen+16 {
			h.ReleaseSensitive()
			return nil, ErrHandshake
		}
		if err = h.hybrid.ConsumeEKEM(h.state, make([]byte, h.hybrid.params.CiphertextSize), src[off:off+hybridLen]); err != nil {
			h.ReleaseSensitive()
			return nil, handshakeError(err)
		}
		off += hybridLen
	}
	if err = mixDH(h.state, h.static, bobEphemeral); err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	empty, err := h.state.DecryptAndHash(make([]byte, 0), src[off:off+replyKeySectionLen])
	if err != nil || len(empty) != 0 {
		h.ReleaseSensitive()
		return nil, handshakeError(err)
	}
	off += replyKeySectionLen
	if len(src)-off < 16 || len(payloadDst) < len(src)-off-16 {
		h.ReleaseSensitive()
		return nil, wire.ErrShortBuffer
	}
	hash := h.state.Hash()
	h.splitRoot = h.state.ChainingKey()
	first, second, err := h.state.Split()
	h.state = nil
	if err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	h.splitSend, h.splitReceive, h.splitReady = first, second, true
	attachKey, err := deriveAttachPayloadKey(h.splitReceive)
	if err != nil {
		h.ReleaseSensitive()
		return nil, err
	}
	defer clear(attachKey[:])
	var nonce [cryptx.ChaChaNonceSize]byte
	payload, err := cryptx.OpenChaCha20Poly1305To(payloadDst, attachKey[:], nonce[:], src[off:], hash[:])
	if err != nil {
		h.ReleaseSensitive()
		return nil, handshakeError(err)
	}
	return payload, nil
}

// Split consumes a completed initiator handshake and returns the directional
// data-phase ciphers in send, receive order.
func (h *Initiator) Split() (send, receive *cryptx.ChaCha20Poly1305, err error) {
	_, send, receive, err = h.SplitWithRoot()
	return send, receive, err
}

// SplitWithRoot additionally returns the post-handshake chaining key required
// as the root key for both initial ratchet tag sets.
func (h *Initiator) SplitWithRoot() (root [32]byte, send, receive *cryptx.ChaCha20Poly1305, err error) {
	if h == nil || h.closed || !h.splitReady || h.splitSend == nil || h.splitReceive == nil {
		return root, nil, nil, ErrHandshakeClosed
	}
	root, send, receive = h.splitRoot, h.splitSend, h.splitReceive
	clear(h.splitRoot[:])
	h.splitSend, h.splitReceive, h.splitReady = nil, nil, false
	h.static, h.remoteStatic, h.ephemeral = nil, nil, nil
	clear(h.ephemeralEnc[:])
	h.closed = true
	return root, send, receive, nil
}

// Split consumes a successfully parsed responder handshake and returns its
// directional data-phase ciphers in send, receive order.
func (h *Responder) Split() (send, receive *cryptx.ChaCha20Poly1305, err error) {
	_, send, receive, err = h.SplitWithRoot()
	return send, receive, err
}

// SplitWithRoot returns the same post-handshake chaining key as the initiator.
// Noise Split is initiator ordered, so responder cipher ownership is reversed.
func (h *Responder) SplitWithRoot() (root [32]byte, send, receive *cryptx.ChaCha20Poly1305, err error) {
	if h == nil || h.closed || !h.splitReady || h.splitSend == nil || h.splitReceive == nil {
		return root, nil, nil, ErrHandshakeClosed
	}
	root, send, receive = h.splitRoot, h.splitSend, h.splitReceive
	clear(h.splitRoot[:])
	h.splitSend, h.splitReceive, h.splitReady = nil, nil, false
	h.static, h.aliceEphemeral, h.aliceStatic = nil, nil, nil
	h.closed = true
	return root, send, receive, nil
}

func deriveAttachPayloadKey(cipher *cryptx.ChaCha20Poly1305) ([32]byte, error) {
	var key [32]byte
	if cipher == nil {
		return key, ErrHandshake
	}
	var split [32]byte
	if err := cipher.CopyKey(split[:]); err != nil {
		return key, err
	}
	defer clear(split[:])
	material := hkdf64(split[:], nil, "AttachPayloadKDF")
	defer clear(material[:])
	copy(key[:], material[:32])
	return key, nil
}

func initializeInitiatorState(cryptoType uint16) (*noise.SymmetricState, *HybridInitiator, error) {
	name, err := protocolName(cryptoType)
	if err != nil {
		return nil, nil, err
	}
	state := noise.Initialize(name)
	if err := state.MixHash(nil); err != nil {
		state.ReleaseSensitive()
		return nil, nil, err
	}
	if cryptoType == 4 {
		return state, nil, nil
	}
	hybrid, err := NewHybridInitiator(cryptoType)
	if err != nil {
		state.ReleaseSensitive()
	}
	return state, hybrid, err
}

func initializeResponderState(cryptoType uint16) (*noise.SymmetricState, *HybridResponder, error) {
	name, err := protocolName(cryptoType)
	if err != nil {
		return nil, nil, err
	}
	state := noise.Initialize(name)
	if err := state.MixHash(nil); err != nil {
		state.ReleaseSensitive()
		return nil, nil, err
	}
	if cryptoType == 4 {
		return state, nil, nil
	}
	hybrid, err := NewHybridResponder(cryptoType)
	if err != nil {
		state.ReleaseSensitive()
	}
	return state, hybrid, err
}

func protocolName(cryptoType uint16) (string, error) {
	if cryptoType == 4 {
		return "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256", nil
	}
	params, known := cryptx.Parameters(cryptoType)
	if !known {
		return "", ErrHandshake
	}
	return params.NoiseIdentifier, nil
}

func mixDH(state *noise.SymmetricState, private *ecdh.PrivateKey, public *ecdh.PublicKey) error {
	secret, err := private.ECDH(public)
	if err != nil {
		return err
	}
	defer clear(secret)
	return state.MixKey(secret)
}

func handshakeError(err error) error {
	if err == nil {
		return ErrHandshake
	}
	return err
}
