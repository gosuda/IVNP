package ntcp2

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/transport/noise"
)

const (
	HandshakeProtocol              = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
	SessionRequestCiphertextLen    = 64
	MaxSessionRequestLen           = 65535
	LegacyNTCPMaxSessionRequestLen = 287
)

var (
	ErrHandshake = errors.New("ntcp2: invalid handshake message")
	ErrNetwork   = errors.New("ntcp2: incompatible network or version")
)

// SessionRequestOptions is the 16-byte NTCP2 message-one option block.
type SessionRequestOptions struct {
	NetworkID           uint8
	Version             uint8
	PaddingLength       uint16
	Message3Part2Length uint16
	Timestamp           uint32
}

func (o SessionRequestOptions) marshalTo(dst []byte) {
	dst[0], dst[1] = o.NetworkID, o.Version
	binary.BigEndian.PutUint16(dst[2:4], o.PaddingLength)
	binary.BigEndian.PutUint16(dst[4:6], o.Message3Part2Length)
	clear(dst[6:8])
	binary.BigEndian.PutUint32(dst[8:12], o.Timestamp)
	clear(dst[12:16])
}

func parseSessionRequestOptions(src []byte, expectedNetwork uint8) (SessionRequestOptions, error) {
	if len(src) != 16 {
		return SessionRequestOptions{}, ErrHandshake
	}
	options := SessionRequestOptions{NetworkID: src[0], Version: src[1], PaddingLength: binary.BigEndian.Uint16(src[2:4]), Message3Part2Length: binary.BigEndian.Uint16(src[4:6]), Timestamp: binary.BigEndian.Uint32(src[8:12])}
	parseSessionRequestOptionsRejected := options.NetworkID != expectedNetwork || options.Version != 2 || src[6] != 0 || src[7] != 0 || src[12] != 0 || src[13] != 0 || src[14] != 0
	if !parseSessionRequestOptionsRejected {
		parseSessionRequestOptionsRejected = src[15] != 0
	}
	if parseSessionRequestOptionsRejected {
		return SessionRequestOptions{}, ErrNetwork
	}
	return options, nil
}

type SessionCreatedOptions struct {
	PaddingLength uint16
	Timestamp     uint32
}

func (o SessionCreatedOptions) marshalTo(dst []byte) {
	clear(dst)
	binary.BigEndian.PutUint16(dst[2:4], o.PaddingLength)
	binary.BigEndian.PutUint32(dst[8:12], o.Timestamp)
}

func parseSessionCreatedOptions(src []byte) (SessionCreatedOptions, error) {
	parseSessionCreatedOptionsRejected := len(src) != 16 || src[0] != 0 || src[1] != 0 || src[4] != 0 || src[5] != 0 || src[6] != 0 || src[7] != 0 || src[12] != 0 || src[13] != 0 || src[14] != 0
	if !parseSessionCreatedOptionsRejected {
		parseSessionCreatedOptionsRejected = src[15] != 0
	}
	if parseSessionCreatedOptionsRejected {
		return SessionCreatedOptions{}, ErrHandshake
	}
	return SessionCreatedOptions{PaddingLength: binary.BigEndian.Uint16(src[2:4]), Timestamp: binary.BigEndian.Uint32(src[8:12])}, nil
}

// Initiator holds the Noise state between SessionRequest and SessionCreated.
type Initiator struct {
	state               *noise.SymmetricState
	ephemeral           *ecdh.PrivateKey
	peerEphemeral       *ecdh.PublicKey
	message3Part2Length uint16
	aesState            [aes.BlockSize]byte
	completed           bool
	dataSessionTaken    bool
}

// ReleaseSensitive abandons an unpromoted handshake and overwrites its
// IVNP-owned Noise and obfuscation state.
func (i *Initiator) ReleaseSensitive() {
	if i != nil {
		i.clearHandshake()
	}
}

// NewInitiator initializes the NTCP2 Noise XK transcript for Bob's published
// X25519 static key. remoteHash and remoteIV are the RouterInfo NTCP2 i/s
// values used only for public AES obfuscation of message one.
func NewInitiator(remoteStatic []byte) (*Initiator, error) {
	curve := ecdh.X25519()
	static, err := curve.NewPublicKey(remoteStatic)
	if err != nil {
		return nil, err
	}
	state := noise.Initialize(HandshakeProtocol)
	keepState := false
	defer func() {
		if !keepState {
			state.ReleaseSensitive()
		}
	}()
	state.MixHash(nil)
	state.MixHash(static.Bytes())
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	state.MixHash(ephemeral.PublicKey().Bytes())
	shared, err := ephemeral.ECDH(static)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, err
	}
	keepState = true
	return &Initiator{state: state, ephemeral: ephemeral}, nil
}

// BuildSessionRequest writes exactly one complete SessionRequest. padding is
// caller-generated randomness; its exact length is authenticated in options.
func (i *Initiator) BuildSessionRequest(dst, remoteHash, remoteIV, padding []byte, options SessionRequestOptions, legacyNTCPPort bool) ([]byte, error) {
	buildSessionRequestRejected := i == nil || i.state == nil || i.ephemeral == nil || len(remoteHash) != 32 || len(remoteIV) != aes.BlockSize
	if !buildSessionRequestRejected {
		buildSessionRequestRejected = len(padding) > MaxSessionRequestLen-SessionRequestCiphertextLen
	}
	if buildSessionRequestRejected {
		return nil, ErrHandshake
	}
	if int(options.PaddingLength) != len(padding) {
		return nil, ErrHandshake
	}
	total := SessionRequestCiphertextLen + len(padding)
	if legacyNTCPPort && total > LegacyNTCPMaxSessionRequestLen || total > MaxSessionRequestLen {
		return nil, ErrHandshake
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	if err := aesCBCEncrypt(dst[:32], i.ephemeral.PublicKey().Bytes(), remoteHash, remoteIV); err != nil {
		return nil, err
	}
	var encodedOptions [16]byte
	options.marshalTo(encodedOptions[:])
	ciphertext, err := i.state.EncryptAndHash(dst[32:64], encodedOptions[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != 32 {
		return nil, ErrHandshake
	}
	copy(dst[64:total], padding)
	copy(i.aesState[:], dst[16:32])
	i.message3Part2Length = options.Message3Part2Length
	i.state.MixHash(padding)
	return dst[:total], nil
}

// Responder holds the transcript after a validated SessionRequest and the
// state needed to authenticate SessionConfirmed.
type Responder struct {
	state               *noise.SymmetricState
	peerEphemeral       *ecdh.PublicKey
	ephemeral           *ecdh.PrivateKey
	message3Part2Length uint16
	aesState            [aes.BlockSize]byte
	completed           bool
	dataSessionTaken    bool
}

// ReleaseSensitive abandons an unpromoted handshake and overwrites its
// IVNP-owned Noise and obfuscation state.
func (r *Responder) ReleaseSensitive() {
	if r != nil {
		r.clearHandshake()
	}
}

// ParseSessionRequest validates one complete buffered SessionRequest and
// returns the state for message two. staticPrivate is Bob's X25519 static
// private key published as rs.
func ParseSessionRequest(src, staticPrivate, remoteHash, remoteIV []byte, expectedNetwork uint8, legacyNTCPPort bool) (*Responder, SessionRequestOptions, error) {
	parseSessionRequestRejected := len(src) < SessionRequestCiphertextLen || len(src) > MaxSessionRequestLen
	if !parseSessionRequestRejected {
		parseSessionRequestRejected = legacyNTCPPort && len(src) > LegacyNTCPMaxSessionRequestLen
	}
	if parseSessionRequestRejected {
		return nil, SessionRequestOptions{}, ErrHandshake
	}
	responder, options, err := parseSessionRequestHeader(src[:SessionRequestCiphertextLen], staticPrivate, remoteHash, remoteIV, expectedNetwork)
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	if err = finishSessionRequest(responder, src[SessionRequestCiphertextLen:], options, legacyNTCPPort); err != nil {
		responder.ReleaseSensitive()
		return nil, SessionRequestOptions{}, err
	}
	return responder, options, nil
}

// ReadSessionRequest reads exactly one SessionRequest from reader without
// consuming data from the following SessionConfirmed message.
func ReadSessionRequest(reader io.Reader, staticPrivate, remoteHash, remoteIV []byte, expectedNetwork uint8, legacyNTCPPort bool) (*Responder, SessionRequestOptions, error) {
	var header [SessionRequestCiphertextLen]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, SessionRequestOptions{}, err
	}
	responder, options, err := parseSessionRequestHeader(header[:], staticPrivate, remoteHash, remoteIV, expectedNetwork)
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	padding := make([]byte, options.PaddingLength)
	if _, err = io.ReadFull(reader, padding); err != nil {
		responder.ReleaseSensitive()
		return nil, SessionRequestOptions{}, err
	}
	if err = finishSessionRequest(responder, padding, options, legacyNTCPPort); err != nil {
		responder.ReleaseSensitive()
		return nil, SessionRequestOptions{}, err
	}
	return responder, options, nil
}

func parseSessionRequestHeader(src, staticPrivate, remoteHash, remoteIV []byte, expectedNetwork uint8) (*Responder, SessionRequestOptions, error) {
	if len(src) != SessionRequestCiphertextLen || len(remoteHash) != 32 || len(remoteIV) != aes.BlockSize {
		return nil, SessionRequestOptions{}, ErrHandshake
	}
	curve := ecdh.X25519()
	private, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	var peerBytes [32]byte
	if err = aesCBCDecrypt(peerBytes[:], src[:32], remoteHash, remoteIV); err != nil {
		return nil, SessionRequestOptions{}, err
	}
	peer, err := curve.NewPublicKey(peerBytes[:])
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	state := noise.Initialize(HandshakeProtocol)
	keepState := false
	defer func() {
		if !keepState {
			state.ReleaseSensitive()
		}
	}()
	state.MixHash(nil)
	state.MixHash(private.PublicKey().Bytes())
	state.MixHash(peer.Bytes())
	shared, err := private.ECDH(peer)
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, SessionRequestOptions{}, err
	}
	var plainOptions [16]byte
	plain, err := state.DecryptAndHash(plainOptions[:], src[32:64])
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	options, err := parseSessionRequestOptions(plain, expectedNetwork)
	if err != nil {
		return nil, SessionRequestOptions{}, err
	}
	responder := &Responder{state: state, peerEphemeral: peer, message3Part2Length: options.Message3Part2Length}
	copy(responder.aesState[:], src[16:32])
	keepState = true
	return responder, options, nil
}

func finishSessionRequest(responder *Responder, padding []byte, options SessionRequestOptions, legacyNTCPPort bool) error {
	total := SessionRequestCiphertextLen + len(padding)
	finishSessionRequestRejected := len(padding) != int(options.PaddingLength) || total > MaxSessionRequestLen
	if !finishSessionRequestRejected {
		finishSessionRequestRejected = legacyNTCPPort && total > LegacyNTCPMaxSessionRequestLen
	}
	if finishSessionRequestRejected {
		return ErrHandshake
	}
	responder.state.MixHash(padding)
	return nil
}

// BuildSessionCreated writes Bob's complete message-two response.
func (r *Responder) BuildSessionCreated(dst, remoteHash, padding []byte, options SessionCreatedOptions) ([]byte, error) {
	buildSessionCreatedRejected := r == nil || r.state == nil || r.peerEphemeral == nil || len(remoteHash) != 32 || int(options.PaddingLength) != len(padding) || len(padding) > MaxSessionRequestLen-SessionRequestCiphertextLen
	if !buildSessionCreatedRejected {
		buildSessionCreatedRejected = len(dst) < SessionRequestCiphertextLen+len(padding)
	}
	if buildSessionCreatedRejected {
		return nil, ErrHandshake
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.state.MixHash(ephemeral.PublicKey().Bytes())
	shared, err := ephemeral.ECDH(r.peerEphemeral)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = r.state.MixKey(shared); err != nil {
		return nil, err
	}
	total := SessionRequestCiphertextLen + len(padding)
	if err = aesCBCEncrypt(dst[:32], ephemeral.PublicKey().Bytes(), remoteHash, r.aesState[:]); err != nil {
		return nil, err
	}
	var encoded [16]byte
	options.marshalTo(encoded[:])
	if _, err = r.state.EncryptAndHash(dst[32:64], encoded[:]); err != nil {
		return nil, err
	}
	copy(dst[64:total], padding)
	r.state.MixHash(padding)
	r.ephemeral = ephemeral
	return dst[:total], nil
}

// ParseSessionCreated advances Alice's state through one complete buffered
// SessionCreated message.
func (i *Initiator) ParseSessionCreated(src, remoteHash []byte) (SessionCreatedOptions, error) {
	if i == nil || i.state == nil || i.ephemeral == nil || len(src) < SessionRequestCiphertextLen || len(src) > MaxSessionRequestLen {
		return SessionCreatedOptions{}, ErrHandshake
	}
	options, err := i.parseSessionCreatedHeader(src[:SessionRequestCiphertextLen], remoteHash)
	if err != nil {
		return SessionCreatedOptions{}, err
	}
	if err = i.finishSessionCreated(src[SessionRequestCiphertextLen:], options); err != nil {
		return SessionCreatedOptions{}, err
	}
	return options, nil
}

// ReadSessionCreated reads exactly one SessionCreated from reader without
// consuming data from the following SessionConfirmed message.
func (i *Initiator) ReadSessionCreated(reader io.Reader, remoteHash []byte) (SessionCreatedOptions, error) {
	if i == nil || i.state == nil || i.ephemeral == nil {
		return SessionCreatedOptions{}, ErrHandshake
	}
	var header [SessionRequestCiphertextLen]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return SessionCreatedOptions{}, err
	}
	options, err := i.parseSessionCreatedHeader(header[:], remoteHash)
	if err != nil {
		return SessionCreatedOptions{}, err
	}
	padding := make([]byte, options.PaddingLength)
	if _, err = io.ReadFull(reader, padding); err != nil {
		return SessionCreatedOptions{}, err
	}
	if err = i.finishSessionCreated(padding, options); err != nil {
		return SessionCreatedOptions{}, err
	}
	return options, nil
}

func (i *Initiator) parseSessionCreatedHeader(src, remoteHash []byte) (SessionCreatedOptions, error) {
	if i == nil || i.state == nil || i.ephemeral == nil || len(src) != SessionRequestCiphertextLen || len(remoteHash) != 32 {
		return SessionCreatedOptions{}, ErrHandshake
	}
	var peerBytes [32]byte
	if err := aesCBCDecrypt(peerBytes[:], src[:32], remoteHash, i.aesState[:]); err != nil {
		return SessionCreatedOptions{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes[:])
	if err != nil {
		return SessionCreatedOptions{}, err
	}
	i.state.MixHash(peer.Bytes())
	shared, err := i.ephemeral.ECDH(peer)
	if err != nil {
		return SessionCreatedOptions{}, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return SessionCreatedOptions{}, err
	}
	var plain [16]byte
	if _, err = i.state.DecryptAndHash(plain[:], src[32:64]); err != nil {
		return SessionCreatedOptions{}, err
	}
	options, err := parseSessionCreatedOptions(plain[:])
	if err != nil {
		return SessionCreatedOptions{}, err
	}
	i.peerEphemeral = peer
	return options, nil
}

func (i *Initiator) finishSessionCreated(padding []byte, options SessionCreatedOptions) error {
	if len(padding) != int(options.PaddingLength) || SessionRequestCiphertextLen+len(padding) > MaxSessionRequestLen {
		return ErrHandshake
	}
	i.state.MixHash(padding)
	return nil
}

// BuildSessionConfirmed writes both SessionConfirmed AEAD frames. payload is
// the caller-built RouterInfo/options/padding block sequence advertised by
// Message3Part2Length in SessionRequest.
func (i *Initiator) BuildSessionConfirmed(dst, staticPrivate, payload []byte) ([]byte, error) {
	buildSessionConfirmedRejected := i == nil || i.state == nil || i.completed || i.peerEphemeral == nil || len(payload)+16 != int(i.message3Part2Length) || len(payload)+64 > MaxSessionRequestLen
	if !buildSessionConfirmedRejected {
		buildSessionConfirmedRejected = len(dst) < 64+len(payload)
	}
	if buildSessionConfirmedRejected {
		return nil, ErrHandshake
	}
	private, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, err
	}
	if _, err = i.state.EncryptAndHash(dst[:48], private.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	shared, err := private.ECDH(i.peerEphemeral)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return nil, err
	}
	if _, err = i.state.EncryptAndHash(dst[48:48+len(payload)+16], payload); err != nil {
		return nil, err
	}
	i.completed = true
	return dst[:64+len(payload)], nil
}

// ParseSessionConfirmed authenticates both Message3 frames and returns
// Alice's static X25519 key and RouterInfo/options/padding payload.
func (r *Responder) ParseSessionConfirmed(src []byte) ([]byte, []byte, error) {
	parseSessionConfirmedRejected := r == nil || r.state == nil || r.completed || r.ephemeral == nil || len(src) < 64 || len(src) > MaxSessionRequestLen
	if !parseSessionConfirmedRejected {
		parseSessionConfirmedRejected = len(src)-48 != int(r.message3Part2Length)
	}
	if parseSessionConfirmedRejected {
		return nil, nil, ErrHandshake
	}
	var static [32]byte
	if _, err := r.state.DecryptAndHash(static[:], src[:48]); err != nil {
		return nil, nil, err
	}
	peerStatic, err := ecdh.X25519().NewPublicKey(static[:])
	if err != nil {
		return nil, nil, err
	}
	shared, err := r.ephemeral.ECDH(peerStatic)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	if err = r.state.MixKey(shared); err != nil {
		return nil, nil, err
	}
	payload := make([]byte, len(src)-64)
	if _, err = r.state.DecryptAndHash(payload, src[48:]); err != nil {
		return nil, nil, err
	}
	r.completed = true
	return static[:], payload, nil
}

// NewDataSession derives NTCP2's post-handshake data-phase directions in
// Alice's transmit/receive order. It may be called exactly once, after a
// successful SessionConfirmed has been written. The transcript state and
// ephemeral keys are discarded once its session owns the derived ciphers.
func (i *Initiator) NewDataSession(conn net.Conn) (*Session, error) {
	if i == nil || i.state == nil || conn == nil || !i.completed || i.dataSessionTaken {
		return nil, ErrHandshake
	}
	session, err := newDataSession(conn, i.state, true)
	if err != nil {
		return nil, err
	}
	i.dataSessionTaken = true
	i.clearHandshake()
	return session, nil
}

// NewDataSession derives NTCP2's post-handshake data-phase directions in
// Bob's transmit/receive order. Callers must validate the authenticated peer
// RouterInfo and static key before promoting this session to the peer table.
func (r *Responder) NewDataSession(conn net.Conn) (*Session, error) {
	if r == nil || r.state == nil || conn == nil || !r.completed || r.dataSessionTaken {
		return nil, ErrHandshake
	}
	session, err := newDataSession(conn, r.state, false)
	if err != nil {
		return nil, err
	}
	r.dataSessionTaken = true
	r.clearHandshake()
	return session, nil
}

func (i *Initiator) clearHandshake() {
	if i.state != nil {
		i.state.ReleaseSensitive()
		i.state = nil
	}
	i.ephemeral = nil
	i.peerEphemeral = nil
	clear(i.aesState[:])
}

func (r *Responder) clearHandshake() {
	if r.state != nil {
		r.state.ReleaseSensitive()
		r.state = nil
	}
	r.ephemeral = nil
	r.peerEphemeral = nil
	clear(r.aesState[:])
}

func newDataSession(conn net.Conn, state *noise.SymmetricState, initiator bool) (*Session, error) {
	if state == nil {
		return nil, cryptography.ErrSensitiveReleased
	}
	chainingKey, handshakeHash := state.ChainingKey(), state.Hash()
	temp := hmac256(chainingKey[:], nil, nil, nil)
	kab := hmac256(temp[:], []byte{1}, nil, nil)
	kba := hmac256(temp[:], kab[:], []byte{2}, nil)
	askMaster := hmac256(temp[:], []byte("ask"), []byte{1}, nil)
	temp = hmac256(askMaster[:], handshakeHash[:], []byte("siphash"), nil)
	sipMaster := hmac256(temp[:], []byte{1}, nil, nil)
	temp = hmac256(sipMaster[:], nil, nil, nil)
	sipAB := hmac256(temp[:], []byte{1}, nil, nil)
	sipBA := hmac256(temp[:], sipAB[:], []byte{2}, nil)
	defer clear(chainingKey[:])
	defer clear(handshakeHash[:])
	defer clear(temp[:])
	defer clear(kab[:])
	defer clear(kba[:])
	defer clear(askMaster[:])
	defer clear(sipMaster[:])
	defer clear(sipAB[:])
	defer clear(sipBA[:])

	ab, err := NewDirection(kab[:], sipAB[:16], sipAB[16:24])
	if err != nil {
		return nil, err
	}
	ba, err := NewDirection(kba[:], sipBA[:16], sipBA[16:24])
	if err != nil {
		ab.ReleaseSensitive()
		return nil, err
	}
	if initiator {
		return NewSession(conn, ab, ba), nil
	}
	return NewSession(conn, ba, ab), nil
}

func hmac256(key, first, second, third []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	if len(first) != 0 {
		_, _ = mac.Write(first)
	}
	if len(second) != 0 {
		_, _ = mac.Write(second)
	}
	if len(third) != 0 {
		_, _ = mac.Write(third)
	}
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	return sum
}

func aesCBCEncrypt(dst, plaintext, key, iv []byte) error {
	if len(plaintext) != len(dst) || len(plaintext)%aes.BlockSize != 0 || len(key) != 32 || len(iv) != aes.BlockSize {
		return ErrHandshake
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var previous [aes.BlockSize]byte
	copy(previous[:], iv)
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		for i := range aes.BlockSize {
			dst[offset+i] = plaintext[offset+i] ^ previous[i]
		}
		block.Encrypt(dst[offset:offset+aes.BlockSize], dst[offset:offset+aes.BlockSize])
		copy(previous[:], dst[offset:offset+aes.BlockSize])
	}
	return nil
}

func aesCBCDecrypt(dst, ciphertext, key, iv []byte) error {
	if len(ciphertext) != len(dst) || len(ciphertext)%aes.BlockSize != 0 || len(key) != 32 || len(iv) != aes.BlockSize {
		return ErrHandshake
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var previous, current [aes.BlockSize]byte
	copy(previous[:], iv)
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		copy(current[:], ciphertext[offset:offset+aes.BlockSize])
		block.Decrypt(dst[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
		for i := range aes.BlockSize {
			dst[offset+i] ^= previous[i]
		}
		previous = current
	}
	return nil
}
