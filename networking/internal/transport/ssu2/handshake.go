package ssu2

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/transport/noise"
)

const HandshakeProtocol = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"

var ErrHandshake = errors.New("ssu2: invalid handshake message")

// Initiator owns one SSU2 Noise XK exchange. The local static key is supplied
// when SessionConfirmed is built; remoteStatic and introKey are the `s` and
// `i` values selected from Bob's RouterInfo.
type Initiator struct {
	state            *noise.SymmetricState
	introKey         [cryptx.ChaChaKeySize]byte
	remoteStatic     *ecdh.PublicKey
	ephemeral        *ecdh.PrivateKey
	peerEphemeral    *ecdh.PublicKey
	destinationID    uint64
	sourceID         uint64
	requestHeaderKey [cryptx.ChaChaKeySize]byte
	confirmHeaderKey [cryptx.ChaChaKeySize]byte
	completed        bool
}

// Responder owns one parsed SessionRequest through SessionConfirmed. It must
// be discarded after any parse failure or after SessionConfirmed is accepted.
type Responder struct {
	state            *noise.SymmetricState
	introKey         [cryptx.ChaChaKeySize]byte
	peerEphemeral    *ecdh.PublicKey
	ephemeral        *ecdh.PrivateKey
	destinationID    uint64
	sourceID         uint64
	requestHeaderKey [cryptx.ChaChaKeySize]byte
	confirmHeaderKey [cryptx.ChaChaKeySize]byte
	completed        bool
}

// ReleaseSensitive abandons the handshake and overwrites IVNP-owned transcript,
// introduction, and header-key buffers.
func (i *Initiator) ReleaseSensitive() {
	if i == nil {
		return
	}
	if i.state != nil {
		i.state.ReleaseSensitive()
		i.state = nil
	}
	clear(i.introKey[:])
	clear(i.requestHeaderKey[:])
	clear(i.confirmHeaderKey[:])
	i.remoteStatic, i.ephemeral, i.peerEphemeral = nil, nil, nil
	i.completed = false
}

// ReleaseSensitive abandons the handshake and overwrites IVNP-owned transcript,
// introduction, and header-key buffers.
func (r *Responder) ReleaseSensitive() {
	if r == nil {
		return
	}
	if r.state != nil {
		r.state.ReleaseSensitive()
		r.state = nil
	}
	clear(r.introKey[:])
	clear(r.requestHeaderKey[:])
	clear(r.confirmHeaderKey[:])
	r.peerEphemeral, r.ephemeral = nil, nil
	r.completed = false
}

// NewInitiator prepares a one-use exchange. destinationID and sourceID are
// Alice's random nonzero connection IDs and must be distinct.
func NewInitiator(remoteStatic, introKey []byte, destinationID, sourceID uint64) (*Initiator, error) {
	if len(introKey) != cryptx.ChaChaKeySize || destinationID == 0 || sourceID == 0 || SameConnectionID(destinationID, sourceID) {
		return nil, ErrHandshake
	}
	remote, err := ecdh.X25519().NewPublicKey(remoteStatic)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	state := noise.Initialize(HandshakeProtocol)
	state.MixHash(nil)
	state.MixHash(remote.Bytes())
	var key [cryptx.ChaChaKeySize]byte
	copy(key[:], introKey)
	return &Initiator{state: state, introKey: key, remoteStatic: remote, ephemeral: ephemeral, destinationID: destinationID, sourceID: sourceID}, nil
}

// BuildSessionRequest writes an encrypted long-header SessionRequest. payload
// must contain a DateTime block and at least eight bytes of SSU2 blocks.
func (i *Initiator) BuildSessionRequest(dst, payload []byte, packetNumber uint32, token uint64) ([]byte, error) {
	if i == nil || i.completed || i.ephemeral == nil || !validHandshakePayload(payload) {
		return nil, ErrHandshake
	}
	total := LongHeaderLen + 32 + len(payload) + PacketTagLen
	if total < MinPacketLen || total > MaxIPv4PacketLen {
		return nil, ErrPacketLength
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	header := LongHeader{DestinationID: i.destinationID, PacketNumber: packetNumber, Type: SessionRequest, Version: Version, NetworkID: NetworkID, SourceID: i.sourceID, Token: token}
	if err := header.MarshalTo(dst[:LongHeaderLen]); err != nil {
		return nil, err
	}
	i.state.MixHash(dst[:LongHeaderLen])
	i.state.MixHash(i.ephemeral.PublicKey().Bytes())
	shared, err := i.ephemeral.ECDH(i.remoteStatic)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return nil, err
	}
	if _, err = i.state.EncryptAndHash(dst[LongHeaderLen+32:total], payload); err != nil {
		return nil, err
	}
	i.requestHeaderKey = deriveHeaderKey(i.state.ChainingKey(), "SessCreateHeader")
	copy(dst[LongHeaderLen:LongHeaderLen+32], i.ephemeral.PublicKey().Bytes())
	if err = ProtectHeader(dst[:total], i.introKey[:], i.introKey[:], 48); err != nil {
		return nil, err
	}
	return dst[:total], nil
}

// PeekSessionRequest authenticates neither the ephemeral key nor the payload;
// it only removes enough header protection to validate a token before the
// responder performs an expensive X25519 operation. packet remains unchanged.
func PeekSessionRequest(packet, introKey []byte) (LongHeader, error) {
	if len(packet) < LongHeaderLen+32+PacketTagLen || len(packet) > MaxIPv4PacketLen || len(introKey) != cryptx.ChaChaKeySize {
		return LongHeader{}, ErrHandshake
	}
	var raw [LongHeaderLen]byte
	copy(raw[:], packet[:LongHeaderLen])
	if err := xorHeaderMask(raw[:8], introKey, packet[len(packet)-24:len(packet)-12]); err != nil {
		return LongHeader{}, err
	}
	if err := xorHeaderMask(raw[8:16], introKey, packet[len(packet)-12:]); err != nil {
		return LongHeader{}, err
	}
	if err := maskHeaderExtension(raw[16:], introKey); err != nil {
		return LongHeader{}, err
	}
	header, err := ParseLongHeader(raw[:], NetworkID)
	if err != nil || header.Type != SessionRequest || header.DestinationID == 0 || header.SourceID == 0 || SameConnectionID(header.DestinationID, header.SourceID) {
		return LongHeader{}, ErrHandshake
	}
	return header, nil
}

// PeekDestinationID recovers the routing connection ID from a short-header
// packet without requiring the per-session second header key. packet remains
// unchanged, so it may subsequently be authenticated by a DataCipher or a
// ConfirmedReassembler.
func PeekDestinationID(packet, receiverIntroKey []byte) (uint64, error) {
	if len(packet) < MinPacketLen || len(packet) > MaxIPv4PacketLen || len(receiverIntroKey) != cryptx.ChaChaKeySize {
		return 0, ErrHandshake
	}
	var destination [8]byte
	copy(destination[:], packet[:8])
	if err := xorHeaderMask(destination[:], receiverIntroKey, packet[len(packet)-24:len(packet)-12]); err != nil {
		return 0, err
	}
	id := binary.BigEndian.Uint64(destination[:])
	if id == 0 {
		return 0, ErrHandshake
	}
	return id, nil
}

// ParseSessionRequest removes header protection and authenticates one complete
// SessionRequest. packet is modified in place and must be caller-owned.
func ParseSessionRequest(packet, staticPrivate, introKey []byte) (*Responder, LongHeader, []byte, error) {
	if len(packet) < LongHeaderLen+32+PacketTagLen || len(packet) > MaxIPv4PacketLen || len(introKey) != cryptx.ChaChaKeySize {
		return nil, LongHeader{}, nil, ErrHandshake
	}
	if err := ProtectHeader(packet, introKey, introKey, 48); err != nil {
		return nil, LongHeader{}, nil, err
	}
	header, err := ParseLongHeader(packet[:LongHeaderLen], NetworkID)
	if err != nil || header.Type != SessionRequest || header.DestinationID == 0 || header.SourceID == 0 || SameConnectionID(header.DestinationID, header.SourceID) {
		return nil, LongHeader{}, nil, ErrHandshake
	}
	static, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, LongHeader{}, nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(packet[LongHeaderLen : LongHeaderLen+32])
	if err != nil {
		return nil, LongHeader{}, nil, err
	}
	state := noise.Initialize(HandshakeProtocol)
	state.MixHash(nil)
	state.MixHash(static.PublicKey().Bytes())
	state.MixHash(packet[:LongHeaderLen])
	state.MixHash(peer.Bytes())
	shared, err := static.ECDH(peer)
	if err != nil {
		return nil, LongHeader{}, nil, err
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, LongHeader{}, nil, err
	}
	payload := make([]byte, len(packet)-(LongHeaderLen+32+PacketTagLen))
	plain, err := state.DecryptAndHash(payload, packet[LongHeaderLen+32:])
	if err != nil || !validHandshakePayload(plain) {
		return nil, LongHeader{}, nil, ErrHandshake
	}
	var key [cryptx.ChaChaKeySize]byte
	copy(key[:], introKey)
	responder := &Responder{
		state:            state,
		introKey:         key,
		peerEphemeral:    peer,
		destinationID:    header.DestinationID,
		sourceID:         header.SourceID,
		requestHeaderKey: deriveHeaderKey(state.ChainingKey(), "SessCreateHeader"),
	}
	return responder, header, plain, nil
}

// BuildSessionCreated writes Bob's response to a parsed SessionRequest.
func (r *Responder) BuildSessionCreated(dst, payload []byte, packetNumber uint32) ([]byte, error) {
	if r == nil || r.completed || r.ephemeral != nil || !validHandshakePayload(payload) {
		return nil, ErrHandshake
	}
	total := LongHeaderLen + 32 + len(payload) + PacketTagLen
	if total < MinPacketLen || total > MaxIPv4PacketLen {
		return nil, ErrPacketLength
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	header := LongHeader{DestinationID: r.sourceID, PacketNumber: packetNumber, Type: SessionCreated, Version: Version, NetworkID: NetworkID, SourceID: r.destinationID}
	if err := header.MarshalTo(dst[:LongHeaderLen]); err != nil {
		return nil, err
	}
	r.state.MixHash(dst[:LongHeaderLen])
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
	if _, err = r.state.EncryptAndHash(dst[LongHeaderLen+32:total], payload); err != nil {
		return nil, err
	}
	r.confirmHeaderKey = deriveHeaderKey(r.state.ChainingKey(), "SessionConfirmed")
	r.ephemeral = ephemeral
	copy(dst[LongHeaderLen:LongHeaderLen+32], ephemeral.PublicKey().Bytes())
	if err = ProtectHeader(dst[:total], r.introKey[:], r.requestHeaderKey[:], 48); err != nil {
		return nil, err
	}
	return dst[:total], nil
}

// ParseSessionCreated advances an initiator after removing Bob's header
// protection. packet is modified in place and must be caller-owned.
func (i *Initiator) ParseSessionCreated(packet []byte) (LongHeader, []byte, error) {
	if i == nil || i.completed || i.peerEphemeral != nil || len(packet) < LongHeaderLen+32+PacketTagLen || len(packet) > MaxIPv4PacketLen {
		return LongHeader{}, nil, ErrHandshake
	}
	if err := ProtectHeader(packet, i.introKey[:], i.requestHeaderKey[:], 48); err != nil {
		return LongHeader{}, nil, err
	}
	header, err := ParseLongHeader(packet[:LongHeaderLen], NetworkID)
	if err != nil || header.Type != SessionCreated || header.DestinationID != i.sourceID || header.SourceID != i.destinationID || header.Token != 0 {
		return LongHeader{}, nil, ErrHandshake
	}
	peer, err := ecdh.X25519().NewPublicKey(packet[LongHeaderLen : LongHeaderLen+32])
	if err != nil {
		return LongHeader{}, nil, err
	}
	i.state.MixHash(packet[:LongHeaderLen])
	i.state.MixHash(peer.Bytes())
	shared, err := i.ephemeral.ECDH(peer)
	if err != nil {
		return LongHeader{}, nil, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return LongHeader{}, nil, err
	}
	payload := make([]byte, len(packet)-(LongHeaderLen+32+PacketTagLen))
	plain, err := i.state.DecryptAndHash(payload, packet[LongHeaderLen+32:])
	if err != nil || !validHandshakePayload(plain) {
		return LongHeader{}, nil, ErrHandshake
	}
	i.peerEphemeral = peer
	i.confirmHeaderKey = deriveHeaderKey(i.state.ChainingKey(), "SessionConfirmed")
	return header, plain, nil
}

// BuildSessionConfirmed writes one unfragmented SessionConfirmed packet. The
// caller must use BuildSessionConfirmedFragments for RouterInfos that exceed a
// single datagram's MTU budget.
func (i *Initiator) BuildSessionConfirmed(dst, staticPrivate, payload []byte) ([]byte, error) {
	if i == nil || i.completed || i.peerEphemeral == nil || !validConfirmedPayload(payload) {
		return nil, ErrHandshake
	}
	total := ShortHeaderLen + 48 + len(payload) + PacketTagLen
	if total < MinPacketLen || total > MaxIPv4PacketLen {
		return nil, ErrPacketLength
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	static, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, err
	}
	header := ShortHeader{DestinationID: i.destinationID, Type: SessionConfirmed, Fragment: 1}
	if err = header.MarshalTo(dst[:ShortHeaderLen]); err != nil {
		return nil, err
	}
	i.state.MixHash(dst[:ShortHeaderLen])
	if _, err = i.state.EncryptAndHash(dst[ShortHeaderLen:ShortHeaderLen+48], static.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	shared, err := static.ECDH(i.peerEphemeral)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return nil, err
	}
	if _, err = i.state.EncryptAndHash(dst[ShortHeaderLen+48:total], payload); err != nil {
		return nil, err
	}
	if err = ProtectHeader(dst[:total], i.introKey[:], i.confirmHeaderKey[:], 0); err != nil {
		return nil, err
	}
	i.completed = true
	return dst[:total], nil
}

// BuildSessionConfirmedFragments writes SessionConfirmed fragments for payloads
// whose RouterInfo does not fit in one datagram. Every returned packet is
// immutable for retransmission and uses packet number zero as required by SSU2.
func (i *Initiator) BuildSessionConfirmedFragments(staticPrivate, payload []byte, maxPacket int) ([][]byte, error) {
	if i == nil || i.completed || i.peerEphemeral == nil || !validConfirmedPayload(payload) {
		return nil, ErrHandshake
	}
	if maxPacket > MaxIPv4PacketLen {
		maxPacket = MaxIPv4PacketLen
	}
	if maxPacket < MinPacketLen {
		return nil, ErrPacketLength
	}
	ciphertextLen := 48 + len(payload) + PacketTagLen
	maxFragment := maxPacket - ShortHeaderLen
	if maxFragment < 24 {
		return nil, ErrPacketLength
	}
	count := (ciphertextLen + maxFragment - 1) / maxFragment
	if count < 1 || count > 15 {
		return nil, ErrPacketLength
	}
	firstFragment := min(ciphertextLen, maxFragment)
	lastFragment := ciphertextLen - (count-1)*maxFragment
	if count > 1 && lastFragment < 24 {
		firstFragment -= 24 - lastFragment
	}
	static, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, err
	}
	header := ShortHeader{DestinationID: i.destinationID, Type: SessionConfirmed, Fragment: uint8(count)}
	var firstHeader [ShortHeaderLen]byte
	if err = header.MarshalTo(firstHeader[:]); err != nil {
		return nil, err
	}
	i.state.MixHash(firstHeader[:])
	ciphertext := make([]byte, ciphertextLen)
	if _, err = i.state.EncryptAndHash(ciphertext[:48], static.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	shared, err := static.ECDH(i.peerEphemeral)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if err = i.state.MixKey(shared); err != nil {
		return nil, err
	}
	if _, err = i.state.EncryptAndHash(ciphertext[48:], payload); err != nil {
		return nil, err
	}
	packets := make([][]byte, 0, count)
	offset := 0
	for index := range count {
		n := maxFragment
		if index == 0 {
			n = firstFragment
		}
		if n > len(ciphertext)-offset {
			n = len(ciphertext) - offset
		}
		if n < 24 {
			return nil, ErrPacketLength
		}
		header.Fragment = uint8(index<<4 | count)
		packet := make([]byte, ShortHeaderLen+n)
		if err = header.MarshalTo(packet[:ShortHeaderLen]); err != nil {
			return nil, err
		}
		copy(packet[ShortHeaderLen:], ciphertext[offset:offset+n])
		if err = ProtectHeader(packet, i.introKey[:], i.confirmHeaderKey[:], 0); err != nil {
			return nil, err
		}
		packets = append(packets, packet)
		offset += n
	}
	if offset != len(ciphertext) {
		return nil, ErrHandshake
	}
	i.completed = true
	return packets, nil
}

// ConfirmedReassembler bounds one pending fragmented SessionConfirmed. It
// buffers encrypted fragments until all arrive, then authenticates them as a
// single Noise payload using fragment zero's header as associated data.
type ConfirmedReassembler struct {
	responder *Responder
	total     uint8
	count     uint8
	header    [ShortHeaderLen]byte
	fragments [15][]byte
}

func NewConfirmedReassembler(responder *Responder) *ConfirmedReassembler {
	return &ConfirmedReassembler{responder: responder}
}

// ReleaseSensitive clears retained fragment ciphertext and releases the
// unpromoted responder state.
func (r *ConfirmedReassembler) ReleaseSensitive() {
	if r == nil {
		return
	}
	for i := range r.fragments {
		clear(r.fragments[i])
		r.fragments[i] = nil
	}
	clear(r.header[:])
	r.total, r.count = 0, 0
	if r.responder != nil {
		r.responder.ReleaseSensitive()
		r.responder = nil
	}
}

// Add accepts one caller-owned packet. complete is true only after a complete,
// authenticated SessionConfirmed has been returned. Duplicate fragments are
// ignored before transcript processing so a valid retransmission remains safe.
func (r *ConfirmedReassembler) Add(packet []byte) (static, payload []byte, complete bool, err error) {
	if r == nil || r.responder == nil || r.responder.completed || len(packet) < MinPacketLen || len(packet) > MaxIPv4PacketLen {
		return nil, nil, false, ErrHandshake
	}
	if err = ProtectHeader(packet, r.responder.introKey[:], r.responder.confirmHeaderKey[:], 0); err != nil {
		return nil, nil, false, err
	}
	header, err := ParseShortHeader(packet[:ShortHeaderLen])
	if err != nil || header.Type != SessionConfirmed || header.DestinationID != r.responder.destinationID {
		return nil, nil, false, ErrHandshake
	}
	total := header.Fragment & 0x0f
	index := header.Fragment >> 4
	if total == 1 && index == 0 {
		static, payload, err = r.responder.parseSessionConfirmed(packet[:ShortHeaderLen], packet[ShortHeaderLen:])
		if err != nil {
			return nil, nil, false, err
		}
		return static, payload, true, nil
	}
	if total < 2 || index >= total {
		return nil, nil, false, ErrHandshake
	}
	if r.total == 0 {
		r.total = total
	} else if r.total != total {
		return nil, nil, false, ErrHandshake
	}
	if r.fragments[index] != nil {
		return nil, nil, false, nil
	}
	r.fragments[index] = append([]byte(nil), packet[ShortHeaderLen:]...)
	r.count++
	if index == 0 {
		copy(r.header[:], packet[:ShortHeaderLen])
	}
	if r.count != r.total || r.fragments[0] == nil {
		return nil, nil, false, nil
	}
	totalLen := 0
	for index := 0; index < int(r.total); index++ {
		if r.fragments[index] == nil {
			return nil, nil, false, nil
		}
		totalLen += len(r.fragments[index])
	}
	ciphertext := make([]byte, 0, totalLen)
	for index := 0; index < int(r.total); index++ {
		ciphertext = append(ciphertext, r.fragments[index]...)
	}
	static, payload, err = r.responder.parseSessionConfirmed(r.header[:], ciphertext)
	if err != nil {
		return nil, nil, false, err
	}
	return static, payload, true, nil
}

// ParseSessionConfirmed authenticates one unfragmented SessionConfirmed and
// returns Alice's static key and its required RouterInfo-first payload.
func (r *Responder) ParseSessionConfirmed(packet []byte) ([]byte, []byte, error) {
	if r == nil || r.completed || r.ephemeral == nil || len(packet) < ShortHeaderLen+48+PacketTagLen || len(packet) > MaxIPv4PacketLen {
		return nil, nil, ErrHandshake
	}
	if err := ProtectHeader(packet, r.introKey[:], r.confirmHeaderKey[:], 0); err != nil {
		return nil, nil, err
	}
	header, err := ParseShortHeader(packet[:ShortHeaderLen])
	if err != nil || header.Type != SessionConfirmed || header.DestinationID != r.destinationID || header.Fragment != 1 {
		return nil, nil, ErrHandshake
	}
	return r.parseSessionConfirmed(packet[:ShortHeaderLen], packet[ShortHeaderLen:])
}

func (r *Responder) parseSessionConfirmed(header, ciphertext []byte) ([]byte, []byte, error) {
	if r.completed || len(header) != ShortHeaderLen || len(ciphertext) < 48+PacketTagLen {
		return nil, nil, ErrHandshake
	}
	r.state.MixHash(header)
	var static [32]byte
	plainStatic, err := r.state.DecryptAndHash(static[:], ciphertext[:48])
	if err != nil || len(plainStatic) != len(static) {
		return nil, nil, ErrHandshake
	}
	peer, err := ecdh.X25519().NewPublicKey(static[:])
	if err != nil {
		return nil, nil, err
	}
	shared, err := r.ephemeral.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	if err = r.state.MixKey(shared); err != nil {
		return nil, nil, err
	}
	payload := make([]byte, len(ciphertext)-(48+PacketTagLen))
	plain, err := r.state.DecryptAndHash(payload, ciphertext[48:])
	if err != nil || !validConfirmedPayload(plain) {
		return nil, nil, ErrHandshake
	}
	r.completed = true
	return append([]byte(nil), static[:]...), plain, nil
}

// DataCiphers derives directional data packet ciphers after SessionConfirmed.
// localIntro is Alice's RouterInfo `i` key. The initiator's first result sends
// to Bob; its second result receives from Bob.
func (i *Initiator) DataCiphers(localIntro []byte) (*DataCipher, *DataCipher, error) {
	if i == nil || !i.completed || i.state == nil {
		return nil, nil, ErrHandshake
	}
	send, receive, err := deriveDataCiphers(i.state, localIntro, i.introKey[:], true)
	if err == nil {
		i.ReleaseSensitive()
	}
	return send, receive, err
}

// DataCiphers derives directional data packet ciphers after SessionConfirmed.
// peerIntro is Alice's RouterInfo `i` key. The responder's first result sends
// to Alice; its second result receives from Alice.
func (r *Responder) DataCiphers(peerIntro []byte) (*DataCipher, *DataCipher, error) {
	if r == nil || !r.completed || r.state == nil {
		return nil, nil, ErrHandshake
	}
	send, receive, err := deriveDataCiphers(r.state, r.introKey[:], peerIntro, false)
	if err == nil {
		r.ReleaseSensitive()
	}
	return send, receive, err
}

func deriveDataCiphers(state *noise.SymmetricState, localIntro, peerIntro []byte, initiator bool) (*DataCipher, *DataCipher, error) {
	if state == nil || len(localIntro) != cryptx.ChaChaKeySize || len(peerIntro) != cryptx.ChaChaKeySize {
		return nil, nil, ErrHandshake
	}
	chain := state.ChainingKey()
	split := hkdfExpand64(chain[:], nil, nil)
	abKey := hkdfExpand64(split[:32], nil, []byte("HKDFSSU2DataKeys"))
	baKey := hkdfExpand64(split[32:], nil, []byte("HKDFSSU2DataKeys"))
	defer clear(chain[:])
	defer clear(split[:])
	defer clear(abKey[:])
	defer clear(baKey[:])
	if initiator {
		send, err := NewDataCipher(abKey[:32], peerIntro, abKey[32:])
		if err != nil {
			return nil, nil, err
		}
		receive, err := NewDataCipher(baKey[:32], localIntro, baKey[32:])
		if err != nil {
			send.ReleaseSensitive()
			return nil, nil, err
		}
		return send, receive, nil
	}
	send, err := NewDataCipher(baKey[:32], peerIntro, baKey[32:])
	if err != nil {
		return nil, nil, err
	}
	receive, err := NewDataCipher(abKey[:32], localIntro, abKey[32:])
	if err != nil {
		send.ReleaseSensitive()
		return nil, nil, err
	}
	return send, receive, nil
}

func deriveHeaderKey(chain [32]byte, label string) [cryptx.ChaChaKeySize]byte {
	return hkdfExpand(chain[:], nil, []byte(label))
}

func hkdfExpand(salt, input, info []byte) [cryptx.ChaChaKeySize]byte {
	expanded := hkdfExpand64(salt, input, info)
	var out [cryptx.ChaChaKeySize]byte
	copy(out[:], expanded[:32])
	return out
}

func hkdfExpand64(salt, input, info []byte) [64]byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(input)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	_, _ = mac.Write(info)
	_, _ = mac.Write([]byte{1})
	first := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	_, _ = mac.Write(first)
	_, _ = mac.Write(info)
	_, _ = mac.Write([]byte{2})
	second := mac.Sum(nil)
	var out [64]byte
	copy(out[:32], first)
	copy(out[32:], second)
	clear(prk)
	clear(first)
	clear(second)
	return out
}

func validHandshakePayload(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	iterator := NewBlockIterator(payload)
	dateTime := false
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return false
		}
		if !ok {
			return dateTime
		}
		if block.Type == BlockDateTime {
			if dateTime {
				return false
			}
			dateTime = true
		}
	}
}

func validConfirmedPayload(payload []byte) bool {
	iterator := NewBlockIterator(payload)
	block, ok, err := iterator.Next()
	if err != nil || !ok || block.Type != BlockRouterInfo {
		return false
	}
	for {
		block, ok, err = iterator.Next()
		if err != nil {
			return false
		}
		if !ok {
			return true
		}
		if block.Type != BlockOptions && block.Type != BlockI2NP && block.Type != BlockPadding {
			return false
		}
	}
}

// MarshalBlock appends a caller-owned SSU2 block. It is useful for handshake
// DateTime and RouterInfo payload construction.
func MarshalBlock(dst []byte, kind uint8, data []byte) ([]byte, error) {
	if len(data) > 0xffff {
		return nil, ErrPacketLength
	}
	start := len(dst)
	dst = append(dst, make([]byte, 3+len(data))...)
	dst[start] = kind
	binary.BigEndian.PutUint16(dst[start+1:start+3], uint16(len(data)))
	copy(dst[start+3:], data)
	return dst, nil
}
