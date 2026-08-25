package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/transport/noise"
	"io"
)

const (
	ShortBuildRecordSize       = 218
	ShortBuildRequestPlainSize = 154
	ShortBuildReplyPlainSize   = 202

	shortBuildPeerSize       = 16
	shortBuildEphemeralSize  = 32
	shortBuildCipherOffset   = shortBuildPeerSize + shortBuildEphemeralSize
	shortBuildFlagOffset     = 40
	shortBuildGatewayFlag    = 1 << 7
	shortBuildEndpointFlag   = 1 << 6
	shortBuildOptionsOffset  = 56
	shortBuildMaxOptionsSize = 98
	shortBuildLifetime       = 600
)

const shortBuildProtocol = "Noise_N_25519_ChaChaPoly_SHA256"

var (
	ErrShortBuildRecord = errors.New("tunnel: invalid short build record")
	ErrShortBuildKey    = errors.New("tunnel: invalid short build key")
)

// ShortBuildKeys contains the per-hop keys derived by the ECIES short tunnel
// build handshake. Hash is the Noise transcript AD required to authenticate the
// hop's reply. Values are caller-owned and must be cleared when the pending
// build expires.
type ShortBuildKeys struct {
	ReplyKey      [32]byte
	LayerKey      [32]byte
	IVKey         [32]byte
	GarlicKey     [32]byte
	GarlicTag     [8]byte
	Hash          [32]byte
	HasGarlicKeys bool
}

// ShortBuildRequest is the authenticated 154-byte request carried inside one
// ECIES short build record. Options aliases the parsed plaintext.
type ShortBuildRequest struct {
	ReceiveTunnelID uint32
	NextTunnelID    uint32
	NextRouter      foundation.Hash
	Gateway         bool
	Endpoint        bool
	RequestMinutes  uint32
	LifetimeSeconds uint32
	NextMessageID   uint32
	Options         foundation.Mapping
	Bandwidth       ShortBuildOptions
}

// MarshalShortBuildRequest writes the canonical request fields and random
// padding. options must be one complete canonical I2P Mapping including its
// two-byte length prefix; nil encodes an empty mapping.
func MarshalShortBuildRequest(dst []byte, request ShortBuildRequest, options []byte) error {
	return marshalShortBuildRequest(dst, request, options, rand.Reader)
}

func marshalShortBuildRequest(dst []byte, request ShortBuildRequest, options []byte, random io.Reader) error {
	marshalShortBuildRequestRejected := len(dst) < ShortBuildRequestPlainSize || request.ReceiveTunnelID == 0 || request.NextTunnelID == 0 || request.NextMessageID == 0 || request.Gateway && request.Endpoint || request.LifetimeSeconds != shortBuildLifetime
	if !marshalShortBuildRequestRejected {
		marshalShortBuildRequestRejected = random == nil
	}
	if marshalShortBuildRequestRejected {
		return ErrShortBuildRecord
	}
	if options == nil {
		options = []byte{0, 0}
	}

	mapping, used, err := foundation.ParseMapping(options)
	if err != nil || used != len(options) || mapping.EncodedLen() > shortBuildMaxOptionsSize {
		return ErrShortBuildRecord
	}
	clear(dst[:ShortBuildRequestPlainSize])
	binary.BigEndian.PutUint32(dst[0:4], request.ReceiveTunnelID)
	binary.BigEndian.PutUint32(dst[4:8], request.NextTunnelID)
	copy(dst[8:40], request.NextRouter[:])
	if request.Gateway {
		dst[shortBuildFlagOffset] = shortBuildGatewayFlag
	}
	if request.Endpoint {
		dst[shortBuildFlagOffset] = shortBuildEndpointFlag
	}
	// bytes 41-42 and layer encryption type byte 43 remain zero.
	binary.BigEndian.PutUint32(dst[44:48], request.RequestMinutes)
	binary.BigEndian.PutUint32(dst[48:52], request.LifetimeSeconds)
	binary.BigEndian.PutUint32(dst[52:56], request.NextMessageID)
	copy(dst[shortBuildOptionsOffset:], options)
	if _, err = io.ReadFull(random, dst[shortBuildOptionsOffset+len(options):ShortBuildRequestPlainSize]); err != nil {
		clear(dst[:ShortBuildRequestPlainSize])
		return err
	}
	return nil
}

// ParseShortBuildRequest validates the fixed fields, currently supported AES
// layer type, lifetime, and bounded canonical options mapping.
func ParseShortBuildRequest(plaintext []byte) (ShortBuildRequest, error) {
	if len(plaintext) != ShortBuildRequestPlainSize {
		return ShortBuildRequest{}, ErrShortBuildRecord
	}
	flags := plaintext[shortBuildFlagOffset]
	if flags&^(byte(shortBuildGatewayFlag)|byte(shortBuildEndpointFlag)) != 0 || flags&(shortBuildGatewayFlag|shortBuildEndpointFlag) == shortBuildGatewayFlag|shortBuildEndpointFlag || plaintext[41] != 0 || plaintext[42] != 0 || plaintext[43] != 0 {
		return ShortBuildRequest{}, ErrShortBuildRecord
	}
	request := ShortBuildRequest{
		ReceiveTunnelID: binary.BigEndian.Uint32(plaintext[0:4]),
		NextTunnelID:    binary.BigEndian.Uint32(plaintext[4:8]),
		Gateway:         flags&shortBuildGatewayFlag != 0,
		Endpoint:        flags&shortBuildEndpointFlag != 0,
		RequestMinutes:  binary.BigEndian.Uint32(plaintext[44:48]),
		LifetimeSeconds: binary.BigEndian.Uint32(plaintext[48:52]),
		NextMessageID:   binary.BigEndian.Uint32(plaintext[52:56]),
	}
	if request.ReceiveTunnelID == 0 || request.NextTunnelID == 0 || request.NextMessageID == 0 || request.LifetimeSeconds != shortBuildLifetime {
		return ShortBuildRequest{}, ErrShortBuildRecord
	}
	copy(request.NextRouter[:], plaintext[8:40])
	mapping, used, err := foundation.ParseMapping(plaintext[shortBuildOptionsOffset:])
	if err != nil || used > shortBuildMaxOptionsSize {
		return ShortBuildRequest{}, ErrShortBuildRecord
	}
	request.Options = mapping
	var ok bool
	request.Bandwidth, ok = parseShortBuildOptions(mapping, request.Gateway)
	if !ok {
		return ShortBuildRequest{}, ErrShortBuildRecord
	}
	return request, nil
}

// PreprocessShortBuildRecords conceals each later hop's request with every
// earlier hop's reply key. positions maps path order to record slots.
func PreprocessShortBuildRecords(records []byte, keys []ShortBuildKeys, positions []uint8) error {
	if len(keys) == 0 || len(keys) != len(positions) || len(records)%ShortBuildRecordSize != 0 {
		return ErrShortBuildRecord
	}
	count := len(records) / ShortBuildRecordSize
	if count < len(keys) || count > 8 {
		return ErrShortBuildRecord
	}
	var used [8]bool
	for _, position := range positions {
		if int(position) >= count || used[position] {
			return ErrShortBuildRecord
		}
		used[position] = true
	}
	for later := 1; later < len(keys); later++ {
		slot := positions[later]
		record := records[int(slot)*ShortBuildRecordSize : (int(slot)+1)*ShortBuildRecordSize]
		for earlier := 0; earlier < later; earlier++ {
			if err := TransformShortBuildRecord(record, record, keys[earlier].ReplyKey, slot); err != nil {
				return err
			}
		}
	}
	return nil
}

// ProcessShortBuildRecords processes the record addressed to local, replaces
// it with an authenticated reply, and applies this hop's reply layer to every
// other record. The returned request aliases plaintextDst.
func ProcessShortBuildRecords(records, plaintextDst []byte, local foundation.Hash, staticPrivate []byte, accept bool, random io.Reader) (ShortBuildRequest, ShortBuildKeys, uint8, error) {
	var keys ShortBuildKeys
	if len(staticPrivate) != shortBuildEphemeralSize {
		return ShortBuildRequest{}, keys, 0, ErrShortBuildRecord
	}
	private, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return ShortBuildRequest{}, keys, 0, ErrShortBuildKey
	}
	return processShortBuildRecordsWithPrivate(records, plaintextDst, local, private, accept, random)
}

// processShortBuildRecordsWithPrivate is the manager hot-path variant. A
// BuildManager owns this immutable X25519 key for its lifetime, avoiding a
// private-key parse for every admitted transit request.
func processShortBuildRecordsWithPrivate(records, plaintextDst []byte, local foundation.Hash, private *ecdh.PrivateKey, accept bool, random io.Reader) (ShortBuildRequest, ShortBuildKeys, uint8, error) {
	var keys ShortBuildKeys
	if len(records)%ShortBuildRecordSize != 0 || len(plaintextDst) < ShortBuildRequestPlainSize || private == nil || random == nil {
		return ShortBuildRequest{}, keys, 0, ErrShortBuildRecord
	}
	count := len(records) / ShortBuildRecordSize
	if count < 1 || count > 8 {
		return ShortBuildRequest{}, keys, 0, ErrShortBuildRecord
	}
	found := -1
	for index := range count {
		record := records[index*ShortBuildRecordSize : (index+1)*ShortBuildRecordSize]
		if subtle.ConstantTimeCompare(record[:shortBuildPeerSize], local[:shortBuildPeerSize]) == 1 {
			if found >= 0 {
				return ShortBuildRequest{}, keys, 0, ErrShortBuildRecord
			}
			found = index
		}
	}
	if found < 0 {
		return ShortBuildRequest{}, keys, 0, ErrShortBuildRecord
	}
	slot := uint8(found)
	record := records[found*ShortBuildRecordSize : (found+1)*ShortBuildRecordSize]
	plaintext, derived, err := decryptShortBuildRequestWithPrivate(plaintextDst, record, local, private)
	if err != nil {
		return ShortBuildRequest{}, keys, 0, err
	}
	request, err := ParseShortBuildRequest(plaintext)
	if err != nil {
		clear(plaintextDst[:ShortBuildRequestPlainSize])
		return ShortBuildRequest{}, keys, 0, err
	}
	var reply [ShortBuildReplyPlainSize]byte
	// Empty canonical Mapping; remaining bytes are indistinguishable padding.
	if _, err = io.ReadFull(random, reply[2:len(reply)-1]); err != nil {
		clear(plaintextDst[:ShortBuildRequestPlainSize])
		return ShortBuildRequest{}, keys, 0, err
	}
	if !accept {
		reply[len(reply)-1] = 30
	}
	if _, err = SealShortBuildReply(record, reply[:], derived, slot); err != nil {
		clear(plaintextDst[:ShortBuildRequestPlainSize])
		return ShortBuildRequest{}, keys, 0, err
	}
	for index := range count {
		if index == found {
			continue
		}
		other := records[index*ShortBuildRecordSize : (index+1)*ShortBuildRecordSize]
		if err = TransformShortBuildRecord(other, other, derived.ReplyKey, uint8(index)); err != nil {
			clear(plaintextDst[:ShortBuildRequestPlainSize])
			return ShortBuildRequest{}, keys, 0, err
		}
	}
	return request, derived, slot, nil
}

// OpenShortBuildReplies removes later-hop layers and authenticates every real
// hop reply in path order. replies must have room for len(keys) reply records.
func OpenShortBuildReplies(replies []byte, keys []ShortBuildKeys, positions []uint8, dst []byte) error {
	if len(keys) == 0 || len(keys) != len(positions) || len(replies)%ShortBuildRecordSize != 0 || len(dst) < len(keys)*ShortBuildReplyPlainSize {
		return ErrShortBuildRecord
	}
	count := len(replies) / ShortBuildRecordSize
	for hop, slot := range positions {
		if int(slot) >= count {
			return ErrShortBuildRecord
		}
		var record [ShortBuildRecordSize]byte
		copy(record[:], replies[int(slot)*ShortBuildRecordSize:(int(slot)+1)*ShortBuildRecordSize])
		for later := hop + 1; later < len(keys); later++ {
			if err := TransformShortBuildRecord(record[:], record[:], keys[later].ReplyKey, slot); err != nil {
				return err
			}
		}
		plaintext := dst[hop*ShortBuildReplyPlainSize : (hop+1)*ShortBuildReplyPlainSize]
		if _, err := OpenShortBuildReply(plaintext, record[:], keys[hop], slot); err != nil {
			clear(dst[:len(keys)*ShortBuildReplyPlainSize])
			return err
		}
		if mapping, used, err := foundation.ParseMapping(plaintext); err != nil || used > ShortBuildReplyPlainSize-1 || mapping.EncodedLen() > ShortBuildReplyPlainSize-1 {
			clear(dst[:len(keys)*ShortBuildReplyPlainSize])
			return ErrShortBuildRecord
		}
		replyCode := plaintext[ShortBuildReplyPlainSize-1]
		if replyCode != 0 && replyCode != 30 {
			clear(dst[:len(keys)*ShortBuildReplyPlainSize])
			return ErrShortBuildRecord
		}
	}
	return nil
}

// EncryptShortBuildRequest creates one 218-byte ECIES short build record using
// a fresh X25519 ephemeral key. plaintext is the exact 154-byte request layout
// from the tunnel-creation-ecies specification.
func EncryptShortBuildRequest(dst []byte, hop foundation.Hash, hopStatic []byte, plaintext []byte) (ShortBuildKeys, error) {
	return encryptShortBuildRequest(dst, hop, hopStatic, plaintext, rand.Reader)
}

func encryptShortBuildRequest(dst []byte, hop foundation.Hash, hopStatic, plaintext []byte, random io.Reader) (ShortBuildKeys, error) {
	var keys ShortBuildKeys
	if len(dst) < ShortBuildRecordSize || len(hopStatic) != shortBuildEphemeralSize || len(plaintext) != ShortBuildRequestPlainSize || random == nil {
		return keys, ErrShortBuildRecord
	}
	curve := ecdh.X25519()
	remote, err := curve.NewPublicKey(hopStatic)
	if err != nil {
		return keys, ErrShortBuildKey
	}
	ephemeral, err := curve.GenerateKey(random)
	if err != nil {
		return keys, err
	}
	copy(dst[:shortBuildPeerSize], hop[:shortBuildPeerSize])
	copy(dst[shortBuildPeerSize:shortBuildCipherOffset], ephemeral.PublicKey().Bytes())
	state := initializeShortBuild(hopStatic, ephemeral.PublicKey().Bytes())
	defer state.ReleaseSensitive()
	shared, err := ephemeral.ECDH(remote)
	if err != nil {
		return keys, ErrShortBuildKey
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return keys, err
	}
	ciphertext, err := state.EncryptAndHash(dst[shortBuildCipherOffset:ShortBuildRecordSize], plaintext)
	if err != nil || len(ciphertext) != ShortBuildRequestPlainSize+cryptography.ChaChaTagSize {
		return keys, ErrShortBuildRecord
	}
	keys = deriveShortBuildKeys(state.ChainingKey(), state.Hash(), plaintext[shortBuildFlagOffset]&shortBuildEndpointFlag != 0)
	return keys, nil
}

func DecryptShortBuildRequest(dst, record []byte, local foundation.Hash, staticPrivate []byte) ([]byte, ShortBuildKeys, error) {
	var keys ShortBuildKeys
	if len(staticPrivate) != shortBuildEphemeralSize {
		return nil, keys, ErrShortBuildRecord
	}
	private, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, keys, ErrShortBuildKey
	}
	return decryptShortBuildRequestWithPrivate(dst, record, local, private)
}

func decryptShortBuildRequestWithPrivate(dst, record []byte, local foundation.Hash, private *ecdh.PrivateKey) ([]byte, ShortBuildKeys, error) {
	var keys ShortBuildKeys
	if len(dst) < ShortBuildRequestPlainSize || len(record) != ShortBuildRecordSize || private == nil || subtle.ConstantTimeCompare(record[:shortBuildPeerSize], local[:shortBuildPeerSize]) != 1 {
		return nil, keys, ErrShortBuildRecord
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(record[shortBuildPeerSize:shortBuildCipherOffset])
	if err != nil {
		return nil, keys, ErrShortBuildKey
	}
	state := initializeShortBuild(private.PublicKey().Bytes(), ephemeral.Bytes())
	defer state.ReleaseSensitive()
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, keys, ErrShortBuildKey
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, keys, err
	}
	plaintext, err := state.DecryptAndHash(dst[:ShortBuildRequestPlainSize], record[shortBuildCipherOffset:])
	if err != nil {
		clear(dst[:ShortBuildRequestPlainSize])
		return nil, keys, ErrShortBuildRecord
	}
	keys = deriveShortBuildKeys(state.ChainingKey(), state.Hash(), plaintext[shortBuildFlagOffset]&shortBuildEndpointFlag != 0)
	return plaintext, keys, nil
}

// SealShortBuildReply authenticates a hop's 202-byte reply at its record index.
func SealShortBuildReply(dst, plaintext []byte, keys ShortBuildKeys, recordIndex uint8) ([]byte, error) {
	if recordIndex >= 8 || len(dst) < ShortBuildRecordSize || len(plaintext) != ShortBuildReplyPlainSize {
		return nil, ErrShortBuildRecord
	}
	cipher, err := cryptography.NewChaCha20Poly1305(keys.ReplyKey[:])
	if err != nil {
		return nil, err
	}
	defer cipher.ReleaseSensitive()
	nonce := shortBuildNonce(recordIndex)
	return cipher.SealTo(dst[:ShortBuildRecordSize], nonce[:], plaintext, keys.Hash[:])
}

// OpenShortBuildReply authenticates the creator's reply record at recordIndex.
func OpenShortBuildReply(dst, ciphertext []byte, keys ShortBuildKeys, recordIndex uint8) ([]byte, error) {
	if recordIndex >= 8 || len(dst) < ShortBuildReplyPlainSize || len(ciphertext) != ShortBuildRecordSize {
		return nil, ErrShortBuildRecord
	}
	cipher, err := cryptography.NewChaCha20Poly1305(keys.ReplyKey[:])
	if err != nil {
		return nil, err
	}
	defer cipher.ReleaseSensitive()
	nonce := shortBuildNonce(recordIndex)
	plaintext, err := cipher.OpenTo(dst[:ShortBuildReplyPlainSize], nonce[:], ciphertext, keys.Hash[:])
	if err != nil {
		clear(dst[:ShortBuildReplyPlainSize])
		return nil, ErrShortBuildRecord
	}
	return plaintext, nil
}

// TransformShortBuildRecord applies the per-hop ChaCha20 layer to another
// complete encrypted record. Applying it twice with the same index restores the
// original bytes.
func TransformShortBuildRecord(dst, src []byte, replyKey [32]byte, recordIndex uint8) error {
	if recordIndex >= 8 || len(dst) < ShortBuildRecordSize || len(src) != ShortBuildRecordSize {
		return ErrShortBuildRecord
	}
	nonce := shortBuildNonce(recordIndex)
	stream, err := cryptography.NewChaCha20Stream(replyKey[:], nonce[:])
	if err != nil {
		return err
	}
	stream.SetCounter(1)
	stream.XORKeyStream(dst[:ShortBuildRecordSize], src)
	return nil
}

func initializeShortBuild(static, ephemeral []byte) *noise.SymmetricState {
	state := noise.Initialize(shortBuildProtocol)
	_ = state.MixHash(nil)
	_ = state.MixHash(static)
	_ = state.MixHash(ephemeral)
	return state
}

func deriveShortBuildKeys(chain, hash [32]byte, endpoint bool) ShortBuildKeys {
	var keys ShortBuildKeys
	chain, keys.ReplyKey = tunnelKDF(chain, "SMTunnelReplyKey")
	chain, keys.LayerKey = tunnelKDF(chain, "SMTunnelLayerKey")
	if endpoint {
		chain, keys.IVKey = tunnelKDF(chain, "TunnelLayerIVKey")
		chain, keys.GarlicKey = tunnelKDF(chain, "RGarlicKeyAndTag")
		copy(keys.GarlicTag[:], chain[:len(keys.GarlicTag)])
		keys.HasGarlicKeys = true
	} else {
		keys.IVKey = chain
	}
	keys.Hash = hash
	return keys
}

func tunnelKDF(salt [32]byte, info string) ([32]byte, [32]byte) {
	prk := shortBuildHMAC(salt, nil, "", 0)
	first := shortBuildHMAC(prk, nil, info, 1)
	second := shortBuildHMAC(prk, &first, info, 2)
	clear(prk[:])
	return first, second
}

// shortBuildHMAC specializes HMAC-SHA256 for the bounded HKDF inputs above.
// Keeping the pads and both hash messages on the stack avoids making tunnel
// construction retain dozens of short-lived hash.Hash objects per hop.
func shortBuildHMAC(key [32]byte, prefix *[32]byte, info string, counter byte) [32]byte {
	var inner [128]byte
	for i := range sha256.BlockSize {
		inner[i] = 0x36
	}
	for i := range key {
		inner[i] ^= key[i]
	}
	offset := sha256.BlockSize
	if prefix != nil {
		copy(inner[offset:], prefix[:])
		offset += len(prefix)
	}
	copy(inner[offset:], info)
	offset += len(info)
	if counter != 0 {
		inner[offset] = counter
		offset++
	}
	innerHash := sha256.Sum256(inner[:offset])

	var outer [sha256.BlockSize + sha256.Size]byte
	for i := range sha256.BlockSize {
		outer[i] = 0x5c
	}
	for i := range key {
		outer[i] ^= key[i]
	}
	copy(outer[sha256.BlockSize:], innerHash[:])
	return sha256.Sum256(outer[:])
}

func shortBuildNonce(index uint8) [cryptography.ChaChaNonceSize]byte {
	var nonce [cryptography.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(index))
	return nonce
}
