package tunnel

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/crypto/cryptx"
)

// The variable build format is retained for interoperability with routers that
// still use the 528-byte ElGamal and long ECIES tunnel build records.
const (
	VariableBuildRecordSize          = 528
	LegacyBuildRequestPlainSize      = 222
	LongBuildRequestPlainSize        = 464
	LongBuildResponsePlainSize       = 512
	legacyBuildPeerSize              = 16
	legacyBuildEncryptedOffset       = 16
	longBuildEphemeralOffset         = 16
	longBuildCipherOffset            = 48
	legacyBuildGatewayFlag      byte = 1 << 7
	legacyBuildEndpointFlag     byte = 1 << 6
	legacyBuildLifetimeSeconds       = 600
	legacyBuildMaxRecords            = 8
	legacyBuildMinRecords            = 4
)

var (
	ErrLegacyBuildRecord = errors.New("tunnel: invalid legacy build record")
	ErrLegacyBuildKey    = errors.New("tunnel: invalid legacy build key")
)

// VariableBuildKind selects the asymmetric format for one 528-byte record.
// The format is selected per hop, not per message.
type VariableBuildKind uint8

const (
	VariableBuildElGamal VariableBuildKind = iota + 1
	VariableBuildLongECIES
)

// VariableBuildRequest is the common, parsed view of an ElGamal or long ECIES
// request. RequestHours is used by ElGamal; RequestMinutes and LifetimeSeconds
// are used by long ECIES.
type VariableBuildRequest struct {
	ReceiveTunnelID uint32
	NextTunnelID    uint32
	NextRouter      ivnp.Hash
	LayerKey        [32]byte
	IVKey           [32]byte
	ReplyKey        [32]byte
	ReplyIV         [16]byte
	Gateway         bool
	Endpoint        bool
	RequestHours    uint32
	RequestMinutes  uint32
	LifetimeSeconds uint32
	NextMessageID   uint32
}

// VariableBuildKeys are retained by a creator until its reply arrives. The
// explicit reply key/IV always protect other records. ResponseKey/ResponseAD
// are used only for the owning long-ECIES response.
type VariableBuildKeys struct {
	Kind        VariableBuildKind
	LayerKey    [32]byte
	IVKey       [32]byte
	ReplyKey    [32]byte
	ReplyIV     [16]byte
	ResponseKey [32]byte
	ResponseAD  [32]byte
}

// VariableBuildHop describes one participant in a mixed 528-byte path. Exactly
// the key corresponding to Kind is used.
type VariableBuildHop struct {
	Router          ivnp.Hash
	Kind            VariableBuildKind
	ElGamalKey      cryptx.ElGamalPublicKey
	StaticKey       [32]byte
	ReceiveTunnelID uint32
}

// MarshalElGamalBuildRequest encodes the exact 222-byte legacy request. The
// historical local-router-hash field is required on the wire even though a
// transit hop does not consume it.
func MarshalElGamalBuildRequest(dst []byte, request VariableBuildRequest, local ivnp.Hash, random io.Reader) error {
	if len(dst) < LegacyBuildRequestPlainSize || random == nil || !validVariableRequest(request) || request.Gateway && request.Endpoint {
		return ErrLegacyBuildRecord
	}
	clear(dst[:LegacyBuildRequestPlainSize])
	binary.BigEndian.PutUint32(dst[0:4], request.ReceiveTunnelID)
	copy(dst[4:36], local[:])
	binary.BigEndian.PutUint32(dst[36:40], request.NextTunnelID)
	copy(dst[40:72], request.NextRouter[:])
	copy(dst[72:104], request.LayerKey[:])
	copy(dst[104:136], request.IVKey[:])
	copy(dst[136:168], request.ReplyKey[:])
	copy(dst[168:184], request.ReplyIV[:])
	dst[184] = variableBuildFlags(request)
	binary.BigEndian.PutUint32(dst[185:189], request.RequestHours)
	binary.BigEndian.PutUint32(dst[189:193], request.NextMessageID)
	if _, err := io.ReadFull(random, dst[193:LegacyBuildRequestPlainSize]); err != nil {
		clear(dst[:LegacyBuildRequestPlainSize])
		return err
	}
	return nil
}

// MarshalLongECIESBuildRequest encodes the exact 464-byte Noise-N request.
func MarshalLongECIESBuildRequest(dst []byte, request VariableBuildRequest) error {
	if len(dst) < LongBuildRequestPlainSize || !validVariableRequest(request) || request.Gateway && request.Endpoint || request.LifetimeSeconds != legacyBuildLifetimeSeconds {
		return ErrLegacyBuildRecord
	}
	clear(dst[:LongBuildRequestPlainSize])
	binary.BigEndian.PutUint32(dst[0:4], request.ReceiveTunnelID)
	binary.BigEndian.PutUint32(dst[4:8], request.NextTunnelID)
	copy(dst[8:40], request.NextRouter[:])
	copy(dst[40:72], request.LayerKey[:])
	copy(dst[72:104], request.IVKey[:])
	copy(dst[104:136], request.ReplyKey[:])
	copy(dst[136:152], request.ReplyIV[:])
	dst[152] = variableBuildFlags(request)
	binary.BigEndian.PutUint32(dst[156:160], request.RequestMinutes)
	binary.BigEndian.PutUint32(dst[160:164], request.LifetimeSeconds)
	binary.BigEndian.PutUint32(dst[164:168], request.NextMessageID)
	// Empty canonical Mapping at bytes 168-169; the rest is specified zero pad.
	return nil
}

// ParseElGamalBuildRequest validates the fixed fields of a decrypted legacy
// request. The local hash and random padding deliberately remain opaque.
func ParseElGamalBuildRequest(plaintext []byte) (VariableBuildRequest, error) {
	if len(plaintext) != LegacyBuildRequestPlainSize {
		return VariableBuildRequest{}, ErrLegacyBuildRecord
	}
	request := VariableBuildRequest{
		ReceiveTunnelID: binary.BigEndian.Uint32(plaintext[0:4]),
		NextTunnelID:    binary.BigEndian.Uint32(plaintext[36:40]),
		RequestHours:    binary.BigEndian.Uint32(plaintext[185:189]),
		NextMessageID:   binary.BigEndian.Uint32(plaintext[189:193]),
	}
	copy(request.NextRouter[:], plaintext[40:72])
	copy(request.LayerKey[:], plaintext[72:104])
	copy(request.IVKey[:], plaintext[104:136])
	copy(request.ReplyKey[:], plaintext[136:168])
	copy(request.ReplyIV[:], plaintext[168:184])
	if !setVariableFlags(&request, plaintext[184]) || !validVariableRequest(request) {
		return VariableBuildRequest{}, ErrLegacyBuildRecord
	}
	return request, nil
}

// ParseLongECIESBuildRequest validates the fixed fields and reserved flags of
// a long ECIES request. Interoperable Mapping options are bounded to 296 bytes.
func ParseLongECIESBuildRequest(plaintext []byte) (VariableBuildRequest, error) {
	if len(plaintext) != LongBuildRequestPlainSize {
		return VariableBuildRequest{}, ErrLegacyBuildRecord
	}
	request := VariableBuildRequest{
		ReceiveTunnelID: binary.BigEndian.Uint32(plaintext[0:4]),
		NextTunnelID:    binary.BigEndian.Uint32(plaintext[4:8]),
		RequestMinutes:  binary.BigEndian.Uint32(plaintext[156:160]),
		LifetimeSeconds: binary.BigEndian.Uint32(plaintext[160:164]),
		NextMessageID:   binary.BigEndian.Uint32(plaintext[164:168]),
	}
	copy(request.NextRouter[:], plaintext[8:40])
	copy(request.LayerKey[:], plaintext[40:72])
	copy(request.IVKey[:], plaintext[72:104])
	copy(request.ReplyKey[:], plaintext[104:136])
	copy(request.ReplyIV[:], plaintext[136:152])
	if !setVariableFlags(&request, plaintext[152]) || plaintext[153] != 0 || plaintext[154] != 0 || plaintext[155] != 0 || !validVariableRequest(request) || request.LifetimeSeconds != legacyBuildLifetimeSeconds {
		return VariableBuildRequest{}, ErrLegacyBuildRecord
	}
	mapping, used, err := ivnp.ParseMapping(plaintext[168:])
	if err != nil || used > 296 || mapping.EncodedLen() > 296 {
		return VariableBuildRequest{}, ErrLegacyBuildRecord
	}
	return request, nil
}

// EncryptElGamalBuildRequest creates a complete 528-byte legacy record.
func EncryptElGamalBuildRequest(dst []byte, hop ivnp.Hash, public cryptx.ElGamalPublicKey, plaintext []byte) error {
	if len(dst) < VariableBuildRecordSize || len(plaintext) != LegacyBuildRequestPlainSize {
		return ErrLegacyBuildRecord
	}
	var encrypted [cryptx.ElGamalCiphertextSize]byte
	if _, err := cryptx.EncryptElGamal(encrypted[:], public, plaintext); err != nil {
		return err
	}
	copy(dst[:legacyBuildPeerSize], hop[:legacyBuildPeerSize])
	copy(dst[legacyBuildEncryptedOffset:272], encrypted[1:257])
	copy(dst[272:VariableBuildRecordSize], encrypted[258:])
	clear(encrypted[:])
	return nil
}

// DecryptElGamalBuildRequest authenticates and decrypts one legacy record.
func DecryptElGamalBuildRequest(dst, record []byte, local ivnp.Hash, private cryptx.ElGamalPrivateKey) ([]byte, error) {
	if len(dst) < LegacyBuildRequestPlainSize || len(record) != VariableBuildRecordSize || subtle.ConstantTimeCompare(record[:legacyBuildPeerSize], local[:legacyBuildPeerSize]) != 1 {
		return nil, ErrLegacyBuildRecord
	}
	var encrypted [cryptx.ElGamalCiphertextSize]byte
	copy(encrypted[1:257], record[legacyBuildEncryptedOffset:272])
	copy(encrypted[258:], record[272:VariableBuildRecordSize])
	plaintext, err := cryptx.DecryptElGamal(dst[:LegacyBuildRequestPlainSize], private, encrypted[:])
	clear(encrypted[:])
	if err != nil {
		clear(dst[:LegacyBuildRequestPlainSize])
		return nil, ErrLegacyBuildRecord
	}
	return plaintext, nil
}

// EncryptLongECIESBuildRequest creates one long Noise-N record using a fresh
// X25519 ephemeral key and returns the key/AD for its authenticated response.
func EncryptLongECIESBuildRequest(dst []byte, hop ivnp.Hash, static []byte, plaintext []byte) (VariableBuildKeys, error) {
	return encryptLongECIESBuildRequest(dst, hop, static, plaintext, rand.Reader)
}

func encryptLongECIESBuildRequest(dst []byte, hop ivnp.Hash, static, plaintext []byte, random io.Reader) (VariableBuildKeys, error) {
	var keys VariableBuildKeys
	if len(dst) < VariableBuildRecordSize || len(static) != 32 || len(plaintext) != LongBuildRequestPlainSize || random == nil {
		return keys, ErrLegacyBuildRecord
	}
	curve := ecdh.X25519()
	remote, err := curve.NewPublicKey(static)
	if err != nil {
		return keys, ErrLegacyBuildKey
	}
	ephemeral, err := curve.GenerateKey(random)
	if err != nil {
		return keys, err
	}
	copy(dst[:legacyBuildPeerSize], hop[:legacyBuildPeerSize])
	copy(dst[longBuildEphemeralOffset:longBuildCipherOffset], ephemeral.PublicKey().Bytes())
	state := initializeShortBuild(static, ephemeral.PublicKey().Bytes())
	defer state.ReleaseSensitive()
	shared, err := ephemeral.ECDH(remote)
	if err != nil {
		return keys, ErrLegacyBuildKey
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return keys, err
	}
	ciphertext, err := state.EncryptAndHash(dst[longBuildCipherOffset:VariableBuildRecordSize], plaintext)
	if err != nil || len(ciphertext) != LongBuildRequestPlainSize+cryptx.ChaChaTagSize {
		return keys, ErrLegacyBuildRecord
	}
	keys.Kind = VariableBuildLongECIES
	keys.ResponseKey = state.ChainingKey()
	keys.ResponseAD = state.Hash()
	copy(keys.LayerKey[:], plaintext[40:72])
	copy(keys.IVKey[:], plaintext[72:104])
	copy(keys.ReplyKey[:], plaintext[104:136])
	copy(keys.ReplyIV[:], plaintext[136:152])
	return keys, nil
}

// DecryptLongECIESBuildRequest validates and decrypts a long Noise-N request.
func DecryptLongECIESBuildRequest(dst, record []byte, local ivnp.Hash, staticPrivate []byte) ([]byte, VariableBuildKeys, error) {
	var keys VariableBuildKeys
	if len(dst) < LongBuildRequestPlainSize || len(record) != VariableBuildRecordSize || len(staticPrivate) != 32 || subtle.ConstantTimeCompare(record[:legacyBuildPeerSize], local[:legacyBuildPeerSize]) != 1 {
		return nil, keys, ErrLegacyBuildRecord
	}
	curve := ecdh.X25519()
	private, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, keys, ErrLegacyBuildKey
	}
	ephemeral, err := curve.NewPublicKey(record[longBuildEphemeralOffset:longBuildCipherOffset])
	if err != nil || subtle.ConstantTimeCompare(ephemeral.Bytes(), private.PublicKey().Bytes()) == 1 || allZero(ephemeral.Bytes()) {
		return nil, keys, ErrLegacyBuildKey
	}
	state := initializeShortBuild(private.PublicKey().Bytes(), ephemeral.Bytes())
	defer state.ReleaseSensitive()
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, keys, ErrLegacyBuildKey
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, keys, err
	}
	plaintext, err := state.DecryptAndHash(dst[:LongBuildRequestPlainSize], record[longBuildCipherOffset:])
	if err != nil {
		clear(dst[:LongBuildRequestPlainSize])
		return nil, keys, ErrLegacyBuildRecord
	}
	keys.Kind = VariableBuildLongECIES
	keys.ResponseKey = state.ChainingKey()
	keys.ResponseAD = state.Hash()
	copy(keys.LayerKey[:], plaintext[40:72])
	copy(keys.IVKey[:], plaintext[72:104])
	copy(keys.ReplyKey[:], plaintext[104:136])
	copy(keys.ReplyIV[:], plaintext[136:152])
	return plaintext, keys, nil
}

// PreprocessVariableBuildRecords applies the creator-side reverse CBC layers.
// CBC is reset for every record and all transforms use the explicit request
// reply key/IV, including a long ECIES participant.
func PreprocessVariableBuildRecords(records []byte, keys []VariableBuildKeys, positions []uint8) error {
	if !validVariableRecordSet(records, keys, positions) {
		return ErrLegacyBuildRecord
	}
	for later := 1; later < len(keys); later++ {
		record := records[int(positions[later])*VariableBuildRecordSize : (int(positions[later])+1)*VariableBuildRecordSize]
		for earlier := 0; earlier < later; earlier++ {
			cbcVariableDecrypt(record, record, keys[earlier].ReplyKey, keys[earlier].ReplyIV)
		}
	}
	return nil
}

// ProcessVariableBuildRecords consumes the one record addressed to local,
// installs its protected reply, and encrypts every other record with this hop's
// CBC reply key. The caller selects the local identity kind.
func ProcessVariableBuildRecords(records, plaintextDst []byte, local ivnp.Hash, kind VariableBuildKind, staticPrivate []byte, elgamalPrivate cryptx.ElGamalPrivateKey, accept bool, random io.Reader) (VariableBuildRequest, VariableBuildKeys, uint8, error) {
	var keys VariableBuildKeys
	if len(records)%VariableBuildRecordSize != 0 || len(plaintextDst) < LongBuildRequestPlainSize || random == nil {
		return VariableBuildRequest{}, keys, 0, ErrLegacyBuildRecord
	}
	count := len(records) / VariableBuildRecordSize
	if count < 1 || count > legacyBuildMaxRecords {
		return VariableBuildRequest{}, keys, 0, ErrLegacyBuildRecord
	}
	found := -1
	for index := 0; index < count; index++ {
		record := records[index*VariableBuildRecordSize : (index+1)*VariableBuildRecordSize]
		if subtle.ConstantTimeCompare(record[:legacyBuildPeerSize], local[:legacyBuildPeerSize]) == 1 {
			if found >= 0 {
				return VariableBuildRequest{}, keys, 0, ErrLegacyBuildRecord
			}
			found = index
		}
	}
	if found < 0 {
		return VariableBuildRequest{}, keys, 0, ErrLegacyBuildRecord
	}
	slot := uint8(found)
	record := records[found*VariableBuildRecordSize : (found+1)*VariableBuildRecordSize]
	var plaintext []byte
	var err error
	switch kind {
	case VariableBuildElGamal:
		plaintext, err = DecryptElGamalBuildRequest(plaintextDst[:LegacyBuildRequestPlainSize], record, local, elgamalPrivate)
		if err == nil {
			keys.Kind = VariableBuildElGamal
		}
	case VariableBuildLongECIES:
		plaintext, keys, err = DecryptLongECIESBuildRequest(plaintextDst[:LongBuildRequestPlainSize], record, local, staticPrivate)
	default:
		return VariableBuildRequest{}, keys, 0, ErrLegacyBuildRecord
	}
	if err != nil {
		return VariableBuildRequest{}, keys, 0, err
	}
	var request VariableBuildRequest
	if kind == VariableBuildElGamal {
		request, err = ParseElGamalBuildRequest(plaintext)
	} else {
		request, err = ParseLongECIESBuildRequest(plaintext)
	}
	if err != nil {
		clear(plaintextDst[:LongBuildRequestPlainSize])
		return VariableBuildRequest{}, keys, 0, err
	}
	keys.Kind = kind
	keys.LayerKey = request.LayerKey
	keys.IVKey = request.IVKey
	keys.ReplyKey = request.ReplyKey
	keys.ReplyIV = request.ReplyIV
	if err = sealVariableBuildReply(record, keys, random, replyCode(accept)); err != nil {
		clear(plaintextDst[:LongBuildRequestPlainSize])
		return VariableBuildRequest{}, keys, 0, err
	}
	for index := 0; index < count; index++ {
		if index != found {
			other := records[index*VariableBuildRecordSize : (index+1)*VariableBuildRecordSize]
			cbcVariableEncrypt(other, other, keys.ReplyKey, keys.ReplyIV)
		}
	}
	return request, keys, slot, nil
}

// OpenVariableBuildReplies removes later CBC layers then checks each own reply.
// It rejects nonzero status codes and authenticated long-record tampering.
func OpenVariableBuildReplies(replies []byte, keys []VariableBuildKeys, positions []uint8, dst []byte) error {
	if !validVariableRecordSet(replies, keys, positions) || len(dst) < len(keys)*LongBuildResponsePlainSize {
		return ErrLegacyBuildRecord
	}
	for hop, slot := range positions {
		var record [VariableBuildRecordSize]byte
		copy(record[:], replies[int(slot)*VariableBuildRecordSize:(int(slot)+1)*VariableBuildRecordSize])
		for later := hop + 1; later < len(keys); later++ {
			cbcVariableDecrypt(record[:], record[:], keys[later].ReplyKey, keys[later].ReplyIV)
		}
		var code byte
		switch keys[hop].Kind {
		case VariableBuildElGamal:
			cbcVariableDecrypt(record[:], record[:], keys[hop].ReplyKey, keys[hop].ReplyIV)
			digest := sha256.Sum256(record[32:])
			if subtle.ConstantTimeCompare(digest[:], record[:32]) != 1 {
				clear(dst)
				return ErrLegacyBuildRecord
			}
			code = record[VariableBuildRecordSize-1]
		case VariableBuildLongECIES:
			plaintext := dst[hop*LongBuildResponsePlainSize : (hop+1)*LongBuildResponsePlainSize]
			cipher, err := cryptx.NewChaCha20Poly1305(keys[hop].ResponseKey[:])
			if err != nil {
				clear(dst)
				return err
			}
			var nonce [cryptx.ChaChaNonceSize]byte
			if _, err = cipher.OpenTo(plaintext, nonce[:], record[:], keys[hop].ResponseAD[:]); err != nil {
				clear(dst)
				return ErrLegacyBuildRecord
			}
			if plaintext[0] != 0 || plaintext[1] != 0 {
				clear(dst)
				return ErrLegacyBuildRecord
			}
			code = plaintext[LongBuildResponsePlainSize-1]
		default:
			clear(dst)
			return ErrLegacyBuildRecord
		}
		if code != 0 && code != 30 {
			clear(dst)
			return ErrLegacyBuildRecord
		}
	}
	return nil
}

func sealVariableBuildReply(record []byte, keys VariableBuildKeys, random io.Reader, code byte) error {
	if len(record) != VariableBuildRecordSize || random == nil || (code != 0 && code != 30) {
		return ErrLegacyBuildRecord
	}
	switch keys.Kind {
	case VariableBuildElGamal:
		if _, err := io.ReadFull(random, record[32:VariableBuildRecordSize-1]); err != nil {
			return err
		}
		record[VariableBuildRecordSize-1] = code
		digest := sha256.Sum256(record[32:])
		copy(record[:32], digest[:])
		cbcVariableEncrypt(record, record, keys.ReplyKey, keys.ReplyIV)
		return nil
	case VariableBuildLongECIES:
		var plaintext [LongBuildResponsePlainSize]byte
		if _, err := io.ReadFull(random, plaintext[2:LongBuildResponsePlainSize-1]); err != nil {
			return err
		}
		plaintext[LongBuildResponsePlainSize-1] = code
		cipher, err := cryptx.NewChaCha20Poly1305(keys.ResponseKey[:])
		if err != nil {
			return err
		}
		var nonce [cryptx.ChaChaNonceSize]byte
		_, err = cipher.SealTo(record, nonce[:], plaintext[:], keys.ResponseAD[:])
		clear(plaintext[:])
		return err
	default:
		return ErrLegacyBuildRecord
	}
}

func cbcVariableEncrypt(dst, src []byte, key [32]byte, iv [16]byte) {
	block, _ := aes.NewCipher(key[:])
	cbcEncrypt(block, dst[:VariableBuildRecordSize], src[:VariableBuildRecordSize], iv[:])
}
func cbcVariableDecrypt(dst, src []byte, key [32]byte, iv [16]byte) {
	block, _ := aes.NewCipher(key[:])
	cbcDecrypt(block, dst[:VariableBuildRecordSize], src[:VariableBuildRecordSize], iv[:])
}
func validVariableRecordSet(records []byte, keys []VariableBuildKeys, positions []uint8) bool {
	if len(keys) == 0 || len(keys) != len(positions) || len(records)%VariableBuildRecordSize != 0 {
		return false
	}
	count := len(records) / VariableBuildRecordSize
	if count < len(keys) || count > legacyBuildMaxRecords {
		return false
	}
	var used [legacyBuildMaxRecords]bool
	for _, position := range positions {
		if int(position) >= count || used[position] {
			return false
		}
		used[position] = true
	}
	return true
}
func variableBuildFlags(request VariableBuildRequest) byte {
	var flags byte
	if request.Gateway {
		flags |= legacyBuildGatewayFlag
	}
	if request.Endpoint {
		flags |= legacyBuildEndpointFlag
	}
	return flags
}
func setVariableFlags(request *VariableBuildRequest, flags byte) bool {
	if flags & ^(legacyBuildGatewayFlag|legacyBuildEndpointFlag) != 0 || flags&(legacyBuildGatewayFlag|legacyBuildEndpointFlag) == legacyBuildGatewayFlag|legacyBuildEndpointFlag {
		return false
	}
	request.Gateway, request.Endpoint = flags&legacyBuildGatewayFlag != 0, flags&legacyBuildEndpointFlag != 0
	return true
}
func validVariableRequest(request VariableBuildRequest) bool {
	return request.ReceiveTunnelID != 0 && request.NextTunnelID != 0 && request.NextMessageID != 0 && request.NextRouter != (ivnp.Hash{}) && request.ReceiveTunnelID != request.NextTunnelID
}
func allZero(value []byte) bool {
	var accumulator byte
	for _, b := range value {
		accumulator |= b
	}
	return accumulator == 0
}
func replyCode(accept bool) byte {
	if accept {
		return 0
	}
	return 30
}
