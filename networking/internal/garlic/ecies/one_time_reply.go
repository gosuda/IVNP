package ecies

import (
	"bytes"
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/i2np"
)

const (
	oneTimeReplyTagLen       = 8
	oneTimeReplyCloveBlock   = 0x0b
	oneTimeReplyPaddingBlock = 0xfe
	oneTimeReplyCloveHeader  = 10 // LOCAL instruction and ECIES transport I2NP header
	oneTimeReplyBlockHeader  = 3
	oneTimeReplyAEADOverhead = cryptx.ChaChaTagSize
	// An I2NP Garlic payload has a four-byte encrypted-data length before the
	// tag-prefixed Existing Session ciphertext.
	maxOneTimeReplyPlaintext = i2np.I2PDMaxPayload - 4 - oneTimeReplyTagLen - oneTimeReplyAEADOverhead
)

var ErrOneTimeReplyExistingSession = errors.New("garlic/ecies: invalid one-time existing-session reply")

// SealOneTimeReplyExistingSession encodes an authenticated one-time ECIES
// Existing Session reply using the explicit key and tag supplied by a tunnel
// builder or encrypted DatabaseLookup requester. dst receives the clear tag,
// ChaCha20-Poly1305 ciphertext, and authenticator. The zero nonce and clear tag
// as associated data are the I2P one-time reply-key wire contract.
func SealOneTimeReplyExistingSession(dst []byte, key [cryptx.ChaChaKeySize]byte, tag [oneTimeReplyTagLen]byte, reply i2np.Message, padding []byte) ([]byte, error) {
	if err := validateOneTimeReply(reply); err != nil {
		return nil, err
	}
	if reply.Header.Expiration < 1000 || reply.Header.Expiration/1000 > uint64(^uint32(0)) {
		return nil, ErrOneTimeReplyExistingSession
	}
	cloveLen := oneTimeReplyCloveHeader + len(reply.Payload)
	if cloveLen > uint16Max || len(padding) > uint16Max {
		return nil, ErrOneTimeReplyExistingSession
	}
	plainLen := oneTimeReplyBlockHeader + cloveLen
	if len(padding) != 0 {
		plainLen += oneTimeReplyBlockHeader + len(padding)
	}
	if plainLen > maxOneTimeReplyPlaintext {
		return nil, ErrOneTimeReplyExistingSession
	}
	if len(dst) < oneTimeReplyTagLen+plainLen+oneTimeReplyAEADOverhead {
		return nil, wire.ErrShortBuffer
	}

	plaintext := dst[oneTimeReplyTagLen : oneTimeReplyTagLen+plainLen]
	plaintext[0] = oneTimeReplyCloveBlock
	binary.BigEndian.PutUint16(plaintext[1:3], uint16(cloveLen))
	plaintext[3] = 0 // LOCAL delivery instruction
	plaintext[4] = byte(reply.Header.Type)
	binary.BigEndian.PutUint32(plaintext[5:9], reply.Header.ID)
	binary.BigEndian.PutUint32(plaintext[9:13], uint32(reply.Header.Expiration/1000))
	copy(plaintext[13:13+len(reply.Payload)], reply.Payload)
	if len(padding) != 0 {
		off := oneTimeReplyBlockHeader + cloveLen
		plaintext[off] = oneTimeReplyPaddingBlock
		binary.BigEndian.PutUint16(plaintext[off+1:off+3], uint16(len(padding)))
		copy(plaintext[off+3:], padding)
	}

	cipher, err := cryptx.NewChaCha20Poly1305(key[:])
	if err != nil {
		return nil, err
	}
	defer cipher.ReleaseSensitive()
	copy(dst[:oneTimeReplyTagLen], tag[:])
	var nonce [cryptx.ChaChaNonceSize]byte
	sealed, err := cipher.SealTo(dst[oneTimeReplyTagLen:oneTimeReplyTagLen+plainLen+oneTimeReplyAEADOverhead], nonce[:], plaintext, tag[:])
	if err != nil {
		return nil, err
	}
	return dst[:oneTimeReplyTagLen+len(sealed)], nil
}

// OpenOneTimeReplyExistingSession authenticates and strictly decodes an I2P
// one-time ECIES reply. The caller must consume the supplied tag before calling
// so an authentication failure cannot make it reusable. The returned payload
// aliases dst.
func OpenOneTimeReplyExistingSession(dst []byte, key [cryptx.ChaChaKeySize]byte, tag [oneTimeReplyTagLen]byte, encrypted []byte) (i2np.Message, error) {
	if len(encrypted) < oneTimeReplyTagLen+oneTimeReplyAEADOverhead || len(encrypted) > oneTimeReplyTagLen+maxOneTimeReplyPlaintext+oneTimeReplyAEADOverhead {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	if !bytes.Equal(encrypted[:oneTimeReplyTagLen], tag[:]) {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	ciphertext := encrypted[oneTimeReplyTagLen:]
	if len(dst) < len(ciphertext)-oneTimeReplyAEADOverhead {
		return i2np.Message{}, wire.ErrShortBuffer
	}
	cipher, err := cryptx.NewChaCha20Poly1305(key[:])
	if err != nil {
		return i2np.Message{}, err
	}
	defer cipher.ReleaseSensitive()
	var nonce [cryptx.ChaChaNonceSize]byte
	plaintext, err := cipher.OpenTo(dst[:len(ciphertext)-oneTimeReplyAEADOverhead], nonce[:], ciphertext, tag[:])
	if err != nil {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	return parseOneTimeReplyExistingSession(plaintext)
}

func parseOneTimeReplyExistingSession(plaintext []byte) (i2np.Message, error) {
	if len(plaintext) < oneTimeReplyBlockHeader+oneTimeReplyCloveHeader || plaintext[0] != oneTimeReplyCloveBlock {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	cloveLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if cloveLen < oneTimeReplyCloveHeader || cloveLen > len(plaintext)-oneTimeReplyBlockHeader {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	clove := plaintext[oneTimeReplyBlockHeader : oneTimeReplyBlockHeader+cloveLen]
	if clove[0] != 0 {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	reply := i2np.Message{
		Header: i2np.Header{
			Type:       i2np.MessageType(clove[1]),
			ID:         binary.BigEndian.Uint32(clove[2:6]),
			Expiration: uint64(binary.BigEndian.Uint32(clove[6:10])) * 1000,
		},
		Payload: clove[oneTimeReplyCloveHeader:],
	}
	if err := validateOneTimeReply(reply); err != nil {
		return i2np.Message{}, err
	}
	rest := plaintext[oneTimeReplyBlockHeader+cloveLen:]
	if len(rest) == 0 {
		return reply, nil
	}
	if len(rest) < oneTimeReplyBlockHeader || rest[0] != oneTimeReplyPaddingBlock || int(binary.BigEndian.Uint16(rest[1:3])) != len(rest)-oneTimeReplyBlockHeader {
		return i2np.Message{}, ErrOneTimeReplyExistingSession
	}
	return reply, nil
}

func validateOneTimeReply(reply i2np.Message) error {
	if reply.Header.Expiration == 0 || len(reply.Payload) > i2np.I2PDMaxPayload {
		return ErrOneTimeReplyExistingSession
	}
	switch reply.Header.Type {
	case i2np.OutboundTunnelBuildReply, i2np.DatabaseStore, i2np.DatabaseSearchReply:
	default:
		return ErrOneTimeReplyExistingSession
	}
	if err := i2np.ValidatePayload(reply.Header.Type, reply.Payload); err != nil {
		return ErrOneTimeReplyExistingSession
	}
	return nil
}

const uint16Max = int(^uint16(0))
