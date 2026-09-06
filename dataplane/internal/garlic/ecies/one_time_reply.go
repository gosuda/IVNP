package garlicecies

import (
	"bytes"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

const (
	oneTimeReplyTagLen       = 8
	oneTimeReplyCloveBlock   = 0x0b
	oneTimeReplyPaddingBlock = 0xfe
	oneTimeReplyCloveHeader  = 10 // LOCAL instruction and ECIES transport I2NP header
	oneTimeReplyBlockHeader  = 3
	oneTimeReplyAEADOverhead = cryptography.ChaChaTagSize
	// An I2NP Garlic payload has a four-byte encrypted-data length before the
	// tag-prefixed Existing Session ciphertext.
	maxOneTimeReplyPlaintext = foundation.I2NPI2PDMaxPayload - 4 - oneTimeReplyTagLen - oneTimeReplyAEADOverhead
)

var ErrOneTimeReplyExistingSession = errors.New("garlic/ecies: invalid one-time existing-session reply")

// SealOneTimeReplyExistingSession encodes an authenticated one-time ECIES
// Existing Session reply using the explicit key and tag supplied by a tunnel
// builder or encrypted DatabaseLookup requester. dst receives the clear tag,
// ChaCha20-Poly1305 ciphertext, and authenticator. The zero nonce and clear tag
// as associated data are the I2P one-time reply-key wire contract.
func SealOneTimeReplyExistingSession(dst []byte, key [cryptography.ChaChaKeySize]byte, tag [oneTimeReplyTagLen]byte, reply foundation.I2NPMessage, padding []byte) ([]byte, error) {
	if err := validateOneTimeReply(reply); err != nil {
		return nil, err
	}
	expiration, ok := foundation.I2NPEncodeTransportExpiration(reply.Header.Expiration)
	if !ok || reply.Header.Expiration < 1000 {
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
	binary.BigEndian.PutUint32(plaintext[9:13], expiration)
	copy(plaintext[13:13+len(reply.Payload)], reply.Payload)
	if len(padding) != 0 {
		off := oneTimeReplyBlockHeader + cloveLen
		plaintext[off] = oneTimeReplyPaddingBlock
		binary.BigEndian.PutUint16(plaintext[off+1:off+3], uint16(len(padding)))
		copy(plaintext[off+3:], padding)
	}

	cipher, err := cryptography.NewChaCha20Poly1305(key[:])
	if err != nil {
		return nil, err
	}
	defer cipher.ReleaseSensitive()
	copy(dst[:oneTimeReplyTagLen], tag[:])
	var nonce [cryptography.ChaChaNonceSize]byte
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
func OpenOneTimeReplyExistingSession(dst []byte, key [cryptography.ChaChaKeySize]byte, tag [oneTimeReplyTagLen]byte, encrypted []byte) (foundation.I2NPMessage, error) {
	if len(encrypted) < oneTimeReplyTagLen+oneTimeReplyAEADOverhead || len(encrypted) > oneTimeReplyTagLen+maxOneTimeReplyPlaintext+oneTimeReplyAEADOverhead {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	if !bytes.Equal(encrypted[:oneTimeReplyTagLen], tag[:]) {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	ciphertext := encrypted[oneTimeReplyTagLen:]
	if len(dst) < len(ciphertext)-oneTimeReplyAEADOverhead {
		return foundation.I2NPMessage{}, wire.ErrShortBuffer
	}
	cipher, err := cryptography.NewChaCha20Poly1305(key[:])
	if err != nil {
		return foundation.I2NPMessage{}, err
	}
	defer cipher.ReleaseSensitive()
	var nonce [cryptography.ChaChaNonceSize]byte
	plaintext, err := cipher.OpenTo(dst[:len(ciphertext)-oneTimeReplyAEADOverhead], nonce[:], ciphertext, tag[:])
	if err != nil {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	return parseOneTimeReplyExistingSession(plaintext)
}

func parseOneTimeReplyExistingSession(plaintext []byte) (foundation.I2NPMessage, error) {
	if len(plaintext) < oneTimeReplyBlockHeader+oneTimeReplyCloveHeader || plaintext[0] != oneTimeReplyCloveBlock {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	cloveLen := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if cloveLen < oneTimeReplyCloveHeader || cloveLen > len(plaintext)-oneTimeReplyBlockHeader {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	clove := plaintext[oneTimeReplyBlockHeader : oneTimeReplyBlockHeader+cloveLen]
	if clove[0] != 0 {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	reply := foundation.I2NPMessage{
		Header: foundation.I2NPHeader{
			Type:       foundation.I2NPMessageType(clove[1]),
			ID:         binary.BigEndian.Uint32(clove[2:6]),
			Expiration: foundation.I2NPDecodeTransportExpiration(binary.BigEndian.Uint32(clove[6:10])),
		},
		Payload: clove[oneTimeReplyCloveHeader:],
	}
	if err := validateOneTimeReply(reply); err != nil {
		return foundation.I2NPMessage{}, err
	}
	rest := plaintext[oneTimeReplyBlockHeader+cloveLen:]
	if len(rest) == 0 {
		return reply, nil
	}
	if len(rest) < oneTimeReplyBlockHeader || rest[0] != oneTimeReplyPaddingBlock || int(binary.BigEndian.Uint16(rest[1:3])) != len(rest)-oneTimeReplyBlockHeader {
		return foundation.I2NPMessage{}, ErrOneTimeReplyExistingSession
	}
	return reply, nil
}

func validateOneTimeReply(reply foundation.I2NPMessage) error {
	if reply.Header.Expiration == 0 || len(reply.Payload) > foundation.I2NPI2PDMaxPayload {
		return ErrOneTimeReplyExistingSession
	}
	switch reply.Header.Type {
	case foundation.I2NPOutboundTunnelBuildReply, foundation.I2NPDatabaseStore, foundation.I2NPDatabaseSearchReply:
	default:
		return ErrOneTimeReplyExistingSession
	}
	if err := foundation.I2NPValidatePayload(reply.Header.Type, reply.Payload); err != nil {
		return ErrOneTimeReplyExistingSession
	}
	return nil
}

const uint16Max = int(^uint16(0))
