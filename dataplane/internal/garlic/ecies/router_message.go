package garlicecies

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"io"

	"gosuda.org/ivnp/cryptography"
	dataplanenoise "gosuda.org/ivnp/dataplane/internal/transport/noise"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

const (
	routerMessageProtocol = "Noise_N_25519_ChaChaPoly_SHA256"
	routerMessageDateTime = 0
	routerMessageClove    = 11
	routerMessageHeader   = 10
	routerMessageMaxSkew  = 5 * 60_000
)

var ErrRouterMessage = errors.New("garlic/ecies: invalid router message")

// SealRouterMessage creates the anonymous Noise-N Garlic packet used for
// router-to-router messages. The plaintext contains one DateTime block and one
// LOCAL Garlic Clove carrying the supplied I2NP message.
func SealRouterMessage(dst []byte, remoteStatic []byte, message foundation.I2NPMessage, now uint64, random io.Reader) ([]byte, error) {
	if len(remoteStatic) != 32 || random == nil || message.Header.Expiration < 1000 || now/1000 > uint64(^uint32(0)) {
		return nil, ErrRouterMessage
	}
	expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		return nil, ErrRouterMessage
	}
	plainLen := 7 + 3 + routerMessageHeader + len(message.Payload)
	if plainLen > foundation.I2NPI2PDMaxPayload || len(dst) < 32+plainLen+cryptography.ChaChaTagSize {
		return nil, wire.ErrShortBuffer
	}
	curve := ecdh.X25519()
	remote, err := curve.NewPublicKey(remoteStatic)
	if err != nil {
		return nil, ErrRouterMessage
	}
	ephemeral, err := curve.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	copy(dst[:32], ephemeral.PublicKey().Bytes())
	state := initializeRouterMessage(remoteStatic, dst[:32])
	defer state.ReleaseSensitive()
	shared, err := ephemeral.ECDH(remote)
	if err != nil {
		return nil, ErrRouterMessage
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return nil, err
	}
	plain := dst[32 : 32+plainLen]
	plain[0] = routerMessageDateTime
	binary.BigEndian.PutUint16(plain[1:3], 4)
	binary.BigEndian.PutUint32(plain[3:7], uint32(now/1000))
	off := 7
	plain[off] = routerMessageClove
	binary.BigEndian.PutUint16(plain[off+1:off+3], uint16(routerMessageHeader+len(message.Payload)))
	off += 3
	plain[off] = 0
	plain[off+1] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(plain[off+2:off+6], message.Header.ID)
	binary.BigEndian.PutUint32(plain[off+6:off+10], expiration)
	copy(plain[off+10:], message.Payload)
	sealed, err := state.EncryptAndHash(dst[32:32+plainLen+cryptography.ChaChaTagSize], plain)
	if err != nil {
		return nil, err
	}
	return dst[:32+len(sealed)], nil
}

// OpenRouterMessage authenticates one anonymous Noise-N packet and returns its
// single LOCAL I2NP clove. dst owns the returned payload.
func OpenRouterMessage(dst, staticPrivate, encrypted []byte, now uint64) (foundation.I2NPMessage, error) {
	if len(staticPrivate) != 32 || len(encrypted) < 32+cryptography.ChaChaTagSize+7+3+routerMessageHeader {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	curve := ecdh.X25519()
	private, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	ephemeral, err := curve.NewPublicKey(encrypted[:32])
	if err != nil {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	state := initializeRouterMessage(private.PublicKey().Bytes(), encrypted[:32])
	defer state.ReleaseSensitive()
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return foundation.I2NPMessage{}, err
	}
	plainLen := len(encrypted) - 32 - cryptography.ChaChaTagSize
	if len(dst) < plainLen {
		return foundation.I2NPMessage{}, wire.ErrShortBuffer
	}
	plain, err := state.DecryptAndHash(dst[:plainLen], encrypted[32:])
	if err != nil || len(plain) < 7+3+routerMessageHeader || plain[0] != routerMessageDateTime || binary.BigEndian.Uint16(plain[1:3]) != 4 {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	stamp := uint64(binary.BigEndian.Uint32(plain[3:7])) * 1000
	if stamp > now+routerMessageMaxSkew || now > stamp+routerMessageMaxSkew {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	off := 7
	if plain[off] != routerMessageClove {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	cloveLen := int(binary.BigEndian.Uint16(plain[off+1 : off+3]))
	off += 3
	if cloveLen != len(plain)-off || cloveLen < routerMessageHeader || plain[off] != 0 {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{
		Type: foundation.I2NPMessageType(plain[off+1]), ID: binary.BigEndian.Uint32(plain[off+2 : off+6]),
		Expiration: foundation.I2NPDecodeTransportExpiration(binary.BigEndian.Uint32(plain[off+6 : off+10])),
	}, Payload: plain[off+10:]}
	if err = foundation.I2NPValidatePayload(message.Header.Type, message.Payload); err != nil {
		return foundation.I2NPMessage{}, ErrRouterMessage
	}
	return message, nil
}

func initializeRouterMessage(static, ephemeral []byte) *dataplanenoise.SymmetricState {
	state := dataplanenoise.Initialize(routerMessageProtocol)
	_ = state.MixHash(nil)
	_ = state.MixHash(static)
	_ = state.MixHash(ephemeral)
	return state
}
