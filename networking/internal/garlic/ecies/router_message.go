package ecies

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/transport/noise"
	"io"
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
func SealRouterMessage(dst []byte, remoteStatic []byte, message i2np.Message, now uint64, random io.Reader) ([]byte, error) {
	if len(remoteStatic) != 32 || random == nil || message.Header.Expiration < 1000 || message.Header.Expiration/1000 > uint64(^uint32(0)) || now/1000 > uint64(^uint32(0)) {
		return nil, ErrRouterMessage
	}
	plainLen := 7 + 3 + routerMessageHeader + len(message.Payload)
	if plainLen > i2np.I2PDMaxPayload || len(dst) < 32+plainLen+cryptx.ChaChaTagSize {
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
	binary.BigEndian.PutUint32(plain[off+6:off+10], uint32(message.Header.Expiration/1000))
	copy(plain[off+10:], message.Payload)
	sealed, err := state.EncryptAndHash(dst[32:32+plainLen+cryptx.ChaChaTagSize], plain)
	if err != nil {
		return nil, err
	}
	return dst[:32+len(sealed)], nil
}

// OpenRouterMessage authenticates one anonymous Noise-N packet and returns its
// single LOCAL I2NP clove. dst owns the returned payload.
func OpenRouterMessage(dst, staticPrivate, encrypted []byte, now uint64) (i2np.Message, error) {
	if len(staticPrivate) != 32 || len(encrypted) < 32+cryptx.ChaChaTagSize+7+3+routerMessageHeader {
		return i2np.Message{}, ErrRouterMessage
	}
	curve := ecdh.X25519()
	private, err := curve.NewPrivateKey(staticPrivate)
	if err != nil {
		return i2np.Message{}, ErrRouterMessage
	}
	ephemeral, err := curve.NewPublicKey(encrypted[:32])
	if err != nil {
		return i2np.Message{}, ErrRouterMessage
	}
	state := initializeRouterMessage(private.PublicKey().Bytes(), encrypted[:32])
	defer state.ReleaseSensitive()
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return i2np.Message{}, ErrRouterMessage
	}
	defer clear(shared)
	if err = state.MixKey(shared); err != nil {
		return i2np.Message{}, err
	}
	plainLen := len(encrypted) - 32 - cryptx.ChaChaTagSize
	if len(dst) < plainLen {
		return i2np.Message{}, wire.ErrShortBuffer
	}
	plain, err := state.DecryptAndHash(dst[:plainLen], encrypted[32:])
	if err != nil || len(plain) < 7+3+routerMessageHeader || plain[0] != routerMessageDateTime || binary.BigEndian.Uint16(plain[1:3]) != 4 {
		return i2np.Message{}, ErrRouterMessage
	}
	stamp := uint64(binary.BigEndian.Uint32(plain[3:7])) * 1000
	if stamp > now+routerMessageMaxSkew || now > stamp+routerMessageMaxSkew {
		return i2np.Message{}, ErrRouterMessage
	}
	off := 7
	if plain[off] != routerMessageClove {
		return i2np.Message{}, ErrRouterMessage
	}
	cloveLen := int(binary.BigEndian.Uint16(plain[off+1 : off+3]))
	off += 3
	if cloveLen != len(plain)-off || cloveLen < routerMessageHeader || plain[off] != 0 {
		return i2np.Message{}, ErrRouterMessage
	}
	message := i2np.Message{Header: i2np.Header{
		Type: i2np.MessageType(plain[off+1]), ID: binary.BigEndian.Uint32(plain[off+2 : off+6]),
		Expiration: uint64(binary.BigEndian.Uint32(plain[off+6:off+10])) * 1000,
	}, Payload: plain[off+10:]}
	if err = i2np.ValidatePayload(message.Header.Type, message.Payload); err != nil {
		return i2np.Message{}, ErrRouterMessage
	}
	return message, nil
}

func initializeRouterMessage(static, ephemeral []byte) *noise.SymmetricState {
	state := noise.Initialize(routerMessageProtocol)
	_ = state.MixHash(nil)
	_ = state.MixHash(static)
	_ = state.MixHash(ephemeral)
	return state
}
