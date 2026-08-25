// ChaCha state wrappers provide allocation-bounded encryption for I2P transports.
package cryptography

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

var (
	ErrKeyLength      = errors.New("cryptx: invalid ChaCha20 key length")
	ErrNonceLength    = errors.New("cryptx: invalid ChaCha20 nonce length")
	ErrDestination    = errors.New("cryptx: destination buffer is too small")
	ErrAuthentication = errors.New("cryptx: ChaCha20 authentication failed")
)

const (
	ChaChaKeySize   = chacha20poly1305.KeySize
	ChaChaNonceSize = chacha20poly1305.NonceSize
	ChaChaTagSize   = chacha20poly1305.Overhead
)

// ChaCha20Poly1305 owns the IVNP copy of its session key. Its x/crypto AEAD is
// retained solely to preserve allocation-free transport framing and is dropped
// on release; Go does not expose a way to overwrite that opaque implementation.
type ChaCha20Poly1305 struct {
	key      [ChaChaKeySize]byte
	aead     cipher.AEAD
	released bool
}

var _ Sensitive = (*ChaCha20Poly1305)(nil)

func NewChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	if len(key) != ChaChaKeySize {
		return nil, ErrKeyLength
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	state := &ChaCha20Poly1305{aead: aead}
	copy(state.key[:], key)
	return state, nil
}

// CopyKey copies this cipher's key into dst. It is deliberately a copy-only
// operation so ownership remains with the cipher; callers deriving a new
// protocol chain must clear their destination when finished.
func (c *ChaCha20Poly1305) CopyKey(dst []byte) error {
	if c == nil || c.released {
		return ErrSensitiveReleased
	}
	if len(dst) < ChaChaKeySize {
		return ErrDestination
	}
	copy(dst[:ChaChaKeySize], c.key[:])
	return nil
}

// SealTo encrypts plaintext into dst. dst must have room for plaintext plus
// the 16-byte tag. The returned view aliases dst and does not allocate.
func (c *ChaCha20Poly1305) SealTo(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if c == nil || c.released {
		return nil, ErrSensitiveReleased
	}
	if len(nonce) != ChaChaNonceSize {
		return nil, ErrNonceLength
	}
	if len(dst) < len(plaintext)+ChaChaTagSize {
		return nil, ErrDestination
	}
	return c.aead.Seal(dst[:0], nonce, plaintext, additionalData), nil
}

// OpenTo authenticates and decrypts ciphertext into dst. dst must have room
// for ciphertext minus the 16-byte tag. Authentication failures leave dst
// unsuitable for use by the caller.
func (c *ChaCha20Poly1305) OpenTo(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if c == nil || c.released {
		return nil, ErrSensitiveReleased
	}
	if len(nonce) != ChaChaNonceSize {
		return nil, ErrNonceLength
	}
	if len(ciphertext) < ChaChaTagSize || len(dst) < len(ciphertext)-ChaChaTagSize {
		return nil, ErrDestination
	}
	return c.aead.Open(dst[:0], nonce, ciphertext, additionalData)
}

// SealChaCha20Poly1305To performs RFC 8439 AEAD framing with caller-owned
// storage and no retained cipher object. It is used for one-time ratchet keys.
func SealChaCha20Poly1305To(dst, key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != ChaChaKeySize {
		return nil, ErrKeyLength
	}
	if len(nonce) != ChaChaNonceSize {
		return nil, ErrNonceLength
	}
	if len(dst) < len(plaintext)+ChaChaTagSize {
		return nil, ErrDestination
	}
	var polyKey [32]byte
	var zero [32]byte
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(polyKey[:], zero[:])
	stream.SetCounter(1)
	ciphertext := dst[:len(plaintext)]
	stream.XORKeyStream(ciphertext, plaintext)
	tag := poly1305Tag(polyKey, additionalData, ciphertext)
	copy(dst[len(plaintext):], tag[:])
	clear(polyKey[:])
	clear(tag[:])
	return dst[:len(plaintext)+ChaChaTagSize], nil
}

// OpenChaCha20Poly1305To authenticates before decrypting and aliases dst.
func OpenChaCha20Poly1305To(dst, key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != ChaChaKeySize {
		return nil, ErrKeyLength
	}
	if len(nonce) != ChaChaNonceSize {
		return nil, ErrNonceLength
	}
	if len(ciphertext) < ChaChaTagSize || len(dst) < len(ciphertext)-ChaChaTagSize {
		return nil, ErrDestination
	}
	body := ciphertext[:len(ciphertext)-ChaChaTagSize]
	var polyKey [32]byte
	var zero [32]byte
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(polyKey[:], zero[:])
	expected := poly1305Tag(polyKey, additionalData, body)
	if subtle.ConstantTimeCompare(expected[:], ciphertext[len(body):]) != 1 {
		clear(polyKey[:])
		clear(expected[:])
		return nil, ErrAuthentication
	}
	stream.SetCounter(1)
	plain := dst[:len(body)]
	stream.XORKeyStream(plain, body)
	clear(polyKey[:])
	clear(expected[:])
	return plain, nil
}

func poly1305Tag(key [32]byte, additionalData, ciphertext []byte) [16]byte {
	mac := poly1305.New(&key)
	_, _ = mac.Write(additionalData)
	if remainder := len(additionalData) & 15; remainder != 0 {
		var padding [16]byte
		_, _ = mac.Write(padding[:16-remainder])
	}
	_, _ = mac.Write(ciphertext)
	if remainder := len(ciphertext) & 15; remainder != 0 {
		var padding [16]byte
		_, _ = mac.Write(padding[:16-remainder])
	}
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(ciphertext)))
	_, _ = mac.Write(lengths[:])
	var tag [16]byte
	copy(tag[:], mac.Sum(tag[:0]))
	return tag
}

// ReleaseSensitive overwrites IVNP-owned session-key storage and drops the
// opaque AEAD reference. It cannot claim erasure inside x/crypto.
func (c *ChaCha20Poly1305) ReleaseSensitive() {
	if c == nil || c.released {
		return
	}
	clear(c.key[:])
	c.aead = nil
	c.released = true
}

// NewChaCha20Stream returns the maintained IETF ChaCha20 stream at I2P's raw
// ChaCha block counter 1. Java I2P and i2pd use counter 1 for SSU2 header
// protection, encrypted LeaseSets, and short-build reply layers.
func NewChaCha20Stream(key, nonce []byte) (*chacha20.Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, ErrKeyLength
	}
	if len(nonce) != chacha20.NonceSize {
		return nil, ErrNonceLength
	}
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err == nil {
		stream.SetCounter(1)
	}
	return stream, err
}
