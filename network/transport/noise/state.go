// Package noise implements the allocation-conscious symmetric state shared by
// the NTCP2 and SSU2 Noise_XK_25519_ChaChaPoly_SHA256 handshakes.
package noise

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math"

	"gosuda.org/ivnp/crypto/cryptx"
	"gosuda.org/ivnp/internal/wire"
)

var ErrNonceExhausted = errors.New("noise: ChaCha nonce exhausted")

// SymmetricState is Noise's chaining-key, handshake-hash, and optional cipher
// state. It is a pointer-owned, single-goroutine handshake object.
type SymmetricState struct {
	chainingKey [32]byte
	hash        [32]byte
	cipher      *cryptx.ChaCha20Poly1305
	hasKey      bool
	nonce       uint64
	released    bool
}

var _ cryptx.Sensitive = (*SymmetricState)(nil)

func Initialize(protocolName string) *SymmetricState {
	state := new(SymmetricState)
	if len(protocolName) <= len(state.hash) {
		copy(state.hash[:], protocolName)
	} else {
		state.hash = sha256.Sum256([]byte(protocolName))
	}
	state.chainingKey = state.hash
	return state
}

func (s *SymmetricState) Hash() [32]byte {
	if s == nil || s.released {
		return [32]byte{}
	}
	return s.hash
}

func (s *SymmetricState) ChainingKey() [32]byte {
	if s == nil || s.released {
		return [32]byte{}
	}
	return s.chainingKey
}

// MixHash binds data to the transcript.
func (s *SymmetricState) MixHash(data []byte) error {
	if s == nil || s.released {
		return cryptx.ErrSensitiveReleased
	}
	h := sha256.New()
	_, _ = h.Write(s.hash[:])
	_, _ = h.Write(data)
	copy(s.hash[:], h.Sum(nil))
	return nil
}

// MixKey derives a new chaining key and transport cipher per Noise HKDF.
func (s *SymmetricState) MixKey(input []byte) error {
	if s == nil || s.released {
		return cryptx.ErrSensitiveReleased
	}
	chain, key := kdf2(s.chainingKey[:], input)
	defer clear(chain[:])
	defer clear(key[:])
	next, err := cryptx.NewChaCha20Poly1305(key[:])
	if err != nil {
		return err
	}
	if s.cipher != nil {
		s.cipher.ReleaseSensitive()
	}
	s.chainingKey = chain
	s.cipher, s.hasKey, s.nonce = next, true, 0
	return nil
}

// EncryptAndHash writes ciphertext into dst and advances the Noise nonce.
func (s *SymmetricState) EncryptAndHash(dst, plaintext []byte) ([]byte, error) {
	if s == nil || s.released {
		return nil, cryptx.ErrSensitiveReleased
	}
	if !s.hasKey {
		if len(dst) < len(plaintext) {
			return nil, wire.ErrShortBuffer
		}
		copy(dst, plaintext)
		if err := s.MixHash(plaintext); err != nil {
			return nil, err
		}
		return dst[:len(plaintext)], nil
	}
	if s.nonce >= math.MaxUint64-1 {
		return nil, ErrNonceExhausted
	}
	var nonce [cryptx.ChaChaNonceSize]byte
	defer clear(nonce[:])
	putNonce(nonce[:], s.nonce)
	ciphertext, err := s.cipher.SealTo(dst, nonce[:], plaintext, s.hash[:])
	if err != nil {
		return nil, err
	}
	if err := s.MixHash(ciphertext); err != nil {
		return nil, err
	}
	s.nonce++
	return ciphertext, nil
}

// DecryptAndHash authenticates ciphertext from the current transcript state.
func (s *SymmetricState) DecryptAndHash(dst, ciphertext []byte) ([]byte, error) {
	if s == nil || s.released {
		return nil, cryptx.ErrSensitiveReleased
	}
	if !s.hasKey {
		if len(dst) < len(ciphertext) {
			return nil, wire.ErrShortBuffer
		}
		copy(dst, ciphertext)
		if err := s.MixHash(ciphertext); err != nil {
			return nil, err
		}
		return dst[:len(ciphertext)], nil
	}
	if s.nonce >= math.MaxUint64-1 {
		return nil, ErrNonceExhausted
	}
	var nonce [cryptx.ChaChaNonceSize]byte
	defer clear(nonce[:])
	putNonce(nonce[:], s.nonce)
	plaintext, err := s.cipher.OpenTo(dst, nonce[:], ciphertext, s.hash[:])
	if err != nil {
		return nil, err
	}
	if err := s.MixHash(ciphertext); err != nil {
		return nil, err
	}
	s.nonce++
	return plaintext, nil
}

// Split derives directional Noise data-phase ciphers in initiator order and
// consumes the handshake state on success.
func (s *SymmetricState) Split() (*cryptx.ChaCha20Poly1305, *cryptx.ChaCha20Poly1305, error) {
	if s == nil || s.released {
		return nil, nil, cryptx.ErrSensitiveReleased
	}
	firstKey, secondKey := kdf2(s.chainingKey[:], nil)
	defer clear(firstKey[:])
	defer clear(secondKey[:])
	first, err := cryptx.NewChaCha20Poly1305(firstKey[:])
	if err != nil {
		return nil, nil, err
	}
	second, err := cryptx.NewChaCha20Poly1305(secondKey[:])
	if err != nil {
		first.ReleaseSensitive()
		return nil, nil, err
	}
	s.ReleaseSensitive()
	return first, second, nil
}

// ReleaseSensitive overwrites all retained IVNP-owned Noise state.
func (s *SymmetricState) ReleaseSensitive() {
	if s == nil || s.released {
		return
	}
	if s.cipher != nil {
		s.cipher.ReleaseSensitive()
		s.cipher = nil
	}
	clear(s.chainingKey[:])
	clear(s.hash[:])
	s.hasKey = false
	s.nonce = 0
	s.released = true
}

func kdf2(key, input []byte) ([32]byte, [32]byte) {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	temporary := mac.Sum(nil)
	defer clear(temporary)
	mac = hmac.New(sha256.New, temporary)
	_, _ = mac.Write([]byte{1})
	firstBytes := mac.Sum(nil)
	defer clear(firstBytes)
	var first [32]byte
	copy(first[:], firstBytes)
	mac = hmac.New(sha256.New, temporary)
	_, _ = mac.Write(first[:])
	_, _ = mac.Write([]byte{2})
	secondBytes := mac.Sum(nil)
	defer clear(secondBytes)
	var second [32]byte
	copy(second[:], secondBytes)
	return first, second
}

func putNonce(dst []byte, value uint64) {
	clear(dst)
	for i := range 8 {
		dst[4+i] = byte(value >> (8 * i))
	}
}
