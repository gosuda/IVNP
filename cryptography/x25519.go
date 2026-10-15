package cryptography

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
)

var ErrLowOrderPoint = errors.New("cryptx: X25519 low-order point")

// X25519PrivateKey holds an X25519 private key scalar.
// Scalar operations run directly on fixed-size arrays so that sensitive
// material is never copied into opaque heap-allocated structs.
type X25519PrivateKey struct {
	scalar   [32]byte
	public   [32]byte
	released bool
}

var _ Sensitive = (*X25519PrivateKey)(nil)

// NewX25519PrivateKey validates and creates a new private key holder from encoded bytes.
func NewX25519PrivateKey(encoded []byte) (*X25519PrivateKey, error) {
	if len(encoded) != 32 {
		return nil, ErrKeyLength
	}
	key := new(X25519PrivateKey)
	copy(key.scalar[:], encoded)
	x25519ScalarMult(&key.public, &key.scalar, &fieldBasepoint)
	return key, nil
}

// GenerateX25519PrivateKey generates a new random X25519 private key using the given random source.
func GenerateX25519PrivateKey(random io.Reader) (*X25519PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	key := new(X25519PrivateKey)
	if _, err := io.ReadFull(random, key.scalar[:]); err != nil {
		clear(key.scalar[:])
		return nil, err
	}
	x25519ScalarMult(&key.public, &key.scalar, &fieldBasepoint)
	return key, nil
}

// PublicKey writes the 32-byte public key into dst.
func (k *X25519PrivateKey) PublicKey(dst *[32]byte) error {
	if k == nil || k.released {
		clear(dst[:])
		return ErrSensitiveReleased
	}
	*dst = k.public
	return nil
}

// ECDH computes the Diffie-Hellman shared secret with peer and writes it into dst.
func (k *X25519PrivateKey) ECDH(dst *[32]byte, peer []byte) error {
	if k == nil || k.released {
		clear(dst[:])
		return ErrSensitiveReleased
	}
	if len(peer) != 32 {
		clear(dst[:])
		return ErrKeyLength
	}
	var peerPoint, zero [32]byte
	copy(peerPoint[:], peer)
	x25519ScalarMult(dst, &k.scalar, &peerPoint)
	if subtle.ConstantTimeCompare(dst[:], zero[:]) == 1 {
		clear(dst[:])
		return ErrLowOrderPoint
	}
	return nil
}

// ReleaseSensitive zeroes the private key scalar and marks the key as released.
func (k *X25519PrivateKey) ReleaseSensitive() {
	if k == nil || k.released {
		return
	}
	clear(k.scalar[:])
	clear(k.public[:])
	k.released = true
}
