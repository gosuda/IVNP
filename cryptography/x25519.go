package cryptography

import (
	"crypto/ecdh"
	"io"
)

// X25519PrivateKey owns an X25519 scalar. The standard-library key is built
// only for an individual operation so no opaque key object outlives this owner.
type X25519PrivateKey struct {
	scalar   [32]byte
	released bool
}

var _ Sensitive = (*X25519PrivateKey)(nil)

// NewX25519PrivateKey validates and copies encoded into a new owner.
func NewX25519PrivateKey(encoded []byte) (*X25519PrivateKey, error) {
	if len(encoded) != 32 {
		return nil, ErrKeyLength
	}
	if _, err := ecdh.X25519().NewPrivateKey(encoded); err != nil {
		return nil, err
	}
	key := new(X25519PrivateKey)
	copy(key.scalar[:], encoded)
	return key, nil
}

// GenerateX25519PrivateKey creates a new scalar using random.
func GenerateX25519PrivateKey(random io.Reader) (*X25519PrivateKey, error) {
	private, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, err
	}
	key := new(X25519PrivateKey)
	copy(key.scalar[:], private.Bytes())
	return key, nil
}

func (k *X25519PrivateKey) privateKey() (*ecdh.PrivateKey, error) {
	if k == nil || k.released {
		return nil, ErrSensitiveReleased
	}
	return ecdh.X25519().NewPrivateKey(k.scalar[:])
}

// PublicKey writes the encoded public key into dst.
func (k *X25519PrivateKey) PublicKey(dst *[32]byte) error {
	private, err := k.privateKey()
	if err != nil {
		clear(dst[:])
		return err
	}
	copy(dst[:], private.PublicKey().Bytes())
	return nil
}

// ECDH writes the shared secret with peer into dst. dst is cleared on error.
func (k *X25519PrivateKey) ECDH(dst *[32]byte, peer []byte) error {
	private, err := k.privateKey()
	if err != nil {
		clear(dst[:])
		return err
	}
	public, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		clear(dst[:])
		return err
	}
	secret, err := private.ECDH(public)
	if err != nil {
		clear(dst[:])
		return err
	}
	copy(dst[:], secret)
	clear(secret)
	return nil
}

// ReleaseSensitive overwrites the retained scalar and prevents future use.
func (k *X25519PrivateKey) ReleaseSensitive() {
	if k == nil || k.released {
		return
	}
	clear(k.scalar[:])
	k.released = true
}
