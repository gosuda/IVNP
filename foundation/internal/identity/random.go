package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

// randomSource feeds identity key and certificate generation. Production
// reads from crypto/rand; deterministic-test builds can pin a reproducible
// stream so simulated fleets keep a fixed topology per seed.
var randomSource io.Reader = rand.Reader

// ed25519KeyPair derives a signing keypair from a fixed-size seed read.
// GenerateKey is avoided because stdlib key generation may read an extra
// byte nondeterministically (randutil.MaybeReadByte), which would desync a
// seeded stream.
func ed25519KeyPair(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var seed [ed25519.SeedSize]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, nil, err
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	clear(seed[:])
	return private.Public().(ed25519.PublicKey), private, nil
}

// x25519Key derives an encryption keypair from a fixed-size private-key read
// for the same reason as ed25519KeyPair.
func x25519Key(r io.Reader) (*ecdh.PrivateKey, error) {
	var raw [32]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return nil, err
	}
	defer clear(raw[:])
	return ecdh.X25519().NewPrivateKey(raw[:])
}
