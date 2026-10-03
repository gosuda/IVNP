//go:build dst || synctest

package simnet

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
)

// PinSessionEntropy points the crypto/rand global reader at a seeded ChaCha8
// stream, so transport handshake key generation (X25519 ephemerals, tokens,
// padding) replays identically per seed. Those draws otherwise read the OS
// entropy source — a real syscall inside the bubble whose completion timing
// decides same-instant wakeup order, which no simulation seed can pin. The
// returned function restores the previous reader.
//
// This mutates process-global state; call it from the test entry point (or a
// per-test helper that restores on cleanup), never from production code.
func PinSessionEntropy(seed uint64) (restore func()) {
	previous := cryptorand.Reader
	var raw [32]byte
	binary.LittleEndian.PutUint64(raw[:8], seed)
	cryptorand.Reader = rand.NewChaCha8(raw)
	return func() { cryptorand.Reader = previous }
}

// SessionEntropySeed resolves the session-entropy seed from DST_SEED or
// IVNP_DST_SEED, falling back to fallback when neither is set. An unparsable
// value is an error rather than a silent fallback.
func SessionEntropySeed(fallback uint64) (uint64, error) {
	env, name := os.Getenv("DST_SEED"), "DST_SEED"
	if env == "" {
		env, name = os.Getenv("IVNP_DST_SEED"), "IVNP_DST_SEED"
	}
	if env == "" {
		return fallback, nil
	}
	seed, err := strconv.ParseUint(env, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q: %w", name, env, err)
	}
	return seed, nil
}
