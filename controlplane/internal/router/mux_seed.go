package router

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// deterministicMuxSeed pins transport-preference streams for deterministic
// simulation. Nil in production: the draw falls back to crypto/rand.
var deterministicMuxSeed atomic.Pointer[foundation.Hash]

type muxRandomStream struct {
	mu sync.Mutex
	// +checklocks:mu
	stream *rand.ChaCha8
}

func (r *muxRandomStream) read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return io.ReadFull(r.stream, b)
}

// newMuxRandom returns the transport-preference draw. A pinned seed yields a
// ChaCha8 stream keyed by (seed, local) so each simulated router replays its
// own preference sequence independent of fleet scheduling order.
func newMuxRandom(local foundation.Hash) func([]byte) (int, error) {
	if seed := deterministicMuxSeed.Load(); seed != nil {
		var input [64]byte
		copy(input[:32], seed[:])
		copy(input[32:64], local[:])
		key := sha256.Sum256(input[:])
		rng := &muxRandomStream{stream: rand.NewChaCha8(key)}
		return rng.read
	}
	return func(b []byte) (int, error) { return io.ReadFull(cryptorand.Reader, b) }
}
