package netdb

import (
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// deterministicExplorerSeedPtr pins the explorer's noise reader for
// deterministic simulation. Nil in production: the explorer falls back to
// crypto/rand so real deployments keep fresh exploration entropy.
var deterministicExplorerSeedPtr atomic.Pointer[foundation.Hash]

func deterministicExplorerSeed() *foundation.Hash { return deterministicExplorerSeedPtr.Load() }

// chainedReader yields sha256(seed‖local‖counter) blocks — a deterministic
// byte stream per (seed, local) pair so one router's explorer replays an
// identical exploration sequence under a fixed simulation seed.
type chainedReader struct {
	block   [sha256.Size]byte
	seed    foundation.Hash
	local   foundation.Hash
	counter uint64
	offset  int
}

func newChainedReader(seed, local foundation.Hash) *chainedReader {
	return &chainedReader{seed: seed, local: local, offset: sha256.Size}
}

func (r *chainedReader) Read(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		if r.offset == len(r.block) {
			var input [72]byte
			copy(input[:32], r.seed[:])
			copy(input[32:64], r.local[:])
			binary.BigEndian.PutUint64(input[64:72], r.counter)
			r.counter++
			r.block = sha256.Sum256(input[:])
			r.offset = 0
		}
		copied := copy(p[total:], r.block[r.offset:])
		r.offset += copied
		total += copied
	}
	return total, nil
}
