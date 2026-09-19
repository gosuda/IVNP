package tunnel

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// deterministicBuildSeed pins build-message deadline fuzz for deterministic
// simulation. Nil in production: deadlines stay crypto-fuzzed.
var deterministicBuildSeed atomic.Pointer[foundation.Hash]

// deterministicDeadlineReader returns a reader whose bytes are
// sha256(seed‖keyMaterial) so one build's deadline fuzz replays identically
// under a fixed simulation seed. Nil when unpinned. Keying on the hop set
// (rather than a shared stream) keeps each build's deadline independent of
// concurrent build scheduling order.
func deterministicDeadlineReader(keyMaterial func(h hash.Hash)) io.Reader {
	seed := deterministicBuildSeed.Load()
	if seed == nil {
		return nil
	}
	h := sha256.New()
	h.Write(seed[:])
	keyMaterial(h)
	return bytes.NewReader(h.Sum(nil))
}
