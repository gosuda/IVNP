package tunnel

import (
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// deterministicSeed pins pool selection keys for deterministic simulation.
// Nil in production: pool keys fall back to crypto/rand so real deployments
// keep per-boot entropy.
var deterministicSeed atomic.Pointer[foundation.Hash]

func deterministicSelectionSeed() *foundation.Hash { return deterministicSeed.Load() }
