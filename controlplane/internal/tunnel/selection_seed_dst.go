//go:build dst || synctest

package tunnel

import (
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicSelectionSeed pins tunnel pool selection keys to a
// seed-derived value so simulated fleets reproduce identical tunnel paths.
// Per-build selection targets already derive from the pool key, so pinning
// the key determinizes the whole selection sequence. Nil restores crypto
// randomness. Call before creating routers.
func SetDeterministicSelectionSeed(seed *foundation.Hash) {
	deterministicSeed.Store(seed)
}
