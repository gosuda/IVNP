//go:build dst || synctest

package netdb

import (
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicExplorerSeed pins the explorer's target-noise reader to a
// seed-derived stream so simulated fleets replay identical exploration
// lookups. Nil restores crypto randomness. Call before creating routers.
func SetDeterministicExplorerSeed(seed *foundation.Hash) {
	deterministicExplorerSeedPtr.Store(seed)
}
