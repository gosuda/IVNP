//go:build dst || synctest

package tunnel

import (
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicBuildSeed pins build-message deadline fuzz to a
// seed-derived per-build value so simulated fleets replay identical build
// expiry. Nil restores crypto randomness. Call before creating routers.
func SetDeterministicBuildSeed(seed *foundation.Hash) {
	deterministicBuildSeed.Store(seed)
}
