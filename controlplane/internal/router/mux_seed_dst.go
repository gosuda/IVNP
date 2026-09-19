//go:build dst || synctest

package router

import (
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicMuxSeed pins the transport-preference streams to a
// seed-derived value so simulated routers replay identical transport choices.
// Nil restores crypto randomness. Call before creating routers.
func SetDeterministicMuxSeed(seed *foundation.Hash) {
	deterministicMuxSeed.Store(seed)
}
