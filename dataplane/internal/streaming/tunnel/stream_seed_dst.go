//go:build dst || synctest

package streamingtunnel

import (
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicStreamSeed pins stream ID and shared-port allocation so
// simulated fleets replay identical local identifiers. Nil restores crypto
// randomness. Call before creating routers.
func SetDeterministicStreamSeed(seed *foundation.Hash) {
	deterministicStreamSeed.Store(seed)
}
