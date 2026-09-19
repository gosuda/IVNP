//go:build dst || synctest

package dataplane

import (
	streamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicSeeds pins the streaming layer's local stream-ID and
// shared-port allocation for deterministic simulation. Nil restores crypto
// randomness.
func SetDeterministicSeeds(streamSeed *foundation.Hash) {
	streamingtunnel.SetDeterministicStreamSeed(streamSeed)
}
