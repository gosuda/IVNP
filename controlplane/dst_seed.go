//go:build dst || synctest

package controlplane

import (
	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

// SetDeterministicSeeds pins the tunnel peer-selection keys, the netdb
// explorer's noise stream, and the transport mux's preference draw for
// deterministic simulation. Nil restores crypto randomness for all.
func SetDeterministicSeeds(tunnelSeed, explorerSeed, muxSeed *foundation.Hash) {
	tunnel.SetDeterministicSelectionSeed(tunnelSeed)
	netdb.SetDeterministicExplorerSeed(explorerSeed)
	router.SetDeterministicMuxSeed(muxSeed)
}
