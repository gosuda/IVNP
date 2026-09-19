package streamingtunnel

import (
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
)

// deterministicStreamSeed pins local stream IDs and shared-port allocation for
// deterministic simulation. Nil in production: both stay crypto-random.
var deterministicStreamSeed atomic.Pointer[foundation.Hash]
