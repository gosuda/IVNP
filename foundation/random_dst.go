//go:build dst || synctest

package foundation

import (
	"crypto/rand"
	"io"
	"sync"

	"gosuda.org/ivnp/foundation/internal/identity"
)

// SetDeterministicRandomSource pins the reader backing router-identity and
// destination generation, so a deterministic simulation can reproduce the
// same fleet topology per seed. Session- and wire-level cryptography keeps
// drawing from crypto/rand. A nil reader restores the default. Call before
// creating any routers or destinations.
func SetDeterministicRandomSource(r io.Reader) {
	if r == nil {
		r = rand.Reader
	}
	identity.SetRandomSource(&lockedRandomSource{r: r})
}

// lockedRandomSource serializes draws because readers such as
// math/rand/v2.ChaCha8 are not safe for concurrent use.
type lockedRandomSource struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedRandomSource) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}
