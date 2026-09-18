//go:build dst || synctest

package identity

import (
	"crypto/rand"
	"io"
)

// SetRandomSource overrides the reader backing identity generation. A nil
// reader restores crypto/rand. Call before creating any identities; the
// reader must be safe for concurrent use.
func SetRandomSource(r io.Reader) {
	if r == nil {
		r = rand.Reader
	}
	randomSource = r
}
