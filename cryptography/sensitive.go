package cryptography

import (
	"errors"
)

// Sensitive is implemented by types holding secret key material that should be
// explicitly zeroed in memory upon release.
type Sensitive interface {
	ReleaseSensitive()
}

// ErrSensitiveReleased is returned when performing an operation on a key
// that has already been released and cleared.
var ErrSensitiveReleased = errors.New("cryptx: sensitive state released")
