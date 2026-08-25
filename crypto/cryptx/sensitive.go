package cryptx

import "errors"

// Sensitive is implemented by pointer-owned IVNP cryptographic state. ReleaseSensitive
// synchronously overwrites IVNP-owned secret buffers and is safe to call repeatedly.
// It cannot erase transient compiler, standard-library, or x/crypto internals.
type Sensitive interface {
	ReleaseSensitive()
}

// ErrSensitiveReleased is returned when an operation is attempted after its
// sensitive owner has been released.
var ErrSensitiveReleased = errors.New("cryptx: sensitive state released")
