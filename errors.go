package ivnp

import (
	"errors"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/interfaces/stream"
)

var (
	ErrInvalidConfig             = errors.New("i2p: invalid configuration")
	ErrStateConflict             = controlplane.ErrStateConflict
	ErrDestinationRequired       = errors.New("i2p: destination required")
	ErrIdentityInUse             = errors.New("i2p: identity already in use")
	ErrUnsupportedIdentity       = errors.New("i2p: unsupported identity")
	ErrUnsupportedNetwork        = stream.ErrUnsupportedNetwork
	ErrAddressInvalid            = stream.ErrAddressInvalid
	ErrAddressUnavailable        = stream.ErrAddressUnavailable
	ErrAddressInUse              = stream.ErrAddressInUse
	ErrNoPortsAvailable          = stream.ErrNoPortsAvailable
	ErrNameResolutionUnavailable = errors.New("i2p: name resolution unavailable")
	ErrResourceLimit             = errors.New("i2p: resource limit reached")
	ErrMessageTooLarge           = errors.New("i2p: message too large")
	ErrMessageTruncated          = errors.New("i2p: message truncated")
)

type ConfigError struct {
	Field string
	Err   error
}

func (e *ConfigError) Error() string        { return "i2p: invalid configuration: " + e.Field }
func (e *ConfigError) Unwrap() error        { return e.Err }
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

func invalidConfig(field string) error { return &ConfigError{Field: field, Err: ErrInvalidConfig} }
