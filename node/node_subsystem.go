// Package node is the only public entry point for the complete IVNP node runtime.
package node

import (
	runtimeinternal "gosuda.org/ivnp/node/internal/runtime"
	"gosuda.org/ivnp/state"
)

type (
	Subsystem             = runtimeinternal.Daemon
	Options               = runtimeinternal.Options
	Status                = runtimeinternal.Status
	DestinationPolicy     = runtimeinternal.DestinationPolicy
	DestinationPolicyKind = runtimeinternal.DestinationPolicyKind
)

const (
	DestinationPublicLeaseSet2            = runtimeinternal.DestinationPublicLS2
	DestinationEncryptedWithoutAuth       = runtimeinternal.DestinationEncryptedNone
	DestinationEncryptedWithDiffieHellman = runtimeinternal.DestinationEncryptedDH
	DestinationEncryptedWithPreSharedKey  = runtimeinternal.DestinationEncryptedPSK
)

func NewSubsystem(configuration state.ConfigurationOperating, options Options) (*Subsystem, error) {
	return runtimeinternal.New(configuration, options)
}
