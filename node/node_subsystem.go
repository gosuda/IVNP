// Package node is the only public entry point for the complete IVNP node runtime.
package node

import (
	noderuntime "gosuda.org/ivnp/node/internal/runtime"
	"gosuda.org/ivnp/state"
)

type (
	Subsystem             = noderuntime.Daemon
	Options               = noderuntime.Options
	Status                = noderuntime.Status
	DestinationPolicy     = noderuntime.DestinationPolicy
	DestinationPolicyKind = noderuntime.DestinationPolicyKind
)

const (
	DestinationPublicLeaseSet2            = noderuntime.DestinationPublicLS2
	DestinationEncryptedWithoutAuth       = noderuntime.DestinationEncryptedNone
	DestinationEncryptedWithDiffieHellman = noderuntime.DestinationEncryptedDH
	DestinationEncryptedWithPreSharedKey  = noderuntime.DestinationEncryptedPSK
)

func NewSubsystem(configuration state.ConfigurationOperating, options Options) (*Subsystem, error) {
	return noderuntime.New(configuration, options)
}
