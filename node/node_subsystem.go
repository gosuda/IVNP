// Package node orchestrates the router runtime, tunnel pools, NetDB, and client services into a runnable node.
package node

import (
	noderuntime "gosuda.org/ivnp/node/internal/runtime"
	"gosuda.org/ivnp/state"
)

type (
	Subsystem             = noderuntime.Daemon
	Options               = noderuntime.Options
	Status                = noderuntime.Status
	TunnelRuntimeSnapshot = noderuntime.TunnelRuntimeSnapshot
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
