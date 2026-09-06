// Package node orchestrates the router runtime, tunnel pools, NetDB, and client services into a runnable node.
package node

import (
	"gosuda.org/ivnp/controlplane"
	noderuntime "gosuda.org/ivnp/node/internal/runtime"
	"gosuda.org/ivnp/state"
)

type (
	Subsystem             = noderuntime.Daemon
	Options               = noderuntime.Options
	Status                = controlplane.Status
	TunnelRuntimeSnapshot = controlplane.TunnelRuntimeSnapshot
	DestinationPolicy     = controlplane.DestinationPolicy
	DestinationPolicyKind = controlplane.DestinationPolicyKind
)

const (
	DestinationPublicLeaseSet2            = controlplane.DestinationPublicLS2
	DestinationEncryptedWithoutAuth       = controlplane.DestinationEncryptedNone
	DestinationEncryptedWithDiffieHellman = controlplane.DestinationEncryptedDH
	DestinationEncryptedWithPreSharedKey  = controlplane.DestinationEncryptedPSK
)

func NewSubsystem(configuration state.ConfigurationOperating, options Options) (*Subsystem, error) {
	return noderuntime.New(configuration, options)
}
