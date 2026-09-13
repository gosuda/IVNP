// Package node composes the control plane with local client services and owns
// their coordinated startup and shutdown; routing policy stays in controlplane.
package node

import (
	"gosuda.org/ivnp/controlplane"
	noderuntime "gosuda.org/ivnp/node/internal/runtime"
	"gosuda.org/ivnp/state"
)

type (
	// Subsystem.Close releases managed resources; Wait joins all node-owned workers.
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

// NewSubsystem opens encrypted state without starting listeners. Start activates
// transports and enabled client services; it does not wait for tunnel readiness.
func NewSubsystem(configuration state.ConfigurationOperating, options Options) (*Subsystem, error) {
	return noderuntime.New(configuration, options)
}
