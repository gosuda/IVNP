// Package node composes the control plane with local client services and owns
// their coordinated startup and shutdown; routing policy stays in controlplane.
package node

import (
	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/node/internal/overlaybridge"
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

	// OverlaySpec composes the node's overlay host: the native context plus
	// each named IVNP fabric under one realm.
	OverlaySpec = overlaybridge.Spec
	// OverlayFabric is one IVNP network context's configuration.
	OverlayFabric = overlaybridge.FabricSpec
	// OverlayRealm is the membership and policy namespace over bound contexts.
	OverlayRealm = overlaybridge.RealmSpec
	// OverlayPeer is one statically configured fabric member.
	OverlayPeer = overlaybridge.StaticPeer
	// OverlayBridge is the composed overlay host owned by an EmbeddedRouter.
	OverlayBridge = overlaybridge.Bridge
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
