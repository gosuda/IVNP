// Package ivnp is the embedding entry point for a router and its client services.
// New opens local state; Start begins network work. Close and Wait release the
// node's resources and join its workers. Start alone does not imply I2P readiness.
package ivnp

import (
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

// Config represents the operating configuration for an IVNP node.
type Config = state.ConfigurationOperating

// LogConfig represents the logging backend configuration.
type LogConfig = state.ConfigurationLog

// LoadConfig reads and validates an operating configuration from path.
func LoadConfig(path string) (Config, error) { return state.ConfigurationLoadOperating(path) }

// LoadOrCreateConfig writes production defaults when absent. Review enabled
// listeners before starting a node with the returned configuration.
func LoadOrCreateConfig(path string) (Config, error) {
	return state.ConfigurationLoadOrCreateOperating(path)
}

// ParseConfig parses raw configuration text as an operating configuration.
func ParseConfig(text, path string) (Config, error) {
	return state.ConfigurationParseOperating(text, path)
}

// Node owns the router and client services; Close also retires its destinations.
type Node = node.Subsystem

// Options injects host collaborators; zero-valued fields select native defaults.
type Options = node.Options

// Status reports lifecycle state, not whether tunnels or remote services are ready.
type Status = node.Status

// New opens and locks encrypted state without opening listeners. Always Close
// the returned node, even if Start is never called or fails.
func New(cfg Config, options Options) (*Node, error) { return node.NewSubsystem(cfg, options) }

type (
	// DestinationController creates isolated endpoints without waiting for tunnel readiness.
	DestinationController = destination.DestinationController

	// DestinationEndpoint owns streams, tunnels, and key material until Close.
	DestinationEndpoint = destination.DestinationEndpoint

	// ReadyDestinationEndpoint waits for live inbound/outbound tunnels and confirmed
	// LeaseSet publication. Give WaitReady a bounded context during bootstrap.
	ReadyDestinationEndpoint = destination.ReadyDestinationEndpoint

	// PreparingDestinationEndpoint prepares a remote route without opening a stream.
	PreparingDestinationEndpoint = destination.PreparingDestinationEndpoint

	// DestinationSpec with Local nil creates a transient identity; supplied keys
	// are cloned, so the caller retains ownership of the original.
	DestinationSpec = destination.DestinationSpec

	// DestinationPolicy defines LeaseSet publication and encryption options.
	DestinationPolicy = node.DestinationPolicy

	// DestinationKind designates the publication visibility of a destination.
	DestinationKind = node.DestinationPolicyKind
)

const (
	DestinationPublicLS2     = node.DestinationPublicLeaseSet2
	DestinationEncryptedNone = node.DestinationEncryptedWithoutAuth
	DestinationEncryptedDH   = node.DestinationEncryptedWithDiffieHellman
	DestinationEncryptedPSK  = node.DestinationEncryptedWithPreSharedKey
)

// Hash is a 32-byte cryptographic identifier used for routers and destinations.
type Hash = foundation.Hash

// B32 returns the canonical .b32.i2p base32 representation of a destination hash.
func B32(hash Hash) string { return foundation.B32(hash) }

// EncodeI2PBase64 returns the canonical I2P base64 string for the given bytes.
func EncodeI2PBase64(raw []byte) string { return foundation.EncodeI2PBase64(raw) }

// DecodeI2PBase64 decodes standard I2P base64-encoded binary data.
func DecodeI2PBase64(encoded []byte) ([]byte, error) { return foundation.DecodeI2PBase64(encoded) }
