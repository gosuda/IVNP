// Package ivnp provides the top-level public API for embedding an IVNP router
// and managing application destinations.
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

// LoadOrCreateConfig reads the configuration file if it exists, or writes
// and returns a production default configuration if it does not.
func LoadOrCreateConfig(path string) (Config, error) {
	return state.ConfigurationLoadOrCreateOperating(path)
}

// ParseConfig parses raw configuration text as an operating configuration.
func ParseConfig(text, path string) (Config, error) {
	return state.ConfigurationParseOperating(text, path)
}

// Node represents an embedded IVNP router node and its associated services.
type Node = node.Subsystem

// Options supplies host-owned collaborators (custom logger, clock, sockets, listener).
type Options = node.Options

// Status describes node runtime health and lifecycle state.
type Status = node.Status

// New initializes an embedded IVNP node with the given configuration and options.
func New(cfg Config, options Options) (*Node, error) { return node.NewSubsystem(cfg, options) }

type (
	// DestinationController creates, queries, and releases application-scoped destinations.
	DestinationController = destination.DestinationController

	// DestinationEndpoint represents an isolated I2P identity for dialing and listening.
	DestinationEndpoint = destination.DestinationEndpoint

	// ReadyDestinationEndpoint synchronizes until inbound and outbound tunnels are ready.
	ReadyDestinationEndpoint = destination.ReadyDestinationEndpoint

	// DestinationSpec configures the creation of a new or imported destination.
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
