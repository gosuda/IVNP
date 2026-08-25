// Package observability is the only public entry point for IVNP metrics and logging.
package observability

import "gosuda.org/ivnp/observability/internal/registry"

type (
	HealthStatus = registry.HealthStatus
	Registry     = registry.Registry
	SSU2Snapshot = registry.SSU2Snapshot
)

const (
	HealthOK          = registry.HealthOK
	HealthUnavailable = registry.HealthUnavailable
)

var (
	NewHandler    = registry.NewHandler
	NewRegistry   = registry.NewRegistry
	RequireBearer = registry.RequireBearer
)
