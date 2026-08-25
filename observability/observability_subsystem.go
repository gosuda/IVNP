// Package observability is the only public entry point for IVNP metrics and logging.
package observability

import registryinternal "gosuda.org/ivnp/observability/internal/registry"

type (
	HealthStatus = registryinternal.HealthStatus
	Registry     = registryinternal.Registry
	SSU2Snapshot = registryinternal.SSU2Snapshot
)

const (
	HealthOK          = registryinternal.HealthOK
	HealthUnavailable = registryinternal.HealthUnavailable
)

var (
	NewHandler    = registryinternal.NewHandler
	NewRegistry   = registryinternal.NewRegistry
	RequireBearer = registryinternal.RequireBearer
)
