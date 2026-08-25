// Package observability is the only public entry point for IVNP metrics and logging.
package observability

import (
	"gosuda.org/ivnp/observability/internal/registry"
)

type (
	HealthStatus    = registry.HealthStatus
	Registry        = registry.Registry
	SSU2Snapshot    = registry.SSU2Snapshot
	TunnelOwner     = registry.TunnelOwner
	TunnelDirection = registry.TunnelDirection
)

const (
	HealthOK                = registry.HealthOK
	HealthUnavailable       = registry.HealthUnavailable
	TunnelOwnerExploratory  = registry.TunnelOwnerExploratory
	TunnelOwnerClient       = registry.TunnelOwnerClient
	TunnelDirectionInbound  = registry.TunnelDirectionInbound
	TunnelDirectionOutbound = registry.TunnelDirectionOutbound
)

var (
	NewHandler    = registry.NewHandler
	NewRegistry   = registry.NewRegistry
	RequireBearer = registry.RequireBearer
)
