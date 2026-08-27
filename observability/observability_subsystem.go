// Package observability provides metrics, health checks, and structured logging for IVNP.
package observability

import (
	"gosuda.org/ivnp/observability/internal/registry"
)

type (
	HealthStatus        = registry.HealthStatus
	Registry            = registry.Registry
	Snapshot            = registry.Snapshot
	LifecycleSnapshot   = registry.LifecycleSnapshot
	ReseedSnapshot      = registry.ReseedSnapshot
	TransportSnapshot   = registry.TransportSnapshot
	NetDBSnapshot       = registry.NetDBSnapshot
	TunnelSnapshot      = registry.TunnelSnapshot
	AdmissionSnapshot   = registry.AdmissionSnapshot
	ProxySnapshot       = registry.ProxySnapshot
	ControlSnapshot     = registry.ControlSnapshot
	BootstrapSnapshot   = registry.BootstrapSnapshot
	PublicationSnapshot = registry.PublicationSnapshot
	GarlicSnapshot      = registry.GarlicSnapshot
	SAMSnapshot         = registry.SAMSnapshot
	SSU2Snapshot        = registry.SSU2Snapshot
	ProcessSnapshot     = registry.ProcessSnapshot
	TunnelOwner         = registry.TunnelOwner
	TunnelDirection     = registry.TunnelDirection
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
