package main

import (
	"net/netip"
	"time"

	"gosuda.org/ivnp/foundation"
)

const (
	// MaxStorePeers bounds in-memory peer tracking to prevent unbounded RAM growth.
	MaxStorePeers = 5000

	// DefaultProbeRateLimit bounds outbound probes to avoid flooding peers while actively verifying network state.
	DefaultProbeRateLimit = 60.0 // probes per second (loosened from 15.0)
	DefaultProbeBurst     = 120.0

	// Probe cooldowns differentiated by peer state:
	ProbeCooldownReachable = 3 * time.Minute  // loosened from 10m
	ProbeCooldownFailed    = 90 * time.Second // recheck failed peers sooner
	ProbeCooldownInterval  = 3 * time.Minute  // default fallback interval
)

// ExplorationMode tracks the dynamic budget allocation phase.
type ExplorationMode string

const (
	ExplorationModeExpansion   ExplorationMode = "expansion"   // Reachable < 1024: aggressive exploration & newcomer probing
	ExplorationModeMaintenance ExplorationMode = "maintenance" // Reachable >= 1024: targeted sparse repair & quality tracking
)

// PeerStats tracks connectivity, stability, and latency observations for a router.
type PeerStats struct {
	TotalProbes         int64         `json:"total_probes"`
	SuccessProbes       int64         `json:"success_probes"`
	ConsecutiveFails    int           `json:"consecutive_fails"`
	LastSeen            time.Time     `json:"last_seen"`
	LastProbed          time.Time     `json:"last_probed"`
	EWMARTT             time.Duration `json:"ewma_rtt"`
	LastRTT             time.Duration `json:"last_rtt"`
	IsReachable         bool          `json:"is_reachable"`
	TunnelBuildAccepted bool          `json:"tunnel_build_accepted,omitempty"`
	LastTunnelAccepted  time.Time     `json:"last_tunnel_accepted,omitempty"`
}

// PeerRecord holds a parsed RouterInfo, its raw wire payload, and indexed network properties.
type PeerRecord struct {
	Hash        foundation.Hash `json:"hash"`
	Raw         []byte          `json:"raw"`
	PublishedAt time.Time       `json:"published_at"`
	IsFloodfill bool            `json:"is_floodfill"`
	Family      string          `json:"family,omitempty"`
	IPv4        []netip.Addr    `json:"ipv4,omitempty"`
	IPv6        []netip.Addr    `json:"ipv6,omitempty"`
	Ports       []uint16        `json:"ports,omitempty"`
	TCPPorts    []uint16        `json:"tcp_ports,omitempty"`
	UDPPorts    []uint16        `json:"udp_ports,omitempty"`
	Stats       PeerStats       `json:"stats"`
	Score       float64         `json:"score"`
}

// ReseedPackage contains pre-rendered, signed reseed archives and their metadata.
type ReseedPackage struct {
	GeneratedAt    time.Time
	PeerCount      int
	FloodfillCount int
	SU3Data        []byte
	ETag           string
	Stats          PackageStats
}

type RTTStats struct {
	MinMs int64 `json:"min_ms"`
	AvgMs int64 `json:"avg_ms"`
	P50Ms int64 `json:"p50_ms"`
	P90Ms int64 `json:"p90_ms"`
	P99Ms int64 `json:"p99_ms"`
	MaxMs int64 `json:"max_ms"`
}

type DiversityStats struct {
	UniqueIPv4Subnets16 int `json:"unique_ipv4_subnets_16"`
	UniqueIPv4Subnets24 int `json:"unique_ipv4_subnets_24"`
	UniqueIPv4Count     int `json:"unique_ipv4_count"`
	UniqueIPv6Count     int `json:"unique_ipv6_count"`
	UniqueFamilies      int `json:"unique_families"`
}

type KBucketStats struct {
	TotalBuckets    int      `json:"total_buckets"`
	CoveredBuckets  int      `json:"covered_buckets"`
	CoveragePercent float64  `json:"coverage_percent"`
	Distribution    [256]int `json:"distribution"`
}

type PackageStats struct {
	PeerCount                int       `json:"peer_count"`
	FloodfillCount           int       `json:"floodfill_count"`
	FloodfillRatio           float64   `json:"floodfill_ratio"`
	IPv4OnlyCount            int       `json:"ipv4_only_count"`
	IPv4OnlyRatio            float64   `json:"ipv4_only_ratio"`
	DualStackCount           int       `json:"dual_stack_count"`
	DualStackRatio           float64   `json:"dual_stack_ratio"`
	IPv6OnlyCount            int       `json:"ipv6_only_count"`
	IPv6OnlyRatio            float64   `json:"ipv6_only_ratio"`
	AverageAvailability      float64   `json:"average_availability"`
	DirectlyReachableCount   int       `json:"directly_reachable_count"`
	DirectlyReachableRatio   float64   `json:"directly_reachable_ratio"`
	TunnelBuildAcceptedCount int       `json:"tunnel_build_accepted_count"`
	TunnelBuildAcceptedRatio float64   `json:"tunnel_build_accepted_ratio"`
	RTT                      RTTStats  `json:"rtt"`
	GenerationMethod         string    `json:"generation_method"`
	RequireReachableFilter   bool      `json:"require_reachable_filter"`
	SU3SizeBytes             int       `json:"su3_size_bytes"`
	ETag                     string    `json:"etag"`
	LastGeneratedAt          time.Time `json:"last_generated_at"`
	NextRefreshETA           int64     `json:"next_refresh_eta_seconds"`
	RefreshIntervalSeconds   int64     `json:"refresh_interval_seconds"`
}

type DetailedStatsResponse struct {
	Version         string          `json:"version"`
	NetworkID       uint8           `json:"network_id"`
	UptimeSeconds   int64           `json:"uptime_seconds"`
	ExplorationMode ExplorationMode `json:"exploration_mode,omitempty"`
	TotalIndexed    int             `json:"total_indexed"`
	ReachablePeers  int             `json:"reachable_peers"`
	FloodfillPeers  int             `json:"floodfill_peers"`
	PublishedPeers  int             `json:"published_peers"`
	AverageEWMARTT  time.Duration   `json:"average_ewma_rtt_ms"`
	LastGeneratedAt time.Time       `json:"last_generated_at"`
	SignerID        string          `json:"signer_id,omitempty"`
	CertificatePEM  string          `json:"certificate_pem,omitempty"`
	PublicKeyPEM    string          `json:"public_key_pem,omitempty"`
	RTT             RTTStats        `json:"rtt"`
	Diversity       DiversityStats  `json:"diversity"`
	KBuckets        KBucketStats    `json:"kbuckets"`
	Package         PackageStats    `json:"package"`
}
