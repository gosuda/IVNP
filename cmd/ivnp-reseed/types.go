package main

import (
	"net/netip"
	"time"

	"gosuda.org/ivnp/foundation"
)

// PeerStats tracks connectivity, stability, and latency observations for a router.
type PeerStats struct {
	TotalProbes      int64         `json:"total_probes"`
	SuccessProbes    int64         `json:"success_probes"`
	ConsecutiveFails int           `json:"consecutive_fails"`
	LastSeen         time.Time     `json:"last_seen"`
	LastProbed       time.Time     `json:"last_probed"`
	EWMARTT          time.Duration `json:"ewma_rtt"`
	LastRTT          time.Duration `json:"last_rtt"`
	IsReachable      bool          `json:"is_reachable"`
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
	Stats       PeerStats       `json:"stats"`
	Score       float64         `json:"score"`
}

// ReseedPackage contains pre-rendered, signed reseed archives and their metadata.
type ReseedPackage struct {
	GeneratedAt time.Time
	PeerCount   int
	SU3Data     []byte
	IVBSData    []byte
	ETag        string
}
