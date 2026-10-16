package noderuntime

type ManagementStatus struct {
	Ready      bool             `json:"ready"`
	State      string           `json:"state,omitempty"`
	RouterHash string           `json:"router_hash,omitempty"`
	Readiness  ReadinessDetails `json:"readiness"`
}

type ReadinessDetails struct {
	BootstrapStage             uint64 `json:"bootstrap_stage"`
	NetDBRouters               uint64 `json:"netdb_routers"`
	RouterInfoPublications     uint64 `json:"router_info_publications"`
	LeaseSet2Publications      uint64 `json:"lease_set2_publications"`
	ExploratoryInboundTunnels  uint64 `json:"exploratory_inbound_tunnels"`
	ExploratoryOutboundTunnels uint64 `json:"exploratory_outbound_tunnels"`
	ClientInboundTunnels       uint64 `json:"client_inbound_tunnels"`
	ClientOutboundTunnels      uint64 `json:"client_outbound_tunnels"`
	FloodfillConfigured        bool   `json:"floodfill_configured"`
	FloodfillAdvertised        bool   `json:"floodfill_advertised"`
	TransitConfigured          bool   `json:"transit_configured"`
	RouterReachable            bool   `json:"router_reachable"`
	SSU2VectorIO               bool   `json:"ssu2_vector_io"`
	SSU2KernelDropAccounting   bool   `json:"ssu2_kernel_drop_accounting"`
	ProcessGoroutines          uint64 `json:"process_goroutines"`
	ProcessHeapInuseBytes      uint64 `json:"process_heap_inuse_bytes"`
	ProcessHeapObjects         uint64 `json:"process_heap_objects"`
}

// Readiness requirement keys reported by UnmetReadinessConditions, in
// evaluation order.
const (
	ReadinessNetDBRouters           = "netdb_routers"
	ReadinessRouterInfoPublication  = "router_info_publication"
	ReadinessLeaseSet2Publication   = "lease_set2_publication"
	ReadinessExploratoryInbound     = "exploratory_inbound"
	ReadinessExploratoryOutbound    = "exploratory_outbound"
	ReadinessClientInbound          = "client_inbound"
	ReadinessClientOutbound         = "client_outbound"
	ReadinessFloodfillAdvertisement = "floodfill_advertisement"
)

// readinessMinimumNetDBRouters is the RouterInfo count the data plane needs
// before peer selection is considered representative.
const readinessMinimumNetDBRouters = 50

// ReadinessCondition is one unmet data-plane readiness requirement. Current
// and Required are meaningful only when Numeric is true.
type ReadinessCondition struct {
	Key      string
	Numeric  bool
	Current  uint64
	Required uint64
}

// UnmetReadinessConditions returns the requirements that keep the data plane
// from reporting ready, in a fixed order. It returns nil when every
// requirement is met; dataPlaneReady uses it as its single source of truth.
func UnmetReadinessConditions(readiness ReadinessDetails) []ReadinessCondition {
	var unmet []ReadinessCondition
	minimum := func(key string, current, required uint64) {
		if current < required {
			unmet = append(unmet, ReadinessCondition{Key: key, Numeric: true, Current: current, Required: required})
		}
	}
	minimum(ReadinessNetDBRouters, readiness.NetDBRouters, readinessMinimumNetDBRouters)
	minimum(ReadinessRouterInfoPublication, readiness.RouterInfoPublications, 1)
	minimum(ReadinessLeaseSet2Publication, readiness.LeaseSet2Publications, 1)
	minimum(ReadinessExploratoryInbound, readiness.ExploratoryInboundTunnels, 1)
	minimum(ReadinessExploratoryOutbound, readiness.ExploratoryOutboundTunnels, 1)
	minimum(ReadinessClientInbound, readiness.ClientInboundTunnels, 1)
	minimum(ReadinessClientOutbound, readiness.ClientOutboundTunnels, 1)
	if readiness.FloodfillConfigured && !readiness.FloodfillAdvertised {
		unmet = append(unmet, ReadinessCondition{Key: ReadinessFloodfillAdvertisement})
	}
	return unmet
}

// PeerProfileSnapshot summarizes the recent tunnel outcomes recorded for one
// peer.
type PeerProfileSnapshot struct {
	Successes         int
	Failures          int
	MeanLatencyMillis uint64
	Samples           int
}

type DestinationSummary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Default bool   `json:"default"`
}
