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
	RouterReachable            bool   `json:"router_reachable"`
	SSU2VectorIO               bool   `json:"ssu2_vector_io"`
	SSU2KernelDropAccounting   bool   `json:"ssu2_kernel_drop_accounting"`
	ProcessGoroutines          uint64 `json:"process_goroutines"`
	ProcessHeapInuseBytes      uint64 `json:"process_heap_inuse_bytes"`
	ProcessHeapObjects         uint64 `json:"process_heap_objects"`
}

type DestinationSummary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Default bool   `json:"default"`
}
