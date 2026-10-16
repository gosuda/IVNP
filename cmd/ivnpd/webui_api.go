package main

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

type ivnpObservabilitySnapshot = observability.Snapshot

type transportStatus struct {
	Enabled           bool   `json:"enabled"`
	BindAddress       string `json:"bind_address"`
	AdvertisedAddress string `json:"advertised_address"`
	ActiveSessions    uint64 `json:"active_sessions"`
	MaxSessions       int    `json:"max_sessions"`
}

type serviceStatus struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	// Listening is nil when the service is disabled.
	Listening *bool `json:"listening"`
}

type unmetCondition struct {
	Key      string  `json:"key"`
	Current  *uint64 `json:"current"`
	Required *uint64 `json:"required"`
}

type statusCapabilities struct {
	ConfigWritable    bool   `json:"config_writable"`
	ConfigWriteReason string `json:"config_write_reason"`
	Restart           bool   `json:"restart"`
	PeerIdentities    bool   `json:"peer_identities"`
}

type statusResponse struct {
	Ready               bool               `json:"ready"`
	State               string             `json:"state"`
	RouterHash          string             `json:"router_hash"`
	RouterB32           string             `json:"router_b32"`
	NetworkID           uint32             `json:"network_id"`
	Version             string             `json:"version"`
	Family              string             `json:"family"`
	UptimeSeconds       uint64             `json:"uptime_seconds"`
	Reachability        string             `json:"reachability"`
	FloodfillConfigured bool               `json:"floodfill_configured"`
	FloodfillAdvertised bool               `json:"floodfill_advertised"`
	TransitConfigured   bool               `json:"transit_configured"`
	Readiness           any                `json:"readiness"`
	UnmetConditions     []unmetCondition   `json:"unmet_conditions"`
	Capabilities        statusCapabilities `json:"capabilities"`
	Transports          struct {
		NTCP2 transportStatus `json:"ntcp2"`
		SSU2  transportStatus `json:"ssu2"`
	} `json:"transports"`
	Reseed struct {
		Enabled   bool   `json:"enabled"`
		Required  bool   `json:"required"`
		Endpoints int    `json:"endpoints"`
		Attempts  uint64 `json:"attempts"`
		Successes uint64 `json:"successes"`
		Failures  uint64 `json:"failures"`
	} `json:"reseed"`
	Services struct {
		HTTPProxy   serviceStatus `json:"http_proxy"`
		SOCKS5      serviceStatus `json:"socks5"`
		SAM         serviceStatus `json:"sam"`
		Metrics     serviceStatus `json:"metrics"`
		Control     serviceStatus `json:"control"`
		AddressBook struct {
			Enabled       bool `json:"enabled"`
			Subscriptions int  `json:"subscriptions"`
		} `json:"addressbook"`
	} `json:"services"`
}

type metricsResponse struct {
	SampledAt int64 `json:"sampled_at"`
	Bandwidth struct {
		InRateBPS     uint64 `json:"in_rate_bps"`
		OutRateBPS    uint64 `json:"out_rate_bps"`
		InTotalBytes  uint64 `json:"in_total_bytes"`
		OutTotalBytes uint64 `json:"out_total_bytes"`
		PeakRateBPS   uint64 `json:"peak_rate_bps"`
		RateLimitBPS  int    `json:"rate_limit_bps"`
	} `json:"bandwidth"`
	Tunnels struct {
		Active         uint64 `json:"active"`
		ExploratoryIn  uint64 `json:"exploratory_in"`
		ExploratoryOut uint64 `json:"exploratory_out"`
		ClientIn       uint64 `json:"client_in"`
		ClientOut      uint64 `json:"client_out"`
		BuildsTotal    uint64 `json:"builds_total"`
		BuildSuccesses uint64 `json:"build_successes"`
		BuildFailures  uint64 `json:"build_failures"`
		Forwarded      uint64 `json:"forwarded_messages"`
	} `json:"tunnels"`
	NetDB struct {
		Routers        uint64 `json:"routers"`
		Floodfills     uint64 `json:"floodfills"`
		Lookups        uint64 `json:"lookups"`
		LookupFailures uint64 `json:"lookup_failures"`
		Stores         uint64 `json:"stores"`
		StoreFailures  uint64 `json:"store_failures"`
	} `json:"netdb"`
	Transport struct {
		Sessions          uint64 `json:"sessions"`
		Connections       uint64 `json:"connections"`
		Disconnections    uint64 `json:"disconnections"`
		HandshakeFailures uint64 `json:"handshake_failures"`
	} `json:"transport"`
	Proxy struct {
		Requests uint64 `json:"requests"`
		Failures uint64 `json:"failures"`
		Active   uint64 `json:"active"`
	} `json:"proxy"`
	Process struct {
		Goroutines          uint64 `json:"goroutines"`
		HeapInuseBytes      uint64 `json:"heap_inuse_bytes"`
		HeapObjects         uint64 `json:"heap_objects"`
		AllocatedBytesTotal uint64 `json:"allocated_bytes_total"`
		GCCycles            uint64 `json:"gc_cycles"`
		GCPauseNS           uint64 `json:"gc_pause_ns"`
	} `json:"process"`
}

type tunnelItem struct {
	ID               uint32   `json:"id"`
	Direction        string   `json:"direction"`
	Kind             string   `json:"kind"`
	DestinationName  string   `json:"destination_name,omitempty"`
	Owner            string   `json:"owner,omitempty"`
	Gateway          string   `json:"gateway,omitempty"`
	GatewayTunnelID  uint32   `json:"gateway_tunnel_id,omitempty"`
	HopCount         uint8    `json:"hop_count"`
	Hops             []string `json:"hops,omitempty"`
	ExpiresAt        uint64   `json:"expires_at"`
	RemainingSeconds uint64   `json:"remaining_seconds"`
	State            string   `json:"state"`
}

type tunnelsResponse struct {
	ExploratoryInboundActive  uint64       `json:"exploratory_inbound_active"`
	ExploratoryInboundTarget  int          `json:"exploratory_inbound_target"`
	ExploratoryOutboundActive uint64       `json:"exploratory_outbound_active"`
	ExploratoryOutboundTarget int          `json:"exploratory_outbound_target"`
	ExploratoryPoolCapacity   int          `json:"exploratory_pool_capacity"`
	ClientInboundActive       uint64       `json:"client_inbound_active"`
	ClientInboundTarget       int          `json:"client_inbound_target"`
	ClientOutboundActive      uint64       `json:"client_outbound_active"`
	ClientOutboundTarget      int          `json:"client_outbound_target"`
	ClientPoolCapacity        int          `json:"client_pool_capacity"`
	BuildsTotal               uint64       `json:"builds_total"`
	BuildSuccesses            uint64       `json:"build_successes"`
	BuildFailures             uint64       `json:"build_failures"`
	ForwardedMessages         uint64       `json:"forwarded_messages"`
	PeerIdentities            bool         `json:"peer_identities"`
	RecentWindowSeconds       int          `json:"recent_window_seconds"`
	RecentBuildSuccesses      uint64       `json:"recent_build_successes"`
	RecentBuildFailures       uint64       `json:"recent_build_failures"`
	Tunnels                   []tunnelItem `json:"tunnels"`
}

type netDBRouterItem struct {
	Hash               string   `json:"hash"`
	B32                string   `json:"b32"`
	Floodfill          bool     `json:"floodfill"`
	Transports         []string `json:"transports"`
	Addresses          []string `json:"addresses"`
	Published          uint64   `json:"published"`
	Version            string   `json:"version"`
	Caps               string   `json:"caps"`
	LastSeenAgoSeconds uint64   `json:"last_seen_ago_seconds"`
}

type netDBResponse struct {
	TotalRouters     uint64            `json:"total_routers"`
	FloodfillRouters uint64            `json:"floodfill_routers"`
	LookupsTotal     uint64            `json:"lookups_total"`
	LookupsFailed    uint64            `json:"lookups_failed"`
	Matched          int               `json:"matched"`
	Routers          []netDBRouterItem `json:"routers"`
}

type peerProfileView struct {
	Successes     int    `json:"successes"`
	Failures      int    `json:"failures"`
	MeanLatencyMS uint64 `json:"mean_latency_ms"`
	Samples       int    `json:"samples"`
}

type peerItem struct {
	netDBRouterItem
	Profile *peerProfileView `json:"profile"`
}

type peersResponse struct {
	Peers   []peerItem `json:"peers"`
	Missing []string   `json:"missing"`
}

type destinationItem struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Default   bool   `json:"default"`
	Bandwidth *struct {
		RateBytesPerSecond uint64 `json:"rate_bytes_per_second"`
		BurstBytes         uint64 `json:"burst_bytes"`
		AvailableBytes     uint64 `json:"available_bytes"`
		AcceptedBytes      uint64 `json:"accepted_bytes"`
		BackpressuredBytes uint64 `json:"backpressured_bytes"`
		Waiters            uint32 `json:"waiters"`
	} `json:"bandwidth,omitempty"`
}

type destinationsResponse struct {
	Destinations []destinationItem `json:"destinations"`
}

func (s *WebUIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	current := s.requestNode(r)
	clientStatus, err := current.ClientStatus(r.Context())
	if err != nil && !clientStatus.Ready {
		s.logger.Debug("webui status reports runtime error", "error", err)
	}
	config := current.Config()
	snapshot := current.RegistrySnapshot()
	uptime := uint64(max(0, time.Since(s.started).Seconds()))
	reachability := "firewalled"
	switch {
	case !config.NTCP2.Enabled && !config.SSU2.Enabled:
		reachability = "disabled"
	case snapshot.Bootstrap.RouterReachable != 0:
		reachability = "reachable"
	case snapshot.Bootstrap.Stage < 3:
		reachability = "testing"
	}

	response := statusResponse{
		Ready:               clientStatus.Ready,
		State:               clientStatus.State,
		RouterHash:          clientStatus.RouterHash,
		RouterB32:           routerHashB32(clientStatus.RouterHash),
		NetworkID:           config.Network.ID,
		Version:             config.Router.Version,
		Family:              config.Router.Family,
		UptimeSeconds:       uptime,
		Reachability:        reachability,
		FloodfillConfigured: config.Router.Floodfill,
		FloodfillAdvertised: clientStatus.Readiness.FloodfillAdvertised,
		TransitConfigured:   config.Router.Transit,
		Readiness:           clientStatus.Readiness,
		UnmetConditions:     unmetConditionViews(controlplane.UnmetReadinessConditions(clientStatus.Readiness)),
		Capabilities:        s.capabilities(r),
	}
	response.Transports.NTCP2 = transportStatus{
		Enabled: config.NTCP2.Enabled, BindAddress: endpointString(config.NTCP2.Bind),
		AdvertisedAddress: endpointString(config.NTCP2.Advertised), ActiveSessions: snapshot.Transport.NTCP2Sessions,
		MaxSessions: config.NTCP2.MaxSessions,
	}
	response.Transports.SSU2 = transportStatus{
		Enabled: config.SSU2.Enabled, BindAddress: endpointString(config.SSU2.Bind),
		AdvertisedAddress: endpointString(config.SSU2.Advertised), ActiveSessions: snapshot.Transport.SSU2Sessions,
		MaxSessions: config.SSU2.MaxSessions,
	}
	response.Reseed.Enabled = config.Reseed.Enabled
	response.Reseed.Required = config.Reseed.Required
	response.Reseed.Endpoints = len(config.Reseed.Endpoints)
	response.Reseed.Attempts = snapshot.Reseed.Attempts
	response.Reseed.Successes = snapshot.Reseed.Successes
	response.Reseed.Failures = snapshot.Reseed.Failures
	listeners := current.ServiceListeners()
	response.Services.HTTPProxy = newServiceStatus(config.HTTPProxy.Enabled, config.HTTPProxy.Address, listeners.HTTPProxy)
	response.Services.SOCKS5 = newServiceStatus(config.SOCKS5.Enabled, config.SOCKS5.Address, listeners.SOCKS5)
	response.Services.SAM = newServiceStatus(config.SAM.Enabled, config.SAM.Address, listeners.SAM)
	response.Services.Metrics = newServiceStatus(config.Metrics.Enabled, config.Metrics.Address, listeners.Metrics)
	response.Services.Control = newServiceStatus(config.Control.Enabled, config.Control.Address, listeners.Control)
	response.Services.AddressBook.Enabled = config.AddressBook.Enabled
	response.Services.AddressBook.Subscriptions = len(config.AddressBook.Subscriptions)
	writeJSONResponse(w, http.StatusOK, response)
}

func newServiceStatus(enabled bool, address state.ConfigurationEndpoint, listening bool) serviceStatus {
	status := serviceStatus{Enabled: enabled, Address: endpointString(address)}
	if enabled {
		status.Listening = &listening
	}
	return status
}

func unmetConditionViews(conditions []controlplane.ReadinessCondition) []unmetCondition {
	views := make([]unmetCondition, 0, len(conditions))
	for _, condition := range conditions {
		view := unmetCondition{Key: condition.Key}
		if condition.Numeric {
			current, required := condition.Current, condition.Required
			view.Current, view.Required = &current, &required
		}
		views = append(views, view)
	}
	return views
}

// capabilities reports the actions available to the requesting client.
func (s *WebUIServer) capabilities(r *http.Request) statusCapabilities {
	reason := s.configWriteBlockedReason(r)
	return statusCapabilities{
		ConfigWritable:    reason == "",
		ConfigWriteReason: reason,
		Restart:           s.config.ConfigPath != "" && s.restartHook != nil,
		PeerIdentities:    s.peerIdentitiesVisible(),
	}
}

// peerIdentitiesVisible applies the peer identity policy: loopback-bound
// listeners always show peers; other listeners require -webui-show-peers.
func (s *WebUIServer) peerIdentitiesVisible() bool {
	return s.policy.loopback || s.config.ShowPeers
}

func (s *WebUIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSONResponse(w, http.StatusOK, s.metricsResponse(s.requestNode(r)))
}

func (s *WebUIServer) metricsResponse(current *node.Subsystem) metricsResponse {
	return s.metricsFromSnapshot(current.Config(), current.RegistrySnapshot())
}

func (s *WebUIServer) metricsFromSnapshot(config state.ConfigurationOperating, snapshot ivnpObservabilitySnapshot) metricsResponse {
	s.trafficMu.RLock()
	traffic := s.traffic
	s.trafficMu.RUnlock()
	response := metricsResponse{SampledAt: time.Now().UnixMilli()}
	response.Bandwidth.InRateBPS = traffic.inRate
	response.Bandwidth.OutRateBPS = traffic.outRate
	response.Bandwidth.InTotalBytes = snapshot.Transport.ReceivedBytes
	response.Bandwidth.OutTotalBytes = snapshot.Transport.SentBytes
	response.Bandwidth.PeakRateBPS = traffic.peakRate
	response.Bandwidth.RateLimitBPS = config.Tunnel.BandwidthRateBytesPerSecond
	response.Tunnels.Active = snapshot.Tunnel.Active
	response.Tunnels.ExploratoryIn = snapshot.Tunnel.ExploratoryInboundActive
	response.Tunnels.ExploratoryOut = snapshot.Tunnel.ExploratoryOutboundActive
	response.Tunnels.ClientIn = snapshot.Tunnel.ClientInboundActive
	response.Tunnels.ClientOut = snapshot.Tunnel.ClientOutboundActive
	response.Tunnels.BuildsTotal = snapshot.Tunnel.Builds
	response.Tunnels.BuildSuccesses = snapshot.Tunnel.BuildSuccesses
	response.Tunnels.BuildFailures = snapshot.Tunnel.BuildFailures
	response.Tunnels.Forwarded = snapshot.Tunnel.ParticipatingForwarded
	response.NetDB.Routers = snapshot.NetDB.Routers
	response.NetDB.Floodfills = snapshot.NetDB.Floodfills
	response.NetDB.Lookups = snapshot.NetDB.Lookups
	response.NetDB.LookupFailures = snapshot.NetDB.LookupFailures
	response.NetDB.Stores = snapshot.NetDB.Stores
	response.NetDB.StoreFailures = snapshot.NetDB.StoreFailures
	response.Transport.Sessions = snapshot.Transport.Sessions
	response.Transport.Connections = snapshot.Transport.Connections
	response.Transport.Disconnections = snapshot.Transport.Disconnections
	response.Transport.HandshakeFailures = snapshot.Transport.HandshakeFailures
	response.Proxy.Requests = snapshot.Proxy.Requests
	response.Proxy.Failures = snapshot.Proxy.Failures
	response.Proxy.Active = snapshot.Proxy.Active
	response.Process.Goroutines = snapshot.Process.Goroutines
	response.Process.HeapInuseBytes = snapshot.Process.HeapInuseBytes
	response.Process.HeapObjects = snapshot.Process.HeapObjects
	response.Process.AllocatedBytesTotal = snapshot.Process.AllocatedBytesTotal
	response.Process.GCCycles = snapshot.Process.GCCyclesTotal
	response.Process.GCPauseNS = snapshot.Process.GCPauseNanosecondsTotal
	return response
}

func (s *WebUIServer) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	current := s.requestNode(r)
	config := current.Config()
	snapshot := current.RegistrySnapshot()
	nowTime := time.Now()
	now := uint64(nowTime.UnixMilli())
	showPeers := s.peerIdentitiesVisible()
	response := tunnelsResponse{
		ExploratoryInboundActive:  snapshot.Tunnel.ExploratoryInboundActive,
		ExploratoryInboundTarget:  config.Tunnel.ExploratoryInboundTarget,
		ExploratoryOutboundActive: snapshot.Tunnel.ExploratoryOutboundActive,
		ExploratoryOutboundTarget: config.Tunnel.ExploratoryOutboundTarget,
		ExploratoryPoolCapacity:   config.Tunnel.ExploratoryPoolCapacity,
		ClientInboundActive:       snapshot.Tunnel.ClientInboundActive,
		ClientInboundTarget:       config.Tunnel.ClientInboundTarget,
		ClientOutboundActive:      snapshot.Tunnel.ClientOutboundActive,
		ClientOutboundTarget:      config.Tunnel.ClientOutboundTarget,
		ClientPoolCapacity:        config.Tunnel.ClientPoolCapacity,
		BuildsTotal:               snapshot.Tunnel.Builds,
		BuildSuccesses:            snapshot.Tunnel.BuildSuccesses,
		BuildFailures:             snapshot.Tunnel.BuildFailures,
		ForwardedMessages:         snapshot.Tunnel.ParticipatingForwarded,
		PeerIdentities:            showPeers,
		Tunnels:                   make([]tunnelItem, 0),
	}
	response.RecentWindowSeconds, response.RecentBuildSuccesses, response.RecentBuildFailures =
		s.history.recentBuilds(nowTime.UnixMilli(), snapshot.Tunnel.BuildSuccesses, snapshot.Tunnel.BuildFailures)
	for _, runtime := range current.TunnelEntriesSnapshot() {
		entry := runtime.Entry
		remaining := uint64(0)
		if entry.Expires > now {
			remaining = (entry.Expires - now) / uint64(time.Second/time.Millisecond)
		}
		item := tunnelItem{
			ID: entry.ID, Direction: tunnelDirection(entry.Direction), Kind: "exploratory",
			DestinationName: runtime.DestinationName, HopCount: entry.HopCount,
			ExpiresAt: entry.Expires, RemainingSeconds: remaining, State: "established",
			GatewayTunnelID: entry.GatewayTunnelID,
		}
		if runtime.DestinationName != "" {
			item.Kind = "client"
		}
		if remaining <= uint64(config.Tunnel.RenewBefore/time.Second) {
			item.State = "expiring"
		}
		if entry.Owner != (foundation.Hash{}) {
			item.Owner = foundation.B32(entry.Owner)
		}
		if showPeers && entry.Gateway != (foundation.Hash{}) {
			item.Gateway = foundation.B32(entry.Gateway)
		}
		if showPeers && entry.HopCount > 0 {
			item.Hops = make([]string, 0, entry.HopCount)
			for index := range int(entry.HopCount) {
				item.Hops = append(item.Hops, foundation.B32(entry.Hops[index]))
			}
		}
		response.Tunnels = append(response.Tunnels, item)
	}
	sort.Slice(response.Tunnels, func(i, j int) bool {
		left, right := response.Tunnels[i], response.Tunnels[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.DestinationName != right.DestinationName {
			return left.DestinationName < right.DestinationName
		}
		if left.Direction != right.Direction {
			return left.Direction < right.Direction
		}
		return left.ID < right.ID
	})
	writeJSONResponse(w, http.StatusOK, response)
}

func (s *WebUIServer) handleNetDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	limit := 50
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > 200 {
			writeAPIError(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	current := s.requestNode(r)
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	now := uint64(time.Now().UnixMilli())
	routers := current.NetDBRoutersSnapshot()
	sort.Slice(routers, func(i, j int) bool {
		if routers[i].LastSeen == routers[j].LastSeen {
			return bytes.Compare(routers[i].Hash[:], routers[j].Hash[:]) < 0
		}
		return routers[i].LastSeen > routers[j].LastSeen
	})
	items := make([]netDBRouterItem, 0, min(limit, len(routers)))
	matched := 0
	if query == "" {
		matched = len(routers)
		for _, router := range routers[:min(limit, len(routers))] {
			items = append(items, netDBRouterView(router, now))
		}
	} else {
		for _, router := range routers {
			item := netDBRouterView(router, now)
			if !netDBRouterMatches(item, query) {
				continue
			}
			matched++
			if len(items) < limit {
				items = append(items, item)
			}
		}
	}
	snapshot := current.RegistrySnapshot()
	writeJSONResponse(w, http.StatusOK, netDBResponse{
		TotalRouters: snapshot.NetDB.Routers, FloodfillRouters: snapshot.NetDB.Floodfills,
		LookupsTotal: snapshot.NetDB.Lookups, LookupsFailed: snapshot.NetDB.LookupFailures,
		Matched: matched, Routers: items,
	})
}

const maxPeerLookup = 64

func (s *WebUIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.peerIdentitiesVisible() {
		writeAPIError(w, http.StatusForbidden, "peer identities are hidden; start ivnpd with -webui-show-peers to show them")
		return
	}
	requested, hashes, err := parsePeerAddresses(r.URL.Query().Get("b32"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	current := s.requestNode(r)
	wanted := make(map[foundation.Hash]struct{}, len(hashes))
	for _, hash := range hashes {
		wanted[hash] = struct{}{}
	}
	now := uint64(time.Now().UnixMilli())
	found := make(map[foundation.Hash]netDBRouterItem, len(hashes))
	for _, router := range current.NetDBRoutersSnapshot() {
		if _, ok := wanted[router.Hash]; ok {
			found[router.Hash] = netDBRouterView(router, now)
		}
	}
	profiles := current.PeerProfileSnapshots(hashes)
	response := peersResponse{Peers: make([]peerItem, 0, len(found)), Missing: make([]string, 0)}
	for index, hash := range hashes {
		item, ok := found[hash]
		if !ok {
			response.Missing = append(response.Missing, requested[index])
			continue
		}
		peer := peerItem{netDBRouterItem: item}
		if profile, ok := profiles[hash]; ok {
			peer.Profile = &peerProfileView{
				Successes: profile.Successes, Failures: profile.Failures,
				MeanLatencyMS: profile.MeanLatencyMillis, Samples: profile.Samples,
			}
		}
		response.Peers = append(response.Peers, peer)
	}
	writeJSONResponse(w, http.StatusOK, response)
}

var errPeerLookupInput = errors.New("b32 must list 1 to 64 comma-separated .b32.i2p router addresses")

// parsePeerAddresses decodes a comma-separated list of router B32 addresses,
// dropping duplicates while preserving request order.
func parsePeerAddresses(raw string) ([]string, []foundation.Hash, error) {
	parts := strings.Split(raw, ",")
	if strings.TrimSpace(raw) == "" || len(parts) > maxPeerLookup {
		return nil, nil, errPeerLookupInput
	}
	addresses := make([]string, 0, len(parts))
	hashes := make([]foundation.Hash, 0, len(parts))
	seen := make(map[foundation.Hash]struct{}, len(parts))
	for _, part := range parts {
		address := strings.ToLower(strings.TrimSpace(part))
		encoded, ok := strings.CutSuffix(address, ".b32.i2p")
		if !ok {
			return nil, nil, errPeerLookupInput
		}
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err != nil || len(decoded) != foundation.HashLength {
			return nil, nil, errPeerLookupInput
		}
		var hash foundation.Hash
		copy(hash[:], decoded)
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		addresses = append(addresses, address)
		hashes = append(hashes, hash)
	}
	return addresses, hashes, nil
}

func netDBRouterView(router controlplane.NetworkDatabaseRouterRef, now uint64) netDBRouterItem {
	item := netDBRouterItem{
		Hash: foundation.EncodeI2PBase64(router.Hash[:]), B32: foundation.B32(router.Hash),
		Floodfill: router.Floodfill, Published: router.Info.Published,
		Version: mappingValue(router.Info.Options, "router.version"), Caps: mappingValue(router.Info.Options, "caps"),
		Transports: make([]string, 0), Addresses: make([]string, 0),
	}
	if now > router.LastSeen {
		item.LastSeenAgoSeconds = (now - router.LastSeen) / uint64(time.Second/time.Millisecond)
	}
	iterator := router.Info.Addresses()
	for {
		address, ok, err := iterator.Next()
		if err != nil || !ok {
			break
		}
		transport := string(address.TransportStyle)
		item.Transports = append(item.Transports, transport)
		host, port := mappingValue(address.Options, "host"), mappingValue(address.Options, "port")
		display := transport
		if host != "" && port != "" {
			display += " " + net.JoinHostPort(host, port)
		} else if host != "" {
			display += " " + host
		}
		item.Addresses = append(item.Addresses, display)
	}
	return item
}

func netDBRouterMatches(item netDBRouterItem, query string) bool {
	if strings.Contains(strings.ToLower(item.Hash), query) || strings.Contains(item.B32, query) ||
		strings.Contains(strings.ToLower(item.Version), query) || strings.Contains(strings.ToLower(item.Caps), query) {
		return true
	}
	for _, value := range item.Addresses {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func mappingValue(mapping foundation.Mapping, wanted string) string {
	iterator := mapping.Iterator()
	for {
		key, value, ok, err := iterator.Next()
		if err != nil || !ok {
			return ""
		}
		if bytes.Equal(key, []byte(wanted)) {
			return string(value)
		}
	}
}

func (s *WebUIServer) handleDestinations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	current := s.requestNode(r)
	destinations, err := current.ListDestinations(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot list destinations")
		return
	}
	items := make([]destinationItem, 0, len(destinations))
	for _, destination := range destinations {
		item := destinationItem{Name: destination.Name, Address: destination.Address, Default: destination.Default}
		if bandwidth, ok := current.DestinationBandwidthSnapshot(destination.Name); ok {
			item.Bandwidth = &struct {
				RateBytesPerSecond uint64 `json:"rate_bytes_per_second"`
				BurstBytes         uint64 `json:"burst_bytes"`
				AvailableBytes     uint64 `json:"available_bytes"`
				AcceptedBytes      uint64 `json:"accepted_bytes"`
				BackpressuredBytes uint64 `json:"backpressured_bytes"`
				Waiters            uint32 `json:"waiters"`
			}{
				RateBytesPerSecond: bandwidth.RateBytesPerSecond, BurstBytes: bandwidth.BurstBytes,
				AvailableBytes: bandwidth.AvailableBytes, AcceptedBytes: bandwidth.AcceptedBytes,
				BackpressuredBytes: bandwidth.BackpressuredBytes, Waiters: bandwidth.Waiters,
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	writeJSONResponse(w, http.StatusOK, destinationsResponse{Destinations: items})
}

func (s *WebUIServer) handleActionReseed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.startReseedAction(s.requestNode(r)); err != nil {
		s.recordAction(actionReseed, err, "")
		writeAPIError(w, http.StatusConflict, err.Error())
		return
	}
	s.recordAction(actionReseed, nil, "reseed started")
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"result": "reseed started"})
}

func (s *WebUIServer) handleActionTunnelProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.requestNode(r).TriggerTunnelProbe(r.Context()); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, controlplane.TunnelErrProbeNotReady) && !errors.Is(err, controlplane.TunnelErrProbePending) {
			status = http.StatusServiceUnavailable
		}
		s.recordAction(actionProbe, err, "")
		writeAPIError(w, status, err.Error())
		return
	}
	s.recordAction(actionProbe, nil, "probe sent")
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"result": "probe sent"})
}

var (
	errRestartMemoryMode  = errors.New("restart is unavailable in memory mode")
	errRestartUnavailable = errors.New("restart is unavailable")
	errRestartInProgress  = errors.New("router is already restarting")
)

func (s *WebUIServer) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.remoteWriteAllowed(r) {
		writeAPIError(w, http.StatusForbidden, configRemoteWriteReason)
		return
	}
	var err error
	switch {
	case s.config.ConfigPath == "":
		err = errRestartMemoryMode
	case s.restartHook == nil:
		err = errRestartUnavailable
	case s.restarting.Swap(true):
		err = errRestartInProgress
	default:
		if err = s.restartHook(); err != nil {
			s.restarting.Store(false)
		}
	}
	if err != nil {
		s.recordAction(actionRestart, err, "")
		writeAPIError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("webui restart requested", "remote", r.RemoteAddr)
	s.recordAction(actionRestart, nil, "restart scheduled")
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"result": "restart scheduled"})
}

func routerHashB32(encoded string) string {
	raw, err := foundation.DecodeI2PBase64([]byte(encoded))
	if err != nil || len(raw) != foundation.HashLength {
		return ""
	}
	var hash foundation.Hash
	copy(hash[:], raw)
	return foundation.B32(hash)
}

func endpointString(endpoint struct {
	Host string
	Port uint16
}) string {
	if endpoint.Host == "" || endpoint.Port == 0 {
		return ""
	}
	return net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port)))
}

func tunnelDirection(direction controlplane.TunnelDirection) string {
	if direction == controlplane.TunnelInbound {
		return "inbound"
	}
	return "outbound"
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSONResponse(w, status, map[string]string{"error": message})
}
