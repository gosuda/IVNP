package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking"
	"gosuda.org/ivnp/observability"
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
}

type statusResponse struct {
	Ready               bool   `json:"ready"`
	State               string `json:"state"`
	RouterHash          string `json:"router_hash"`
	RouterB32           string `json:"router_b32"`
	NetworkID           uint32 `json:"network_id"`
	Version             string `json:"version"`
	Family              string `json:"family"`
	UptimeSeconds       uint64 `json:"uptime_seconds"`
	Reachability        string `json:"reachability"`
	FloodfillConfigured bool   `json:"floodfill_configured"`
	FloodfillAdvertised bool   `json:"floodfill_advertised"`
	Readiness           any    `json:"readiness"`
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
	Routers          []netDBRouterItem `json:"routers"`
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
	clientStatus, err := s.node.ClientStatus(r.Context())
	if err != nil && !clientStatus.Ready {
		s.logger.Debug("webui status reports runtime error", "error", err)
	}
	config := s.node.Config()
	snapshot := s.node.RegistrySnapshot()
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
		Readiness:           clientStatus.Readiness,
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
	response.Services.HTTPProxy = serviceStatus{Enabled: config.HTTPProxy.Enabled, Address: endpointString(config.HTTPProxy.Address)}
	response.Services.SOCKS5 = serviceStatus{Enabled: config.SOCKS5.Enabled, Address: endpointString(config.SOCKS5.Address)}
	response.Services.SAM = serviceStatus{Enabled: config.SAM.Enabled, Address: endpointString(config.SAM.Address)}
	response.Services.Metrics = serviceStatus{Enabled: config.Metrics.Enabled, Address: endpointString(config.Metrics.Address)}
	response.Services.AddressBook.Enabled = config.AddressBook.Enabled
	response.Services.AddressBook.Subscriptions = len(config.AddressBook.Subscriptions)
	writeJSONResponse(w, http.StatusOK, response)
}

func (s *WebUIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSONResponse(w, http.StatusOK, s.currentMetricsResponse())
}

func (s *WebUIServer) currentMetricsResponse() metricsResponse {
	return s.metricsResponse(s.node.RegistrySnapshot())
}

func (s *WebUIServer) metricsResponse(snapshot ivnpObservabilitySnapshot) metricsResponse {
	config := s.node.Config()
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
	config := s.node.Config()
	snapshot := s.node.RegistrySnapshot()
	now := uint64(time.Now().UnixMilli())
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
		Tunnels:                   make([]tunnelItem, 0),
	}
	for _, runtime := range s.node.TunnelEntriesSnapshot() {
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
		if entry.Gateway != (foundation.Hash{}) {
			item.Gateway = foundation.B32(entry.Gateway)
		}
		if entry.HopCount > 0 {
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
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	now := uint64(time.Now().UnixMilli())
	routers := s.node.NetDBRoutersSnapshot()
	sort.Slice(routers, func(i, j int) bool {
		if routers[i].LastSeen == routers[j].LastSeen {
			return bytes.Compare(routers[i].Hash[:], routers[j].Hash[:]) < 0
		}
		return routers[i].LastSeen > routers[j].LastSeen
	})
	items := make([]netDBRouterItem, 0, min(limit, len(routers)))
	for _, router := range routers {
		item := netDBRouterView(router, now)
		if query != "" && !netDBRouterMatches(item, query) {
			continue
		}
		items = append(items, item)
		if len(items) == limit {
			break
		}
	}
	snapshot := s.node.RegistrySnapshot()
	writeJSONResponse(w, http.StatusOK, netDBResponse{
		TotalRouters: snapshot.NetDB.Routers, FloodfillRouters: snapshot.NetDB.Floodfills,
		LookupsTotal: snapshot.NetDB.Lookups, LookupsFailed: snapshot.NetDB.LookupFailures,
		Routers: items,
	})
}

func netDBRouterView(router networking.NetworkDatabaseRouterRef, now uint64) netDBRouterItem {
	item := netDBRouterItem{
		Hash: foundation.EncodeI2PBase64(router.Hash[:]), B32: foundation.B32(router.Hash),
		Floodfill: router.Floodfill, Published: router.Info.Published,
		Version: mappingValue(router.Info.Options, "router.version"), Caps: mappingValue(router.Info.Options, "caps"),
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
	destinations, err := s.node.ListDestinations(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "cannot list destinations")
		return
	}
	items := make([]destinationItem, 0, len(destinations))
	for _, destination := range destinations {
		item := destinationItem{Name: destination.Name, Address: destination.Address, Default: destination.Default}
		if bandwidth, ok := s.node.DestinationBandwidthSnapshot(destination.Name); ok {
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
	if err := s.startReseedAction(); err != nil {
		writeAPIError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"result": "reseed started"})
}

func (s *WebUIServer) handleActionTunnelProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.node.TriggerTunnelProbe(r.Context()); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, networking.TunnelErrProbeNotReady) && !errors.Is(err, networking.TunnelErrProbePending) {
			status = http.StatusServiceUnavailable
		}
		writeAPIError(w, status, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"result": "probe sent"})
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

func tunnelDirection(direction networking.TunnelDirection) string {
	if direction == networking.TunnelInbound {
		return "inbound"
	}
	return "outbound"
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSONResponse(w, status, map[string]string{"error": message})
}
