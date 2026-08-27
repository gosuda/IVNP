package registry

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MetricsPath is the Prometheus metrics endpoint.
	MetricsPath = "/metrics"
	// HealthPath is the JSON health check endpoint.
	HealthPath = "/healthz"

	prometheusContentType = "text/plain; version=0.0.4; charset=utf-8"
	jsonContentType       = "application/json; charset=utf-8"
	maxMetricsResponse    = 32768
)

// HealthStatus represents the node's health state.
type HealthStatus string

const (
	HealthOK          HealthStatus = "ok"
	HealthDegraded    HealthStatus = "degraded"
	HealthUnavailable HealthStatus = "unavailable"
)

// StatusFunc returns the current health status of the running node.
type StatusFunc func(ctx context.Context) HealthStatus

// DefaultHealthTimeout is the default deadline for evaluating StatusFunc.
const DefaultHealthTimeout = time.Second

// HandlerConfig configures the observability HTTP handler.
type HandlerConfig struct {
	HealthTimeout time.Duration
}

// NewHandler creates an http.Handler exposing /metrics and /healthz.
func NewHandler(registry *Registry, status StatusFunc, configs ...HandlerConfig) http.Handler {
	healthTimeout := DefaultHealthTimeout
	if len(configs) != 0 && configs[0].HealthTimeout > 0 {
		healthTimeout = configs[0].HealthTimeout
	}
	return handler{registry: registry, status: status, healthTimeout: healthTimeout}
}

// RequireBearer wraps an http.Handler with constant-time Bearer token authentication.
func RequireBearer(next http.Handler, token string) http.Handler {
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		scheme, provided, hasScheme := strings.Cut(request.Header.Get("Authorization"), " ")
		actual := sha256.Sum256([]byte(provided))
		matches := subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
		authorized := hasScheme && strings.EqualFold(scheme, "Bearer") && matches
		if !authorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ivnp-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, request)
	})
}

type handler struct {
	registry      *Registry
	status        StatusFunc
	healthTimeout time.Duration
}

func (h handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case MetricsPath:
		h.serveMetrics(w, request)
	case HealthPath:
		h.serveHealth(w, request)
	default:
		http.NotFound(w, request)
	}
}

func requireGet(w http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (h handler) serveMetrics(w http.ResponseWriter, request *http.Request) {
	if !requireGet(w, request) {
		return
	}
	w.Header().Set("Content-Type", prometheusContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(prometheusText(h.registry.Snapshot()))
}

func (h handler) serveHealth(w http.ResponseWriter, request *http.Request) {
	if !requireGet(w, request) {
		return
	}

	status := HealthUnavailable
	if h.status != nil {
		statusContext, cancel := context.WithTimeout(request.Context(), h.healthTimeout)
		defer cancel()
		status = h.status(statusContext)
		if statusContext.Err() != nil {
			status = HealthUnavailable
		}
	}
	code, body := healthResponse(status)
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

var (
	healthOKResponse          = []byte("{\"status\":\"ok\"}\n")
	healthDegradedResponse    = []byte("{\"status\":\"degraded\"}\n")
	healthUnavailableResponse = []byte("{\"status\":\"unavailable\"}\n")
)

func healthResponse(status HealthStatus) (int, []byte) {
	switch status {
	case HealthOK:
		return http.StatusOK, healthOKResponse
	case HealthDegraded:
		return http.StatusOK, healthDegradedResponse
	case HealthUnavailable:
		return http.StatusServiceUnavailable, healthUnavailableResponse
	default:
		return http.StatusServiceUnavailable, healthUnavailableResponse
	}
}

type prometheusMetric struct {
	name  string
	help  string
	kind  string
	value uint64
}

func prometheusText(snapshot Snapshot) []byte {
	metrics := [...]prometheusMetric{
		{"ivnp_admission_allowed_total", "Total admitted requests.", "counter", snapshot.Admission.Allowed},
		{"ivnp_admission_rejected_total", "Total rejected requests.", "counter", snapshot.Admission.Rejected},
		{"ivnp_admission_in_flight", "Requests currently undergoing admission.", "gauge", snapshot.Admission.InFlight},
		{"ivnp_bootstrap_stage", "Highest completed bootstrap stage.", "gauge", snapshot.Bootstrap.Stage},
		{"ivnp_control_requests_total", "Total control requests.", "counter", snapshot.Control.Requests},
		{"ivnp_control_failures_total", "Total failed control requests.", "counter", snapshot.Control.Failures},
		{"ivnp_control_active", "Active control requests.", "gauge", snapshot.Control.Active},
		{"ivnp_garlic_ecies_new_session_sent_total", "ECIES new-session messages sent.", "counter", snapshot.Garlic.NewSessionSent},
		{"ivnp_garlic_ecies_new_session_received_total", "ECIES new-session messages received.", "counter", snapshot.Garlic.NewSessionReceived},
		{"ivnp_garlic_ecies_existing_session_sent_total", "ECIES existing-session messages sent.", "counter", snapshot.Garlic.ExistingSessionSent},
		{"ivnp_garlic_ecies_existing_session_received_total", "ECIES existing-session messages received.", "counter", snapshot.Garlic.ExistingSessionReceived},
		{"ivnp_garlic_ecies_dh_steps_sent_total", "ECIES DH ratchet steps sent.", "counter", snapshot.Garlic.DHStepsSent},
		{"ivnp_garlic_ecies_dh_steps_received_total", "ECIES DH ratchet steps received.", "counter", snapshot.Garlic.DHStepsReceived},
		{"ivnp_garlic_tunnel_cloves_forwarded_total", "Garlic cloves forwarded to tunnels.", "counter", snapshot.Garlic.TunnelClovesForwarded},
		{"ivnp_ingress_recovered_panics_total", "Contained ingress panics.", "counter", snapshot.Lifecycle.IngressRecoveredPanics},
		{"ivnp_lifecycle_starts_total", "Total lifecycle starts.", "counter", snapshot.Lifecycle.Starts},
		{"ivnp_lifecycle_stops_total", "Total lifecycle stops.", "counter", snapshot.Lifecycle.Stops},
		{"ivnp_lifecycle_failures_total", "Total lifecycle failures.", "counter", snapshot.Lifecycle.Failures},
		{"ivnp_lifecycle_running", "Whether the lifecycle is running.", "gauge", snapshot.Lifecycle.Running},
		{"ivnp_netdb_lookups_total", "Total NetDB lookup requests sent.", "counter", snapshot.NetDB.Lookups},
		{"ivnp_netdb_lookup_failures_total", "Total failed NetDB lookups.", "counter", snapshot.NetDB.LookupFailures},
		{"ivnp_netdb_stores_total", "Total verified remote NetDB stores admitted.", "counter", snapshot.NetDB.Stores},
		{"ivnp_netdb_store_failures_total", "Total rejected NetDB stores.", "counter", snapshot.NetDB.StoreFailures},
		{"ivnp_netdb_routers", "Current verified remote RouterInfo count.", "gauge", snapshot.NetDB.Routers},
		{"ivnp_netdb_floodfills", "Current verified floodfill RouterInfo count.", "gauge", snapshot.NetDB.Floodfills},
		{"ivnp_process_goroutines", "Current process goroutines.", "gauge", snapshot.Process.Goroutines},
		{"ivnp_process_heap_inuse_bytes", "Current Go heap in-use bytes.", "gauge", snapshot.Process.HeapInuseBytes},
		{"ivnp_process_heap_objects", "Current Go heap objects.", "gauge", snapshot.Process.HeapObjects},
		{"ivnp_process_allocated_bytes_total", "Cumulative Go heap allocation bytes.", "counter", snapshot.Process.AllocatedBytesTotal},
		{"ivnp_process_mallocs_total", "Cumulative Go heap allocation count.", "counter", snapshot.Process.MallocsTotal},
		{"ivnp_process_gc_cycles_total", "Cumulative completed Go garbage-collection cycles.", "counter", snapshot.Process.GCCyclesTotal},
		{"ivnp_process_gc_pause_nanoseconds_total", "Cumulative Go garbage-collection pause time.", "counter", snapshot.Process.GCPauseNanosecondsTotal},
		{"ivnp_proxy_requests_total", "Total proxy requests.", "counter", snapshot.Proxy.Requests},
		{"ivnp_proxy_failures_total", "Total failed proxy requests.", "counter", snapshot.Proxy.Failures},
		{"ivnp_proxy_active", "Active proxy connections.", "gauge", snapshot.Proxy.Active},
		{"ivnp_publication_router_info_successes_total", "Confirmed RouterInfo publications.", "counter", snapshot.Publication.RouterInfoSuccesses},
		{"ivnp_publication_lease_set2_successes_total", "Confirmed LeaseSet2 publications.", "counter", snapshot.Publication.LeaseSet2Successes},
		{"ivnp_publication_attempts_total", "RouterInfo and LeaseSet publication attempts.", "counter", snapshot.Publication.Attempts},
		{"ivnp_publication_send_failures_total", "Publication attempts that failed before send completion.", "counter", snapshot.Publication.SendFailures},
		{"ivnp_publication_timeouts_total", "Sent publication attempts that timed out without confirmation.", "counter", snapshot.Publication.Timeouts},
		{"ivnp_reseed_attempts_total", "Total reseed attempts.", "counter", snapshot.Reseed.Attempts},
		{"ivnp_reseed_successes_total", "Total successful reseeds.", "counter", snapshot.Reseed.Successes},
		{"ivnp_reseed_failures_total", "Total failed reseeds.", "counter", snapshot.Reseed.Failures},
		{"ivnp_reseed_bytes_total", "Total reseed bytes received.", "counter", snapshot.Reseed.Bytes},
		{"ivnp_reseed_sources", "Configured reseed sources.", "gauge", snapshot.Reseed.Sources},
		{"ivnp_router_reachable", "Whether published router reachability is reachable.", "gauge", snapshot.Bootstrap.RouterReachable},
		{"ivnp_sam_udp_invalid_total", "SAM UDP frames rejected by strict parsing or source/session binding.", "counter", snapshot.SAM.UDPInvalid},
		{"ivnp_sam_udp_backpressure_rejections_total", "SAM UDP frames rejected by bounded ingress budgets or queue admission.", "counter", snapshot.SAM.UDPBackpressureRejections},
		{"ivnp_sam_protocol_failures_total", "SAM control protocol command failures.", "counter", snapshot.SAM.ProtocolFailures},
		{"ivnp_ssu2_vector_io_enabled", "Whether the kernel vector backend is active.", "gauge", snapshot.SSU2.VectorIOEnabled},
		{"ivnp_ssu2_kernel_drop_accounting", "Whether kernel UDP drop accounting is active.", "gauge", snapshot.SSU2.KernelDropAccounting},
		{"ivnp_ssu2_received_datagrams_total", "Datagrams returned by receive syscalls.", "counter", snapshot.SSU2.ReceivedDatagrams},
		{"ivnp_ssu2_enqueued_datagrams_total", "Received datagrams admitted to processing.", "counter", snapshot.SSU2.EnqueuedDatagrams},
		{"ivnp_ssu2_processed_datagrams_total", "Enqueued datagrams fully processed.", "counter", snapshot.SSU2.ProcessedDatagrams},
		{"ivnp_ssu2_receive_queue_drops_total", "Receive datagrams rejected by queue admission.", "counter", snapshot.SSU2.ReceiveQueueDrops},
		{"ivnp_ssu2_kernel_drops_total", "Datagrams dropped by the kernel socket queue.", "counter", snapshot.SSU2.KernelDrops},
		{"ivnp_ssu2_send_enqueued_datagrams_total", "Datagrams admitted to the send queue.", "counter", snapshot.SSU2.SendEnqueuedDatagrams},
		{"ivnp_ssu2_sent_datagrams_total", "Datagrams accepted by send syscalls.", "counter", snapshot.SSU2.SentDatagrams},
		{"ivnp_ssu2_send_failed_datagrams_total", "Queued datagrams rejected by send syscalls.", "counter", snapshot.SSU2.SendFailedDatagrams},
		{"ivnp_ssu2_send_queue_drops_total", "Datagrams rejected by send queue admission.", "counter", snapshot.SSU2.SendQueueDrops},
		{"ivnp_ssu2_receive_multi_batches_total", "Receive syscalls returning multiple datagrams.", "counter", snapshot.SSU2.ReceiveMultiBatches},
		{"ivnp_ssu2_send_multi_batches_total", "Send syscalls accepting multiple datagrams.", "counter", snapshot.SSU2.SendMultiBatches},
		{"ivnp_ssu2_ingress_queue_depth", "Current SSU2 ingress queue depth.", "gauge", snapshot.SSU2.IngressQueueDepth},
		{"ivnp_ssu2_egress_queue_depth", "Current SSU2 egress queue depth.", "gauge", snapshot.SSU2.EgressQueueDepth},
		{"ivnp_transport_connections_total", "Total transport connections.", "counter", snapshot.Transport.Connections},
		{"ivnp_transport_disconnections_total", "Total transport disconnections.", "counter", snapshot.Transport.Disconnections},
		{"ivnp_transport_handshake_failures_total", "Total failed transport handshakes.", "counter", snapshot.Transport.HandshakeFailures},
		{"ivnp_transport_received_bytes_total", "Total transport bytes received.", "counter", snapshot.Transport.ReceivedBytes},
		{"ivnp_transport_sent_bytes_total", "Total transport bytes sent.", "counter", snapshot.Transport.SentBytes},
		{"ivnp_transport_sessions", "Active transport sessions.", "gauge", snapshot.Transport.Sessions},
		{"ivnp_transport_ntcp2_sessions", "Active NTCP2 sessions.", "gauge", snapshot.Transport.NTCP2Sessions},
		{"ivnp_transport_ssu2_sessions", "Active SSU2 sessions.", "gauge", snapshot.Transport.SSU2Sessions},
		{"ivnp_transport_race_attempts_total", "Concurrent direct NTCP2 and SSU2 dial races.", "counter", snapshot.Transport.RaceAttempts},
		{"ivnp_transport_ssu2_race_wins_total", "Dial races retained as SSU2.", "counter", snapshot.Transport.SSU2RaceWins},
		{"ivnp_transport_ntcp2_race_wins_total", "Dial races retained as NTCP2.", "counter", snapshot.Transport.NTCP2RaceWins},
		{"ivnp_transport_session_reuses_total", "Sends reusing an authenticated transport session.", "counter", snapshot.Transport.SessionReuses},
		{"ivnp_transport_ssu2_promotions_total", "Peers promoted from NTCP2 to SSU2.", "counter", snapshot.Transport.SSU2Promotions},
		{"ivnp_tunnel_builds_total", "Total tunnel build attempts.", "counter", snapshot.Tunnel.Builds},
		{"ivnp_tunnel_build_successes_total", "Total successful tunnel builds.", "counter", snapshot.Tunnel.BuildSuccesses},
		{"ivnp_tunnel_build_failures_total", "Total failed tunnel builds.", "counter", snapshot.Tunnel.BuildFailures},
		{"ivnp_tunnel_active", "Active tunnels.", "gauge", snapshot.Tunnel.Active},
		{"ivnp_tunnel_exploratory_inbound_active", "Active exploratory inbound tunnels.", "gauge", snapshot.Tunnel.ExploratoryInboundActive},
		{"ivnp_tunnel_exploratory_outbound_active", "Active exploratory outbound tunnels.", "gauge", snapshot.Tunnel.ExploratoryOutboundActive},
		{"ivnp_tunnel_client_inbound_active", "Active client-owned inbound tunnels.", "gauge", snapshot.Tunnel.ClientInboundActive},
		{"ivnp_tunnel_client_outbound_active", "Active client-owned outbound tunnels.", "gauge", snapshot.Tunnel.ClientOutboundActive},
		{"ivnp_tunnel_participating_forwarded_total", "Participating tunnel messages forwarded.", "counter", snapshot.Tunnel.ParticipatingForwarded},
		{"ivnp_tunnel_exploratory_inbound_build_successes_total", "Successful exploratory inbound builds.", "counter", snapshot.Tunnel.ExploratoryInboundSuccesses},
		{"ivnp_tunnel_exploratory_outbound_build_successes_total", "Successful exploratory outbound builds.", "counter", snapshot.Tunnel.ExploratoryOutboundSuccesses},
		{"ivnp_tunnel_client_inbound_build_successes_total", "Successful client inbound builds.", "counter", snapshot.Tunnel.ClientInboundSuccesses},
		{"ivnp_tunnel_client_outbound_build_successes_total", "Successful client outbound builds.", "counter", snapshot.Tunnel.ClientOutboundSuccesses},
		{"ivnp_tunnel_exploratory_inbound_build_timeouts_total", "Timed-out exploratory inbound builds.", "counter", snapshot.Tunnel.ExploratoryInboundTimeouts},
		{"ivnp_tunnel_exploratory_outbound_build_timeouts_total", "Timed-out exploratory outbound builds.", "counter", snapshot.Tunnel.ExploratoryOutboundTimeouts},
		{"ivnp_tunnel_client_inbound_build_timeouts_total", "Timed-out client inbound builds.", "counter", snapshot.Tunnel.ClientInboundTimeouts},
		{"ivnp_tunnel_client_outbound_build_timeouts_total", "Timed-out client outbound builds.", "counter", snapshot.Tunnel.ClientOutboundTimeouts},
	}

	output := make([]byte, 0, maxMetricsResponse)
	for _, metric := range metrics {
		output = append(output, "# HELP "...)
		output = append(output, metric.name...)
		output = append(output, ' ')
		output = append(output, metric.help...)
		output = append(output, '\n')
		output = append(output, "# TYPE "...)
		output = append(output, metric.name...)
		output = append(output, ' ')
		output = append(output, metric.kind...)
		output = append(output, '\n')
		output = append(output, metric.name...)
		output = append(output, ' ')
		output = strconv.AppendUint(output, metric.value, 10)
		output = append(output, '\n')
	}
	return output
}
