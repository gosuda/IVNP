package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistrySnapshotConcurrent(t *testing.T) {
	registry := NewRegistry()
	const workers = 24
	const iterations = 500

	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for range iterations {
				registry.IncLifecycleStarts()
				registry.IncReseedAttempts()
				registry.AddReseedBytes(3)
				registry.IncTransportConnections()
				registry.AddTransportReceivedBytes(5)
				registry.IncNetDBLookups()
				registry.IncTunnelBuilds()
				registry.IncAdmissionAllowed()
				registry.IncProxyRequests()
				registry.IncControlRequests()
				_ = registry.Snapshot()
			}
		}()
	}
	wait.Wait()

	registry.SetLifecycleRunning(1)
	registry.SetReseedSources(2)
	registry.SetTransportSessions(3)
	registry.SetNetDBRouters(4)
	registry.SetTunnelActive(5)
	registry.SetAdmissionInFlight(6)
	registry.SetProxyActive(7)
	registry.SetControlActive(8)

	want := uint64(workers * iterations)
	snapshot := registry.Snapshot()
	if snapshot.Lifecycle.Starts != want || snapshot.Reseed.Attempts != want || snapshot.Reseed.Bytes != want*3 || snapshot.Transport.Connections != want || snapshot.Transport.ReceivedBytes != want*5 || snapshot.NetDB.Lookups != want || snapshot.Tunnel.Builds != want || snapshot.Admission.Allowed != want || snapshot.Proxy.Requests != want || snapshot.Control.Requests != want {
		t.Fatalf("counter snapshot = %+v, want every counter update preserved", snapshot)
	}
	if snapshot.Lifecycle.Running != 1 || snapshot.Reseed.Sources != 2 || snapshot.Transport.Sessions != 3 || snapshot.NetDB.Routers != 4 || snapshot.Tunnel.Active != 5 || snapshot.Admission.InFlight != 6 || snapshot.Proxy.Active != 7 || snapshot.Control.Active != 8 {
		t.Fatalf("gauge snapshot = %+v, want configured values", snapshot)
	}

	registry.IncLifecycleStarts()
	if snapshot.Lifecycle.Starts != want {
		t.Fatalf("snapshot changed after registry update: %+v", snapshot)
	}
}

func TestRegistryCopySharesConcurrentState(t *testing.T) {
	registry := NewRegistry()
	const workers = 24
	const iterations = 500

	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for range iterations {
				copy := *registry
				copy.IncLifecycleStarts()
				_ = copy.Snapshot()
			}
		}()
	}
	wait.Wait()

	if got, want := registry.Snapshot().Lifecycle.Starts, uint64(workers*iterations); got != want {
		t.Fatalf("shared lifecycle starts = %d, want %d", got, want)
	}

	var zero Registry
	zero.SetControlActive(1)
	if got := zero.Snapshot().Control.Active; got != 1 {
		t.Fatalf("zero-value registry active control = %d, want 1", got)
	}
}

func TestPrometheusOutputIsDeterministicAndBounded(t *testing.T) {
	registry := NewRegistry()
	registry.IncLifecycleStarts()
	registry.SetTransportSessions(4)

	snapshot := registry.Snapshot()
	first := prometheusText(snapshot)
	second := prometheusText(snapshot)
	if !bytes.Equal(first, second) {
		t.Fatalf("prometheus output is not deterministic\nfirst: %q\nsecond: %q", first, second)
	}
	if len(first) > maxMetricsResponse {
		t.Fatalf("metrics response is %d bytes, limit is %d", len(first), maxMetricsResponse)
	}
	for _, want := range []string{
		"# HELP ivnp_lifecycle_starts_total Total lifecycle starts.\n",
		"# TYPE ivnp_lifecycle_starts_total counter\n",
		"ivnp_lifecycle_starts_total 1\n",
		"ivnp_transport_sessions 4\n",
	} {
		if !strings.Contains(string(first), want) {
			t.Fatalf("metrics output missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(string(first), "{") {
		t.Fatalf("metrics must not contain labels: %s", first)
	}
}

func TestSoakMetricsStateAndProcessGauges(t *testing.T) {
	registry := NewRegistry()
	registry.SetBootstrapStage(4)
	registry.SetRouterReachable(1)
	registry.IncPublicationRouterInfoSuccesses()
	registry.IncPublicationLeaseSet2Successes()
	registry.SetTunnelExploratoryInboundActive(1)
	registry.SetTunnelExploratoryOutboundActive(2)
	registry.SetTunnelClientInboundActive(3)
	registry.SetTunnelClientOutboundActive(4)
	registry.IncIngressRecoveredPanics()
	registry.IncGarlicECIESNewSessionSent()
	registry.IncGarlicECIESNewSessionReceived()
	registry.IncGarlicECIESExistingSessionSent()
	registry.IncGarlicECIESExistingSessionReceived()
	registry.IncGarlicECIESDHStepsSent()
	registry.IncGarlicECIESDHStepsReceived()
	registry.IncGarlicTunnelClovesForwarded()
	registry.IncTunnelParticipatingForwarded()
	registry.SetSSU2VectorIOEnabled(1)
	registry.SetSSU2KernelDropAccounting(1)
	registry.AddSSU2ReceivedDatagrams(3)
	registry.AddSSU2EnqueuedDatagrams(3)
	registry.AddSSU2ProcessedDatagrams(3)
	registry.AddSSU2SendEnqueuedDatagrams(2)
	registry.AddSSU2SentDatagrams(2)
	registry.IncSSU2ReceiveMultiBatches()
	registry.IncSSU2SendMultiBatches()
	registry.IncSAMUDPInvalid()
	registry.IncSAMUDPBackpressureRejected()
	registry.IncSAMProtocolFailures()

	snapshot := registry.Snapshot()
	if snapshot.Bootstrap.Stage != 4 || snapshot.Bootstrap.RouterReachable != 1 ||
		snapshot.Publication.RouterInfoSuccesses != 1 || snapshot.Publication.LeaseSet2Successes != 1 {
		t.Fatalf("readiness state = %+v %+v", snapshot.Bootstrap, snapshot.Publication)
	}
	if snapshot.Process.Goroutines == 0 || snapshot.Process.HeapInuseBytes == 0 || snapshot.Process.HeapObjects == 0 ||
		snapshot.Process.AllocatedBytesTotal == 0 || snapshot.Process.MallocsTotal == 0 {
		t.Fatalf("process gauges = %+v", snapshot.Process)
	}
	if snapshot.SSU2.ReceivedDatagrams != snapshot.SSU2.EnqueuedDatagrams+snapshot.SSU2.ReceiveQueueDrops ||
		snapshot.SSU2.EnqueuedDatagrams != snapshot.SSU2.ProcessedDatagrams ||
		snapshot.SSU2.SendEnqueuedDatagrams != snapshot.SSU2.SentDatagrams+snapshot.SSU2.SendFailedDatagrams+snapshot.SSU2.SendQueueDrops {
		t.Fatalf("SSU2 conservation = %+v", snapshot.SSU2)
	}

	wire := string(prometheusText(snapshot))
	for _, name := range []string{
		"ivnp_bootstrap_stage",
		"ivnp_netdb_routers",
		"ivnp_publication_router_info_successes_total",
		"ivnp_publication_lease_set2_successes_total",
		"ivnp_tunnel_exploratory_inbound_active",
		"ivnp_tunnel_exploratory_outbound_active",
		"ivnp_tunnel_client_inbound_active",
		"ivnp_tunnel_client_outbound_active",
		"ivnp_router_reachable",
		"ivnp_ssu2_vector_io_enabled",
		"ivnp_ssu2_kernel_drop_accounting",
		"ivnp_process_goroutines",
		"ivnp_process_heap_inuse_bytes",
		"ivnp_process_heap_objects",
		"ivnp_process_allocated_bytes_total",
		"ivnp_process_mallocs_total",
		"ivnp_process_gc_cycles_total",
		"ivnp_process_gc_pause_nanoseconds_total",
		"ivnp_sam_udp_invalid_total",
		"ivnp_sam_udp_backpressure_rejections_total",
		"ivnp_sam_protocol_failures_total",
		"ivnp_ingress_recovered_panics_total",
		"ivnp_garlic_ecies_dh_steps_received_total",
		"ivnp_tunnel_participating_forwarded_total",
		"ivnp_ssu2_received_datagrams_total",
		"ivnp_ssu2_send_multi_batches_total",
		"ivnp_ssu2_ingress_queue_depth",
		"ivnp_ssu2_egress_queue_depth",
	} {
		if !strings.Contains(wire, "\n"+name+" ") {
			t.Errorf("integer sample missing for %s", name)
		}
	}
}

func TestHandlerContentTypesAndHealthMapping(t *testing.T) {
	cases := []struct {
		name   string
		status HealthStatus
		code   int
		body   string
	}{
		{"ok", HealthOK, http.StatusOK, "{\"status\":\"ok\"}\n"},
		{"degraded", HealthDegraded, http.StatusOK, "{\"status\":\"degraded\"}\n"},
		{"unavailable", HealthUnavailable, http.StatusServiceUnavailable, "{\"status\":\"unavailable\"}\n"},
		{"unknown", HealthStatus("secret-destination-key"), http.StatusServiceUnavailable, "{\"status\":\"unavailable\"}\n"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(NewRegistry(), func(context.Context) HealthStatus { return test.status })
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, HealthPath, nil))
			if response.Code != test.code {
				t.Fatalf("status code = %d, want %d", response.Code, test.code)
			}
			if got := response.Header().Get("Content-Type"); got != jsonContentType {
				t.Fatalf("Content-Type = %q, want %q", got, jsonContentType)
			}
			if got := response.Body.String(); got != test.body {
				t.Fatalf("body = %q, want %q", got, test.body)
			}
			if strings.Contains(response.Body.String(), string(test.status)) && test.status != HealthOK && test.status != HealthDegraded && test.status != HealthUnavailable {
				t.Fatalf("unknown status leaked into response: %q", response.Body.String())
			}
		})
	}

	metrics := httptest.NewRecorder()
	NewHandler(NewRegistry(), nil).ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, MetricsPath, nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", metrics.Code, http.StatusOK)
	}
	if got := metrics.Header().Get("Content-Type"); got != prometheusContentType {
		t.Fatalf("metrics Content-Type = %q, want %q", got, prometheusContentType)
	}
}

func TestHandlerHealthTimeoutCancelsStatusAndReturnsUnavailable(t *testing.T) {
	var cancelled bool
	handler := NewHandler(NewRegistry(), func(ctx context.Context) HealthStatus {
		<-ctx.Done()
		cancelled = true
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("status context error = %v, want deadline exceeded", ctx.Err())
		}
		return HealthOK
	}, HandlerConfig{HealthTimeout: time.Millisecond})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, HealthPath, nil))

	if !cancelled {
		t.Fatal("status function was not canceled")
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if got, want := response.Body.String(), "{\"status\":\"unavailable\"}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestRequireBearerRejectsMissingAndAcceptsMatchingToken(t *testing.T) {
	handler := RequireBearer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "metrics-secret")
	for _, authorization := range []string{"", "Basic metrics-secret", "Bearer wrong", "Bearer metrics-secret"} {
		request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if authorization == "Bearer metrics-secret" {
			want = http.StatusNoContent
		}
		if response.Code != want {
			t.Fatalf("authorization %q status = %d, want %d", authorization, response.Code, want)
		}
	}
}

func TestSecretHelpersDoNotLogSuppliedValues(t *testing.T) {
	const token = "bearer-token-very-secret"
	var output bytes.Buffer
	logger, err := NewLogger(LogConfig{Format: "json", Level: "debug", Output: &output})
	if err != nil {
		t.Fatal(err)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "request\nreceived",
		Secret("token", token),
		SecretBytes("destination", []byte(token)),
		SafeError("failure", errors.New(token)),
	)
	if strings.Contains(output.String(), token) {
		t.Fatalf("secret leaked to log: %q", output.String())
	}
	if !strings.Contains(output.String(), Redacted) {
		t.Fatalf("redaction marker absent from log: %q", output.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON logger did not escape structured output: %v\n%s", err, output.Bytes())
	}
	if decoded["msg"] != "request\nreceived" {
		t.Fatalf("message = %#v, want escaped message", decoded["msg"])
	}
}

func TestLoggerValidation(t *testing.T) {
	if _, err := NewLogger(LogConfig{Format: "binary"}); !errors.Is(err, ErrInvalidLogFormat) {
		t.Fatalf("invalid format error = %v", err)
	}
	if _, err := NewLogger(LogConfig{Level: "trace"}); !errors.Is(err, ErrInvalidLogLevel) {
		t.Fatalf("invalid level error = %v", err)
	}
}
