package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertifyDurationCannotBeOverridden(t *testing.T) {
	_, err := parseOptions([]string{"--mode", "certify", "--duration", "3599s"})
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("certify duration override error = %v", err)
	}
}

func TestCertifyDurationIsExactlyOneHour(t *testing.T) {
	opts := parseTestOptions(t, "certify", "")
	if opts.duration != time.Hour {
		t.Fatalf("certify duration = %v, want 1h", opts.duration)
	}
}

func TestSmokeDurationRemainsIneligibleForCertification(t *testing.T) {
	opts := parseTestOptions(t, "smoke", "3s")
	if opts.duration != 3*time.Second || opts.mode != "smoke" {
		t.Fatalf("smoke options = mode %q duration %v", opts.mode, opts.duration)
	}
}

func TestReadinessRefusesMissingEvidence(t *testing.T) {
	missing := readinessMissing("ok", map[string]uint64{"ivnp_netdb_routers": 50})
	if len(missing) == 0 {
		t.Fatal("missing publication/tunnel/vector metrics were accepted")
	}
}

func TestLocalReadinessUsesPinnedSparseTopologyBaseline(t *testing.T) {
	metrics := map[string]uint64{
		"ivnp_bootstrap_stage": 2, "ivnp_netdb_routers": 3,
		"ivnp_publication_router_info_successes_total": 1, "ivnp_publication_lease_set2_successes_total": 1,
		"ivnp_tunnel_exploratory_inbound_active": 1, "ivnp_tunnel_exploratory_outbound_active": 1,
		"ivnp_tunnel_client_inbound_active": 1, "ivnp_tunnel_client_outbound_active": 1,
		"ivnp_ssu2_vector_io_enabled": 1, "ivnp_ssu2_kernel_drop_accounting": 1,
		"ivnp_process_goroutines": 1, "ivnp_process_heap_inuse_bytes": 1, "ivnp_process_heap_objects": 1,
		"ivnp_process_allocated_bytes_total": 1, "ivnp_process_mallocs_total": 1,
		"ivnp_process_gc_cycles_total": 0, "ivnp_process_gc_pause_nanoseconds_total": 0,
		"ivnp_transport_sessions": 3,
	}
	if missing := readinessMissingForScope("local", "ok", metrics); len(missing) != 0 {
		t.Fatalf("local readiness missing = %v", missing)
	}
	if missing := readinessMissingForScope("public", "ok", metrics); len(missing) == 0 {
		t.Fatal("public readiness accepted local transport sessions without router reachability")
	}
}

func TestPublicEvidenceRequiresSignedRunRouterEndpointAndTimeBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	payload := publicProbePayload{
		Schema: "ivnp.public-reachability/v1", RunID: strings.Repeat("a", 32), RouterHash: strings.Repeat("b", 44),
		TCPEndpoint: "203.0.113.10:29442", UDPEndpoint: "203.0.113.10:29443",
		VantageIP: "198.51.100.7", Nonce: "probe-nonce", StartedUTC: start.Add(time.Second), EndedUTC: start.Add(2 * time.Second),
		TCPPassed: true, UDPPassed: true,
	}
	payloadWire, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	evidence := signedPublicProbeEvidence{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payloadWire))}
	wire, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	source, artifacts := filepath.Join(t.TempDir(), "evidence.json"), t.TempDir()
	if err = os.WriteFile(source, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(public)
	if err = validatePublicProbeEvidence(source, key, payload.RunID, payload.RouterHash, "203.0.113.10", artifacts, start, start.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = validatePublicProbeEvidence(source, key, strings.Repeat("c", 32), payload.RouterHash, "203.0.113.10", artifacts, start, start.Add(3*time.Second)); err == nil {
		t.Fatal("signed evidence was accepted for a different run")
	}
	if err = os.WriteFile(source, append(wire, []byte("\n{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = validatePublicProbeEvidence(source, key, payload.RunID, payload.RouterHash, "203.0.113.10", artifacts, start, start.Add(3*time.Second)); err == nil {
		t.Fatal("signed evidence with trailing data was accepted")
	}
}

func TestFinalEvidenceRejectsMissingCounters(t *testing.T) {
	if err := checkFinalEvidence(map[string]uint64{}, map[string]uint64{}); err == nil {
		t.Fatal("missing protocol/vector/accounting evidence was accepted")
	}
}

func TestHardCountersRequireZeroBaseline(t *testing.T) {
	names := []string{
		"ivnp_lifecycle_failures_total",
		"ivnp_ingress_recovered_panics_total",
		"ivnp_ssu2_receive_queue_drops_total",
		"ivnp_ssu2_kernel_drops_total",
		"ivnp_ssu2_send_failed_datagrams_total",
		"ivnp_ssu2_send_queue_drops_total",
		"ivnp_proxy_failures_total",
		"ivnp_control_failures_total",
		"ivnp_sam_protocol_failures_total",
	}
	baseline, current := map[string]uint64{}, map[string]uint64{}
	for _, name := range names {
		baseline[name], current[name] = 0, 0
	}
	for _, pair := range [][2]string{
		{"ivnp_transport_handshake_failures_total", "ivnp_transport_connections_total"},
		{"ivnp_publication_send_failures_total", "ivnp_publication_attempts_total"},
		{"ivnp_publication_timeouts_total", "ivnp_publication_attempts_total"},
		{"ivnp_tunnel_build_failures_total", "ivnp_tunnel_builds_total"},
		{"ivnp_netdb_lookup_failures_total", "ivnp_netdb_lookups_total"},
		{"ivnp_netdb_store_failures_total", "ivnp_netdb_stores_total"},
		{"ivnp_reseed_failures_total", "ivnp_reseed_attempts_total"},
	} {
		baseline[pair[0]], current[pair[0]] = 0, 0
		baseline[pair[1]], current[pair[1]] = 0, 0
	}
	if err := checkHardCounters(baseline, current); err != nil {
		t.Fatalf("zero hard-failure baseline rejected: %v", err)
	}
	baseline["ivnp_lifecycle_failures_total"] = 1
	current["ivnp_lifecycle_failures_total"] = 1
	if err := checkHardCounters(baseline, current); err == nil {
		t.Fatal("nonzero hard-failure baseline accepted")
	}
}

func TestFinalEvidenceConservationAllowsOptionalPeerEvents(t *testing.T) {
	baseline := map[string]uint64{}
	current := map[string]uint64{}
	for _, name := range []string{
		"ivnp_transport_received_bytes_total",
		"ivnp_transport_sent_bytes_total",
		"ivnp_netdb_lookups_total",
		"ivnp_netdb_stores_total",
		"ivnp_garlic_ecies_new_session_sent_total",
		"ivnp_garlic_ecies_new_session_received_total",
		"ivnp_garlic_ecies_existing_session_sent_total",
		"ivnp_garlic_ecies_existing_session_received_total",
		"ivnp_garlic_tunnel_cloves_forwarded_total",
	} {
		baseline[name], current[name] = 0, 1
	}
	current["ivnp_ssu2_received_datagrams_total"] = 3
	current["ivnp_ssu2_enqueued_datagrams_total"] = 3
	current["ivnp_ssu2_processed_datagrams_total"] = 2
	current["ivnp_ssu2_receive_queue_drops_total"] = 0
	current["ivnp_ssu2_kernel_drops_total"] = 0
	current["ivnp_ssu2_send_enqueued_datagrams_total"] = 3
	current["ivnp_ssu2_sent_datagrams_total"] = 2
	current["ivnp_ssu2_send_failed_datagrams_total"] = 0
	current["ivnp_ssu2_send_queue_drops_total"] = 0
	current["ivnp_ssu2_ingress_queue_depth"] = 1
	current["ivnp_ssu2_egress_queue_depth"] = 1
	for _, name := range []string{
		"ivnp_garlic_ecies_dh_steps_sent_total",
		"ivnp_garlic_ecies_dh_steps_received_total",
		"ivnp_tunnel_participating_forwarded_total",
		"ivnp_ssu2_receive_multi_batches_total",
		"ivnp_ssu2_send_multi_batches_total",
	} {
		current[name] = 0
	}
	for _, name := range []string{"ivnp_sam_udp_invalid_total", "ivnp_sam_udp_backpressure_rejections_total", "ivnp_sam_protocol_failures_total"} {
		current[name] = 0
	}
	if err := checkFinalEvidence(baseline, current); err != nil {
		t.Fatalf("conserved final evidence rejected: %v", err)
	}
}
func TestChecksumsCoverRetainedArtifacts(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "events.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "summary.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeChecksums(directory); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(directory, "checksums.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(wire)
	if !strings.Contains(text, "events.jsonl") || !strings.Contains(text, "summary.json") || strings.Contains(text, "checksums.sha256") {
		t.Fatalf("checksum manifest = %q", text)
	}
}

func parseTestOptions(t *testing.T, mode, duration string) options {
	t.Helper()
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("test-control-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--mode", mode,
		"--scope", "local",
		"--artifacts", filepath.Join(directory, "artifacts"),
		"--ivnp-binary", filepath.Join(directory, "ivnp"),
		"--ivnp-config", filepath.Join(directory, "ivnp.conf"),
		"--control-token-file", token,
		"--java-container", "java",
		"--i2pd-a-container", "i2pd-a",
		"--i2pd-b-container", "i2pd-b",
		"--pinned-router-hashes", "java=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,i2pd-a=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=,i2pd-b=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
		"--java-image-id", "sha256:java",
		"--i2pd-image-id", "sha256:i2pd",
		"--builder-image-id", "sha256:builder",
	}
	if duration != "" {
		args = append(args, "--duration", duration)
	}
	opts, err := parseOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	return opts
}
