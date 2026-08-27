package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/observability"
)

func createTestNode(t *testing.T) (*ivnp.Node, string, *slog.LevelVar) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ivnp.conf")
	configText := "[paths]\ndata_dir = data\n\n[network]\nid = 2\n\n[router]\nfloodfill = false\n\n[log]\nlevel = info\n"
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	config, err := ivnp.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load test config: %v", err)
	}
	level := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	node, err := ivnp.New(config, ivnp.Options{Logger: logger})
	if err != nil {
		t.Fatalf("create test node: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := node.Close(); closeErr != nil {
			t.Errorf("close test node: %v", closeErr)
		}
	})
	return node, configPath, level
}

func newTestWebUIServer(t *testing.T, config WebUIConfig) *WebUIServer {
	t.Helper()
	node, configPath, level := createTestNode(t)
	if config.ConfigPath == "" {
		config.ConfigPath = configPath
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	server, err := NewWebUIServer(config, node, logger, level)
	if err != nil {
		t.Fatalf("create WebUI server: %v", err)
	}
	return server
}

func TestWebUIAccessPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		address      string
		token        string
		wantLoopback bool
		wantError    bool
	}{
		{name: "localhost", address: "localhost:7070", wantLoopback: true},
		{name: "127 slash 8", address: "127.44.2.9:7070", wantLoopback: true},
		{name: "IPv6 loopback", address: "[::1]:7070", wantLoopback: true},
		{name: "explicit wildcard with token", address: "0.0.0.0:7070", token: "0123456789abcdef", wantLoopback: false},
		{name: "wildcard without token", address: "0.0.0.0:7070", wantError: true},
		{name: "specific LAN address", address: "192.168.1.20:7070", token: "0123456789abcdef", wantError: true},
		{name: "IPv6 wildcard", address: "[::]:7070", token: "0123456789abcdef", wantError: true},
		{name: "missing port", address: "127.0.0.1", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			policy, err := parseWebUIAccessPolicy(test.address, test.token)
			if (err != nil) != test.wantError {
				t.Fatalf("parseWebUIAccessPolicy(%q) error = %v, wantError %v", test.address, err, test.wantError)
			}
			if err == nil && policy.loopback != test.wantLoopback {
				t.Fatalf("parseWebUIAccessPolicy(%q) loopback = %v, want %v", test.address, policy.loopback, test.wantLoopback)
			}
		})
	}
}

func TestReseedActionOutlivesRequest(t *testing.T) {
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0"})
	reseedDone := make(chan struct{})
	reseedContext := make(chan context.Context, 1)
	server.triggerReseed = func(ctx context.Context) (<-chan struct{}, error) {
		reseedContext <- ctx
		return reseedDone, nil
	}
	parent, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := server.Start(parent); err != nil {
		t.Fatalf("start WebUI server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close WebUI server: %v", err)
		}
	})

	response, err := http.Post("http://"+server.listener.Addr().String()+"/api/actions/reseed", "application/json", nil)
	if err != nil {
		t.Fatalf("POST reseed: %v", err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatalf("close reseed response: %v", err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST reseed status = %d", response.StatusCode)
	}
	actionContext := <-reseedContext
	select {
	case <-actionContext.Done():
		t.Fatal("reseed context canceled when HTTP request completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(reseedDone)
	select {
	case <-actionContext.Done():
	case <-time.After(time.Second):
		t.Fatal("reseed context not released after work completed")
	}
}

func TestWebUILoopbackMiddlewareRejectsRemoteHostAndOrigin(t *testing.T) {
	t.Parallel()
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:7070"})
	handler := server.wrapMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		host       string
		method     string
		origin     string
		wantStatus int
	}{
		{name: "loopback request", remoteAddr: "127.8.4.2:42000", host: "localhost:7070", method: http.MethodGet, wantStatus: http.StatusNoContent},
		{name: "remote client", remoteAddr: "192.168.1.9:42000", host: "localhost:7070", method: http.MethodGet, wantStatus: http.StatusForbidden},
		{name: "DNS rebinding host", remoteAddr: "127.0.0.1:42000", host: "attacker.example", method: http.MethodGet, wantStatus: http.StatusForbidden},
		{name: "cross origin mutation", remoteAddr: "127.0.0.1:42000", host: "localhost:7070", method: http.MethodPost, origin: "https://attacker.example", wantStatus: http.StatusForbidden},
		{name: "same origin mutation", remoteAddr: "127.0.0.1:42000", host: "localhost:7070", method: http.MethodPost, origin: "http://localhost:7070", wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, "http://"+test.host+"/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Host = test.host
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			handler.ServeHTTP(record, request)
			if record.Code != test.wantStatus {
				t.Fatalf("middleware status = %d, want %d; body %q", record.Code, test.wantStatus, record.Body.String())
			}
		})
	}
}

func TestWebUIBearerAuthenticationProtectsAPIOnly(t *testing.T) {
	t.Parallel()
	const token = "secret-token-123456"
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "0.0.0.0:7070", BearerToken: token})
	handler := server.wrapMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "http://router.example/", nil)
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusNoContent {
		t.Fatalf("static request status = %d, want %d", record.Code, http.StatusNoContent)
	}

	request = httptest.NewRequest(http.MethodGet, "http://router.example/api/status?token="+token, nil)
	record = httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusUnauthorized {
		t.Fatalf("non-SSE query token status = %d, want %d", record.Code, http.StatusUnauthorized)
	}

	request = httptest.NewRequest(http.MethodGet, "http://router.example/api/status", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	record = httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusNoContent {
		t.Fatalf("bearer request status = %d, want %d", record.Code, http.StatusNoContent)
	}

	request = httptest.NewRequest(http.MethodGet, "http://router.example/api/events?token="+token, nil)
	record = httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusNoContent {
		t.Fatalf("SSE query token status = %d, want %d", record.Code, http.StatusNoContent)
	}
}

func TestTrafficSamplerUsesCounterDeltas(t *testing.T) {
	t.Parallel()
	server := new(WebUIServer)
	start := time.Unix(100, 0)
	server.sampleTraffic(start, observability.Snapshot{Transport: observability.TransportSnapshot{ReceivedBytes: 1000, SentBytes: 800}})
	server.sampleTraffic(start.Add(2*time.Second), observability.Snapshot{Transport: observability.TransportSnapshot{ReceivedBytes: 5000, SentBytes: 2800}})
	server.trafficMu.RLock()
	sample := server.traffic
	server.trafficMu.RUnlock()
	if sample.inRate != 2000 || sample.outRate != 1000 || sample.peakRate != 2000 {
		t.Fatalf("traffic sample = in %d, out %d, peak %d; want 2000, 1000, 2000", sample.inRate, sample.outRate, sample.peakRate)
	}
}

func TestUpdateINIPreservesCommentsAndAddsKeys(t *testing.T) {
	t.Parallel()
	input := "# operator note\n[router]\nfamily = old # retained syntax replaced\nobsolete = remove-me\n\n[log]\nlevel = info\n"
	updates := []iniUpdate{
		{section: "router", key: "family", value: "new"},
		{section: "router", key: "floodfill", value: "true"},
		{section: "tunnel", key: "hops", value: "4"},
		{section: "router", key: "obsolete", remove: true},
	}
	got := updateINI(input, updates)
	for _, wanted := range []string{"# operator note", "family = new", "floodfill = true", "[tunnel]", "hops = 4", "[log]", "level = info"} {
		if !strings.Contains(got, wanted) {
			t.Fatalf("updateINI output missing %q:\n%s", wanted, got)
		}
	}
	if strings.Contains(got, "obsolete") {
		t.Fatalf("updateINI retained removed key:\n%s", got)
	}
}

func TestWebUIConfigViewMarshalsEmptyLists(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(newWebUIConfigView(ivnp.Config{}, ivnp.Config{}))
	if err != nil {
		t.Fatalf("marshal empty config view: %v", err)
	}
	for _, field := range []string{`"endpoints":[]`, `"subscriptions":[]`} {
		if !bytes.Contains(payload, []byte(field)) {
			t.Fatalf("empty config JSON missing %s: %s", field, payload)
		}
	}
}

func TestWritePrivateFileAtomicSucceeds(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ivnp.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}
	if err := writePrivateFileAtomic(path, []byte("new\n")); err != nil {
		t.Fatalf("writePrivateFileAtomic: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if string(content) != "new\n" {
		t.Fatalf("replaced content = %q, want %q", content, "new\\n")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replaced file: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("replaced permissions = %o, want 600", permissions)
	}
}

func TestWebUIServerEndpointsAndConfigUpdate(t *testing.T) {
	node, configPath, level := createTestNode(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	server, err := NewWebUIServer(WebUIConfig{ListenAddress: "127.0.0.1:0", ConfigPath: configPath}, node, logger, level)
	if err != nil {
		t.Fatalf("create WebUI: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err = server.Start(ctx); err != nil {
		t.Fatalf("start WebUI: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("close WebUI: %v", closeErr)
		}
	})
	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := "http://" + server.listener.Addr().String()

	for _, path := range []string{"/", "/api/status", "/api/metrics", "/api/tunnels", "/api/netdb?limit=5", "/api/destinations", "/api/config"} {
		response, requestErr := client.Get(baseURL + path)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", path, requestErr)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read GET %s: %v; close: %v", path, readErr, closeErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, body %s", path, response.StatusCode, body)
		}
		if path == "/" {
			scriptSources, hashErr := inlineScriptCSPHashes(body)
			if hashErr != nil || scriptSources == "" {
				t.Fatalf("bootstrap CSP hashes = %q, error %v", scriptSources, hashErr)
			}
			policy := response.Header.Get("Content-Security-Policy")
			if !strings.Contains(policy, "script-src 'self' "+scriptSources) || strings.Contains(policy, "'unsafe-inline'") {
				t.Fatalf("bootstrap CSP = %q", policy)
			}
		}
	}

	eventsResponse, err := client.Get(baseURL + "/api/events")
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	eventsReader := bufio.NewReader(eventsResponse.Body)
	eventLine, err := eventsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read SSE event name: %v", err)
	}
	dataLine, err := eventsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read SSE event data: %v", err)
	}
	if err = eventsResponse.Body.Close(); err != nil {
		t.Fatalf("close events response: %v", err)
	}
	if eventLine != "event: metrics\n" || !strings.HasPrefix(dataLine, "data: ") {
		t.Fatalf("SSE event = %q %q", eventLine, dataLine)
	}
	var envelope struct {
		Type    string          `json:"type"`
		Metrics metricsResponse `json:"metrics"`
	}
	if err = json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(dataLine, "data: "))), &envelope); err != nil {
		t.Fatalf("decode SSE metrics: %v", err)
	}
	if envelope.Type != "metrics" || envelope.Metrics.SampledAt <= 0 {
		t.Fatalf("SSE metrics envelope = %#v", envelope)
	}

	response, err := client.Get(baseURL + "/api/config")
	if err != nil {
		t.Fatalf("GET config: %v", err)
	}
	var view webUIConfigView
	if err = json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatalf("close config response: %v", err)
	}
	update := webUIConfigUpdateFromView(view)
	update.Log.Level = "debug"
	update.Tunnel.Hops = 4
	payload, err := json.Marshal(update)
	if err != nil {
		t.Fatalf("marshal config update: %v", err)
	}
	response, err = client.Post(baseURL+"/api/config", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST config: %v", err)
	}
	updateBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read update result: %v", err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatalf("close update response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST config status = %d, body %s, update %+v", response.StatusCode, updateBody, update)
	}
	var result configUpdateResult
	if err = json.Unmarshal(updateBody, &result); err != nil {
		t.Fatalf("decode update result: %v", err)
	}
	if level.Level() != slog.LevelDebug {
		t.Fatalf("live log level = %v, want debug", level.Level())
	}
	if !slices.Contains(result.Applied, "log.level") || !slices.Contains(result.RestartRequired, "tunnel.hops") {
		t.Fatalf("update result = %#v", result)
	}
	persisted, err := ivnp.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if persisted.Log.Level != "debug" || persisted.Tunnel.Hops != 4 {
		t.Fatalf("persisted config = log %q, hops %d", persisted.Log.Level, persisted.Tunnel.Hops)
	}
}
