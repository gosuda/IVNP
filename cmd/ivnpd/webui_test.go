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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

func createTestNode(t *testing.T) (*node.Subsystem, string, *slog.LevelVar) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ivnp.conf")
	configText := "[paths]\ndata_dir = data\n\n[network]\nid = 2\n\n[router]\nfloodfill = false\n\n[log]\nlevel = info\n"
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	config, err := state.ConfigurationLoadOperating(configPath)
	if err != nil {
		t.Fatalf("load test config: %v", err)
	}
	level := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	node, err := node.NewSubsystem(config, node.Options{Logger: logger})
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

func startTestWebUIServer(t *testing.T, server *WebUIServer) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := server.Start(ctx); err != nil {
		t.Fatalf("start WebUI: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("close WebUI: %v", closeErr)
		}
	})
	return "http://" + server.listener.Addr().String()
}

func TestWebUIAccessPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		address      string
		token        string
		disableAuth  bool
		wantLoopback bool
		wantError    bool
	}{
		{name: "localhost", address: "localhost:7070", wantLoopback: true},
		{name: "127 slash 8", address: "127.44.2.9:7070", wantLoopback: true},
		{name: "IPv6 loopback", address: "[::1]:7070", wantLoopback: true},
		{name: "explicit wildcard with token", address: "0.0.0.0:7070", token: "0123456789abcdef", wantLoopback: false},
		{name: "wildcard without token", address: "0.0.0.0:7070", wantError: true},
		{name: "wildcard with disableAuth", address: "0.0.0.0:7070", disableAuth: true, wantLoopback: false},
		{name: "specific LAN address with token", address: "192.168.1.20:7070", token: "0123456789abcdef", wantLoopback: false},
		{name: "specific LAN address with disableAuth", address: "192.168.1.20:7070", disableAuth: true, wantLoopback: false},
		{name: "IPv6 wildcard with token", address: "[::]:7070", token: "0123456789abcdef", wantLoopback: false},
		{name: "missing port", address: "127.0.0.1", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			policy, err := parseWebUIAccessPolicy(test.address, test.token, test.disableAuth)
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
	if record.Code != http.StatusUnauthorized {
		t.Fatalf("SSE query bearer token status = %d, want %d", record.Code, http.StatusUnauthorized)
	}
}


func TestWebUISSETicketAuthorization(t *testing.T) {
	t.Parallel()
	const token = "secret-token-123456"
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "0.0.0.0:7070", BearerToken: token})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/events/ticket", server.handleSSETicket)
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := server.wrapMiddleware(mux)
	request := func(method, path, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://router.example"+path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	for _, test := range []struct {
		name   string
		method string
		path   string
		bearer string
		want   int
	}{
		{name: "ticket without bearer", method: http.MethodPost, path: "/api/events/ticket", want: http.StatusUnauthorized},
		{name: "ticket with query bearer", method: http.MethodPost, path: "/api/events/ticket?token=" + token, want: http.StatusUnauthorized},
		{name: "SSE with query bearer", method: http.MethodGet, path: "/api/events?token=" + token, want: http.StatusUnauthorized},
		{name: "unknown ticket", method: http.MethodGet, path: "/api/events?ticket=unknown", want: http.StatusUnauthorized},
		{name: "ticket issuance requires POST", method: http.MethodGet, path: "/api/events/ticket", bearer: token, want: http.StatusMethodNotAllowed},
		{name: "SSE accepts bearer header", method: http.MethodGet, path: "/api/events", bearer: token, want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := request(test.method, test.path, test.bearer).Code; got != test.want {
				t.Errorf("%s %s status = %d, want %d", test.method, test.path, got, test.want)
			}
		})
	}

	issued := request(http.MethodPost, "/api/events/ticket", token)
	if issued.Code != http.StatusOK {
		t.Fatalf("POST /api/events/ticket status = %d, want 200; body %q", issued.Code, issued.Body.String())
	}
	if got := issued.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("ticket Cache-Control = %q, want no-store", got)
	}
	var result struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode SSE ticket: %v", err)
	}
	if len(result.Ticket) != 43 {
		t.Fatalf("SSE ticket length = %d, want 43", len(result.Ticket))
	}
	for _, test := range []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "ticket cannot authorize status", method: http.MethodGet, path: "/api/status?ticket=" + result.Ticket, want: http.StatusUnauthorized},
		{name: "ticket cannot authorize POST", method: http.MethodPost, path: "/api/events?ticket=" + result.Ticket, want: http.StatusUnauthorized},
		{name: "ticket authorizes SSE once", method: http.MethodGet, path: "/api/events?ticket=" + result.Ticket, want: http.StatusNoContent},
		{name: "ticket replay rejected", method: http.MethodGet, path: "/api/events?ticket=" + result.Ticket, want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := request(test.method, test.path, "").Code; got != test.want {
				t.Errorf("%s %s status = %d, want %d", test.method, "/api/events", got, test.want)
			}
		})
	}

	expired := request(http.MethodPost, "/api/events/ticket", token)
	if expired.Code != http.StatusOK {
		t.Fatalf("POST /api/events/ticket for expiry status = %d, want 200", expired.Code)
	}
	var expiredResult struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(expired.Body.Bytes(), &expiredResult); err != nil {
		t.Fatalf("decode expiring ticket: %v", err)
	}
	server.ticketsMu.Lock()
	server.tickets[expiredResult.Ticket] = time.Now().Add(-time.Second)
	server.ticketsMu.Unlock()
	if got := request(http.MethodGet, "/api/events?ticket="+expiredResult.Ticket, "").Code; got != http.StatusUnauthorized {
		t.Errorf("GET expired SSE ticket status = %d, want 401", got)
	}
}

func TestWebUISSETicketCapacity(t *testing.T) {
	t.Parallel()
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "0.0.0.0:7070", BearerToken: "secret-token-123456"})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/events/ticket", server.handleSSETicket)
	handler := server.wrapMiddleware(mux)
	issue := func() int {
		r := httptest.NewRequest(http.MethodPost, "http://router.example/api/events/ticket", nil)
		r.Header.Set("Authorization", "Bearer secret-token-123456")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	for i := range maxSSETickets - 1 {
		server.tickets[strconv.Itoa(i)] = time.Now().Add(time.Minute)
	}
	if got := issue(); got != http.StatusOK {
		t.Fatalf("issue at ticket limit status = %d, want 200", got)
	}
	if got := issue(); got != http.StatusTooManyRequests {
		t.Errorf("issue beyond ticket limit status = %d, want 429", got)
	}
	server.ticketsMu.Lock()
	server.tickets["0"] = time.Now().Add(-time.Second)
	server.ticketsMu.Unlock()
	if got := issue(); got != http.StatusOK {
		t.Errorf("issue after expiring ticket status = %d, want 200", got)
	}
}

func TestWebUISSETicketConcurrentConsumption(t *testing.T) {
	t.Parallel()
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "0.0.0.0:7070", BearerToken: "secret-token-123456"})
	ticket := strings.Repeat("a", 43)
	server.tickets[ticket] = time.Now().Add(time.Minute)

	const attempts = 32
	results := make(chan bool, attempts)
	for range attempts {
		go func() {
			results <- server.consumeSSETicket(ticket, time.Now())
		}()
	}
	var successes int
	for range attempts {
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("concurrent SSE ticket consumption successes = %d, want 1", successes)
	}
}

func TestWebUIAuthenticatedMetricsEvents(t *testing.T) {
	t.Parallel()
	const token = "secret-token-123456"
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0", BearerToken: token})
	baseURL := startTestWebUIServer(t, server)
	client := &http.Client{Timeout: 3 * time.Second}

	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/events/ticket", nil)
	if err != nil {
		t.Fatalf("build ticket request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	issued, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST SSE ticket: %v", err)
	}
	var payload struct {
		Ticket string `json:"ticket"`
	}
	decodeErr := json.NewDecoder(issued.Body).Decode(&payload)
	closeErr := issued.Body.Close()
	if issued.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil {
		t.Fatalf("POST SSE ticket status = %d, decode = %v, close = %v", issued.StatusCode, decodeErr, closeErr)
	}

	eventURL := baseURL + "/api/events?ticket=" + url.QueryEscape(payload.Ticket)
	stream, err := client.Get(eventURL)
	if err != nil {
		t.Fatalf("GET SSE with ticket: %v", err)
	}
	if stream.StatusCode != http.StatusOK {
		_ = stream.Body.Close()
		t.Fatalf("GET SSE with ticket status = %d, want 200", stream.StatusCode)
	}
	line, readErr := bufio.NewReader(stream.Body).ReadString('\n')
	closeErr = stream.Body.Close()
	if readErr != nil || line != "event: metrics\n" || closeErr != nil {
		t.Fatalf("SSE first line = %q, read = %v, close = %v", line, readErr, closeErr)
	}
	replay, err := client.Get(eventURL)
	if err != nil {
		t.Fatalf("GET SSE replay: %v", err)
	}
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET SSE replay status = %d, want 401", replay.StatusCode)
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
	payload, err := json.Marshal(newWebUIConfigView(state.ConfigurationOperating{}, state.ConfigurationOperating{}))
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

func TestWebUIServerRoutesAndMetricsEvents(t *testing.T) {
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0"})
	baseURL := startTestWebUIServer(t, server)
	client := &http.Client{Timeout: 3 * time.Second}

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
}

func TestWebUIBootstrapEnforcesScriptCSP(t *testing.T) {
	server := newTestWebUIServer(t, WebUIConfig{ListenAddress: "127.0.0.1:0"})
	baseURL := startTestWebUIServer(t, server)
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET bootstrap: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read bootstrap: %v; close: %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET bootstrap status = %d, body %s", response.StatusCode, body)
	}
	scriptSources, err := inlineScriptCSPHashes(body)
	if err != nil || scriptSources == "" {
		t.Fatalf("bootstrap CSP hashes = %q, error %v", scriptSources, err)
	}
	policy := response.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self' "+scriptSources) || strings.Contains(policy, "'unsafe-inline'") {
		t.Fatalf("bootstrap CSP = %q", policy)
	}
}

func TestWebUIConfigUpdatePersistsAndReportsApplyMode(t *testing.T) {
	node, configPath, level := createTestNode(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	server, err := NewWebUIServer(WebUIConfig{ListenAddress: "127.0.0.1:0", ConfigPath: configPath}, node, logger, level)
	if err != nil {
		t.Fatalf("create WebUI: %v", err)
	}
	baseURL := startTestWebUIServer(t, server)
	client := &http.Client{Timeout: 3 * time.Second}

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
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET config status = %d, want %d", response.StatusCode, http.StatusOK)
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
	if result.Status != "saved" {
		t.Errorf("update status = %q, want saved", result.Status)
	}
	if level.Level() != slog.LevelDebug {
		t.Fatalf("live log level = %v, want debug", level.Level())
	}
	if !slices.Contains(result.Applied, "log.level") || !slices.Contains(result.RestartRequired, "tunnel.hops") {
		t.Fatalf("update result = %#v", result)
	}
	if slices.Contains(result.Applied, "tunnel.hops") || slices.Contains(result.RestartRequired, "log.level") {
		t.Errorf("update reports incorrect apply mode: %#v", result)
	}
	persisted, err := state.ConfigurationLoadOperating(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if persisted.Log.Level != "debug" || persisted.Tunnel.Hops != 4 {
		t.Fatalf("persisted config = log %q, hops %d", persisted.Log.Level, persisted.Tunnel.Hops)
	}
}

func TestWebUIProbeEndpoints(t *testing.T) {
	server := newTestWebUIServer(t, WebUIConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   "0123456789abcdef",
	})
	baseURL := startTestWebUIServer(t, server)

	// Node is not running yet in test harness, so healthz and readyz return 503 unavailable
	for _, probe := range []string{"/healthz", "/livez", "/readyz"} {
		response, err := http.Get(baseURL + probe)
		if err != nil {
			t.Fatalf("GET %s error = %v", probe, err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("GET %s status = %d, want 503, body %s", probe, response.StatusCode, body)
		}
		if !strings.Contains(string(body), "unavailable") {
			t.Fatalf("GET %s expected unavailable, got %s", probe, body)
		}
	}

	// Varz returns 200 with JSON metrics even without bearer token
	response, err := http.Get(baseURL + "/varz")
	if err != nil {
		t.Fatalf("GET /varz error = %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /varz status = %d, want 200, body %s", response.StatusCode, body)
	}
	if !strings.Contains(string(body), "bandwidth") {
		t.Fatalf("GET /varz expected bandwidth metrics, got %s", body)
	}
}

func TestWebUIConfigInMemoryConflict(t *testing.T) {
	node, _, level := createTestNode(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
	server, err := NewWebUIServer(WebUIConfig{
		ListenAddress: "127.0.0.1:0",
		ConfigPath:    "",
	}, node, logger, level)
	if err != nil {
		t.Fatalf("create WebUI server: %v", err)
	}
	baseURL := startTestWebUIServer(t, server)

	response, err := http.Get(baseURL + "/api/config")
	if err != nil {
		t.Fatalf("GET /api/config: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config status = %d, want 200", response.StatusCode)
	}

	payload := `{"log":{"level":"debug"}}`
	response, err = http.Post(baseURL+"/api/config", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /api/config: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/config status = %d, want 409, body: %s", response.StatusCode, body)
	}
}
