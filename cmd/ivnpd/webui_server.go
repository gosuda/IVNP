package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

//go:embed all:webui/build
var webUIStaticFS embed.FS

const defaultWebUIListenAddress = "127.0.0.1:7070"

var (
	errWebUINodeRequired      = errors.New("webui: node is required")
	errWebUITokenRequired     = errors.New("webui: explicit 0.0.0.0 requires IVNPD_WEBUI_TOKEN with at least 16 bytes")
	errWebUIStarted           = errors.New("webui: already started")
	errReseedNotStarted       = errors.New("reseed attempt did not start; an attempt may be backed off or unnecessary")
	errUnterminatedScriptTag  = errors.New("unterminated script opening tag")
	errUnterminatedScriptBody = errors.New("unterminated script body")
)

// WebUIConfig defines the ivnpd-owned WebUI listener.
type WebUIConfig struct {
	ListenAddress string
	BearerToken   string
	ConfigPath    string
	DisableAuth   bool
	// AllowRemoteWrite permits configuration writes and restarts from
	// non-loopback clients.
	AllowRemoteWrite bool
	// ShowPeers exposes peer router identities when the listener is not
	// loopback-bound.
	ShowPeers bool
	// ConfigOverrides applies the command-line overrides that main applies to
	// the file configuration, so pending changes compare effective values.
	ConfigOverrides func(*state.ConfigurationOperating)
}

type webUIAccessPolicy struct {
	loopback    bool
	listenHost  string
	requireAuth bool
}

type trafficSample struct {
	initialized bool
	at          time.Time
	received    uint64
	sent        uint64
	inRate      uint64
	outRate     uint64
	peakRate    uint64
}

// WebUIServer hosts the static SvelteKit application and its administrative API.
type WebUIServer struct {
	config        WebUIConfig
	policy        webUIAccessPolicy
	logger        *slog.Logger
	logLevel      *slog.LevelVar
	started       time.Time
	triggerReseed func(context.Context) (<-chan struct{}, error)
	restartHook   func() error

	// nodeMu guards node. API handlers hold the read lock for their whole
	// duration, so detachNode returns only after in-flight node calls finish.
	nodeMu     sync.RWMutex
	node       *node.Subsystem
	restarting atomic.Bool

	server   *http.Server
	listener net.Listener

	tokenHash     [32]byte
	scriptSources string

	configMu sync.Mutex

	trafficMu sync.RWMutex
	traffic   trafficSample

	history historyRing
	actions actionLog

	subscribersMu sync.Mutex
	subscribers   map[chan []byte]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type webUINodeContextKey struct{}

// NewWebUIServer validates the listener policy before any socket is opened.
func NewWebUIServer(cfg WebUIConfig, node *node.Subsystem, logger *slog.Logger, level *slog.LevelVar) (*WebUIServer, error) {
	if node == nil {
		return nil, errWebUINodeRequired
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = defaultWebUIListenAddress
	}
	if logger == nil {
		logger = slog.Default()
	}
	host, _, splitErr := net.SplitHostPort(cfg.ListenAddress)
	if splitErr == nil && !cfg.DisableAuth && cfg.BearerToken == "" && !isLoopbackHost(host) {
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err == nil {
			cfg.BearerToken = hex.EncodeToString(tokenBytes)
			logger.Info("WebUI authentication token generated", "token", cfg.BearerToken)
		}
	}
	policy, err := parseWebUIAccessPolicy(cfg.ListenAddress, cfg.BearerToken, cfg.DisableAuth)
	if err != nil {
		return nil, err
	}
	return &WebUIServer{
		config:      cfg,
		policy:      policy,
		node:        node,
		logger:      logger,
		logLevel:    level,
		started:     time.Now(),
		tokenHash:   sha256.Sum256([]byte(cfg.BearerToken)),
		subscribers: make(map[chan []byte]struct{}),
	}, nil
}

// SetRestartHook installs the function that asks main to restart the node.
// It must be called before Start; a nil hook disables the restart action.
func (s *WebUIServer) SetRestartHook(hook func() error) {
	s.restartHook = hook
}

func (s *WebUIServer) currentNode() *node.Subsystem {
	s.nodeMu.RLock()
	defer s.nodeMu.RUnlock()
	return s.node
}

// detachNode stops API access to the current node and waits for in-flight
// node calls to finish. The caller owns closing the detached node.
func (s *WebUIServer) detachNode() {
	s.restarting.Store(true)
	s.nodeMu.Lock()
	s.node = nil
	s.nodeMu.Unlock()
}

// attachNode serves a started node and ends the restarting state.
func (s *WebUIServer) attachNode(next *node.Subsystem) {
	s.nodeMu.Lock()
	s.node = next
	s.nodeMu.Unlock()
	s.restarting.Store(false)
}

// withNode rejects requests while the node is detached and otherwise runs
// next with the node pinned in the request context.
func (s *WebUIServer) withNode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.nodeMu.RLock()
		defer s.nodeMu.RUnlock()
		if s.node == nil {
			writeRestarting(w)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), webUINodeContextKey{}, s.node)))
	}
}

// requestNode returns the node pinned by withNode. Handlers invoked without
// withNode fall back to the current node.
func (s *WebUIServer) requestNode(r *http.Request) *node.Subsystem {
	if pinned, ok := r.Context().Value(webUINodeContextKey{}).(*node.Subsystem); ok {
		return pinned
	}
	return s.currentNode()
}

// sampleNode runs sample with the current node held, skipping it while the
// node is detached.
func (s *WebUIServer) sampleNode(sample func(*node.Subsystem)) {
	s.nodeMu.RLock()
	defer s.nodeMu.RUnlock()
	if s.node != nil {
		sample(s.node)
	}
}

func writeRestarting(w http.ResponseWriter) {
	writeJSONResponse(w, http.StatusServiceUnavailable, struct {
		Error      string `json:"error"`
		Restarting bool   `json:"restarting"`
	}{Error: "router restarting", Restarting: true})
}

func parseWebUIAccessPolicy(listenAddress, bearerToken string, disableAuth ...bool) (webUIAccessPolicy, error) {
	noAuth := len(disableAuth) > 0 && disableAuth[0]
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return webUIAccessPolicy{}, fmt.Errorf("webui: listen address must include host and port: %w", err)
	}
	if noAuth {
		return webUIAccessPolicy{loopback: false, listenHost: host, requireAuth: false}, nil
	}
	if strings.EqualFold(host, "localhost") {
		return webUIAccessPolicy{loopback: true, listenHost: "localhost", requireAuth: bearerToken != ""}, nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return webUIAccessPolicy{loopback: true, listenHost: host, requireAuth: bearerToken != ""}, nil
	}
	if ip == nil && host != "0.0.0.0" {
		return webUIAccessPolicy{}, fmt.Errorf("webui: listen host %q is not a valid IP or hostname", host)
	}
	if len(bearerToken) < 16 {
		return webUIAccessPolicy{}, errWebUITokenRequired
	}
	return webUIAccessPolicy{loopback: false, listenHost: host, requireAuth: true}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start opens the listener and starts the telemetry stream.
func (s *WebUIServer) Start(parent context.Context) error {
	if s.server != nil {
		return errWebUIStarted
	}
	if parent == nil {
		parent = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(parent)

	listener, err := (&net.ListenConfig{}).Listen(s.ctx, "tcp", s.config.ListenAddress)
	if err != nil {
		s.cancel()
		return fmt.Errorf("webui: listen %s: %w", s.config.ListenAddress, err)
	}
	s.listener = listener

	staticFS, err := fs.Sub(webUIStaticFS, "webui/build")
	if err != nil {
		_ = listener.Close()
		s.cancel()
		return fmt.Errorf("webui: static assets: %w", err)
	}
	indexDocument, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		_ = listener.Close()
		s.cancel()
		return fmt.Errorf("webui: read static bootstrap: %w", err)
	}
	s.scriptSources, err = inlineScriptCSPHashes(indexDocument)
	if err != nil {
		_ = listener.Close()
		s.cancel()
		return fmt.Errorf("webui: secure static bootstrap: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/livez", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/varz", s.handleVarz)
	mux.HandleFunc("/api/status", s.withNode(s.handleStatus))
	mux.HandleFunc("/api/metrics", s.withNode(s.handleMetrics))
	mux.HandleFunc("/api/tunnels", s.withNode(s.handleTunnels))
	mux.HandleFunc("/api/netdb", s.withNode(s.handleNetDB))
	mux.HandleFunc("/api/peers", s.withNode(s.handlePeers))
	mux.HandleFunc("/api/destinations", s.withNode(s.handleDestinations))
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/config/rollback", s.withNode(s.handleConfigRollback))
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/actions/log", s.handleActionsLog)
	mux.HandleFunc("/api/actions/reseed", s.withNode(s.handleActionReseed))
	mux.HandleFunc("/api/actions/tunnel-probe", s.withNode(s.handleActionTunnelProbe))
	mux.HandleFunc("/api/actions/restart", s.handleActionRestart)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.Handle("/", s.staticHandler(staticFS))

	s.server = &http.Server{
		Handler:           s.wrapMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	s.sampleNode(func(current *node.Subsystem) {
		now := time.Now()
		snapshot := current.RegistrySnapshot()
		s.sampleTraffic(now, snapshot)
		s.recordHistory(now, snapshot)
	})
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if serveErr := s.server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("webui server stopped", "error", serveErr)
		}
	}()
	go s.broadcastLoop()

	s.logger.Info("WebUI active", "listen", listener.Addr().String(), "loopback_only", s.policy.loopback, "authenticated", s.policy.requireAuth)
	return nil
}

func (s *WebUIServer) staticHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := cmp.Or(strings.TrimPrefix(r.URL.Path, "/"), "index.html")
		if _, err := fs.Stat(staticFS, path); errors.Is(err, fs.ErrNotExist) {
			request := r.Clone(r.Context())
			request.URL.Path = "/"
			fileServer.ServeHTTP(w, request)
			return
		}
		if strings.HasPrefix(path, "_app/immutable/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}
func (s *WebUIServer) startReseedAction(current *node.Subsystem) error {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	timeout := current.Config().Reseed.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	trigger := s.triggerReseed
	if trigger == nil {
		trigger = current.TriggerReseed
	}
	actionContext, cancel := context.WithTimeout(parent, timeout)
	done, err := trigger(actionContext)
	if err != nil {
		cancel()
		return err
	}
	if done == nil {
		cancel()
		return errReseedNotStarted
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		select {
		case <-done:
		case <-actionContext.Done():
		}
	}()
	return nil
}

// Close gracefully terminates the server and every telemetry subscriber.
func (s *WebUIServer) Close() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	var result error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		graceful := s.server.Shutdown(ctx)
		cancel()
		if graceful != nil {
			// Shutdown can miss a keep-alive connection racing from active to
			// idle and block for the whole grace window. Force-close finishes
			// the job, so only a force-close failure is a close failure.
			result = s.server.Close()
			if result != nil {
				result = errors.Join(graceful, result)
			}
		}
	}
	s.subscribersMu.Lock()
	for subscriber := range s.subscribers {
		close(subscriber)
		delete(s.subscribers, subscriber)
	}
	s.subscribersMu.Unlock()
	s.wg.Wait()
	return result
}

func isPublicProbePath(path string) bool {
	return path == "/healthz" || path == "/livez" || path == "/readyz" || path == "/varz"
}

func (s *WebUIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if current := s.currentNode(); current != nil && current.Status().Running {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("{\"status\":\"unavailable\"}\n"))
}

func (s *WebUIServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if current := s.currentNode(); current != nil {
		clientStatus, _ := current.ClientStatus(r.Context())
		if clientStatus.Ready {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("{\"status\":\"unavailable\"}\n"))
}

func (s *WebUIServer) handleVarz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	s.withNode(func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, s.metricsResponse(s.requestNode(r)))
	})(w, r)
}

func (s *WebUIServer) wrapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setSecurityHeaders(w)
		if isPublicProbePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.policy.loopback && !remoteIsLoopback(r.RemoteAddr) {
			http.Error(w, "loopback clients only", http.StatusForbidden)
			return
		}
		if s.policy.loopback && !allowedLoopbackHost(r.Host) {
			http.Error(w, "host mismatch", http.StatusForbidden)
			return
		}
		if requestChangesState(r.Method) && !sameOriginRequest(r) {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && s.policy.requireAuth && !s.isAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ivnp-webui"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *WebUIServer) setSecurityHeaders(w http.ResponseWriter) {
	scriptPolicy := "'self'"
	if s.scriptSources != "" {
		scriptPolicy += " " + s.scriptSources
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src "+scriptPolicy+"; style-src 'self'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func inlineScriptCSPHashes(document []byte) (string, error) {
	lowerDocument := bytes.ToLower(document)
	const closingTag = "</script>"
	var sources []string
	for offset := 0; offset < len(document); {
		relativeStart := bytes.Index(lowerDocument[offset:], []byte("<script"))
		if relativeStart < 0 {
			break
		}
		tagStart := offset + relativeStart
		relativeTagEnd := bytes.IndexByte(lowerDocument[tagStart:], '>')
		if relativeTagEnd < 0 {
			return "", errUnterminatedScriptTag
		}
		bodyStart := tagStart + relativeTagEnd + 1
		relativeBodyEnd := bytes.Index(lowerDocument[bodyStart:], []byte(closingTag))
		if relativeBodyEnd < 0 {
			return "", errUnterminatedScriptBody
		}
		bodyEnd := bodyStart + relativeBodyEnd
		openingTag := lowerDocument[tagStart:bodyStart]
		if !bytes.Contains(openingTag, []byte("src=")) {
			digest := sha256.Sum256(document[bodyStart:bodyEnd])
			sources = append(sources, "'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'")
		}
		offset = bodyEnd + len(closingTag)
	}
	return strings.Join(sources, " "), nil
}

func remoteIsLoopback(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowedLoopbackHost(hostPort string) bool {
	host := hostPort
	if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
		host = parsedHost
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requestChangesState(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func (s *WebUIServer) isAuthorized(r *http.Request) bool {
	authorization := r.Header.Get("Authorization")
	kind, token, ok := strings.Cut(authorization, " ")
	if ok && strings.EqualFold(kind, "Bearer") && s.tokenMatches(token) {
		return true
	}
	return r.URL.Path == "/api/events" && s.tokenMatches(r.URL.Query().Get("token"))
}

func (s *WebUIServer) tokenMatches(token string) bool {
	if token == "" {
		return false
	}
	provided := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(provided[:], s.tokenHash[:]) == 1
}

func (s *WebUIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	var initialMetrics metricsResponse
	attached := false
	s.sampleNode(func(current *node.Subsystem) {
		initialMetrics, attached = s.metricsResponse(current), true
	})
	if !attached {
		writeRestarting(w)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")

	messages := make(chan []byte, 4)
	s.subscribersMu.Lock()
	s.subscribers[messages] = struct{}{}
	s.subscribersMu.Unlock()
	defer func() {
		s.subscribersMu.Lock()
		delete(s.subscribers, messages)
		s.subscribersMu.Unlock()
	}()

	initial, err := json.Marshal(struct {
		Type    string          `json:"type"`
		Metrics metricsResponse `json:"metrics"`
	}{Type: "metrics", Metrics: initialMetrics})
	if err != nil {
		http.Error(w, "telemetry unavailable", http.StatusInternalServerError)
		return
	}
	if _, err = fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", initial); err != nil {
		return
	}
	flusher.Flush()

	var serverDone <-chan struct{}
	if s.ctx != nil {
		serverDone = s.ctx.Done()
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-serverDone:
			return
		case message, open := <-messages:
			if !open {
				return
			}
			if _, err = fmt.Fprintf(w, "event: metrics\ndata: %s\n\n", message); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *WebUIServer) broadcastLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	historyTicker := time.NewTicker(historyInterval)
	defer historyTicker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			var payload []byte
			s.sampleNode(func(current *node.Subsystem) {
				snapshot := current.RegistrySnapshot()
				s.sampleTraffic(now, snapshot)
				payload, _ = json.Marshal(struct {
					Type    string          `json:"type"`
					Metrics metricsResponse `json:"metrics"`
				}{Type: "metrics", Metrics: s.metricsFromSnapshot(current.Config(), snapshot)})
			})
			if payload != nil {
				s.broadcast(payload)
			}
		case now := <-historyTicker.C:
			s.sampleNode(func(current *node.Subsystem) {
				s.recordHistory(now, current.RegistrySnapshot())
			})
		}
	}
}

func (s *WebUIServer) broadcast(payload []byte) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	for subscriber := range s.subscribers {
		select {
		case subscriber <- payload:
		default:
		}
	}
}

func (s *WebUIServer) sampleTraffic(now time.Time, snapshot ivnpObservabilitySnapshot) {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()
	if !s.traffic.initialized {
		s.traffic = trafficSample{initialized: true, at: now, received: snapshot.Transport.ReceivedBytes, sent: snapshot.Transport.SentBytes}
		return
	}
	elapsed := now.Sub(s.traffic.at)
	if elapsed <= 0 {
		return
	}
	seconds := elapsed.Seconds()
	inRate := counterRate(snapshot.Transport.ReceivedBytes, s.traffic.received, seconds)
	outRate := counterRate(snapshot.Transport.SentBytes, s.traffic.sent, seconds)
	s.traffic.at = now
	s.traffic.received = snapshot.Transport.ReceivedBytes
	s.traffic.sent = snapshot.Transport.SentBytes
	s.traffic.inRate = inRate
	s.traffic.outRate = outRate
	s.traffic.peakRate = max(s.traffic.peakRate, inRate, outRate)
}

func counterRate(current, previous uint64, seconds float64) uint64 {
	if current < previous || seconds <= 0 {
		return 0
	}
	return uint64(float64(current-previous) / seconds)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
