package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
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
	"time"

	"gosuda.org/ivnp"
)

//go:embed all:webui/build
var webUIStaticFS embed.FS

const defaultWebUIListenAddress = "127.0.0.1:7070"

// WebUIConfig defines the ivnpd-owned WebUI listener.
type WebUIConfig struct {
	ListenAddress string
	BearerToken   string
	ConfigPath    string
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
	node          *ivnp.Node
	logger        *slog.Logger
	logLevel      *slog.LevelVar
	started       time.Time
	triggerReseed func(context.Context) (<-chan struct{}, error)

	server   *http.Server
	listener net.Listener

	tokenHash     [32]byte
	scriptSources string

	configMu        sync.RWMutex
	persistedConfig ivnp.Config

	trafficMu sync.RWMutex
	traffic   trafficSample

	subscribersMu sync.Mutex
	subscribers   map[chan []byte]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewWebUIServer validates the listener policy before any socket is opened.
func NewWebUIServer(cfg WebUIConfig, node *ivnp.Node, logger *slog.Logger, level *slog.LevelVar) (*WebUIServer, error) {
	if node == nil {
		return nil, errors.New("webui: node is required")
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = defaultWebUIListenAddress
	}
	policy, err := parseWebUIAccessPolicy(cfg.ListenAddress, cfg.BearerToken)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebUIServer{
		config:          cfg,
		policy:          policy,
		node:            node,
		logger:          logger,
		logLevel:        level,
		started:         time.Now(),
		tokenHash:       sha256.Sum256([]byte(cfg.BearerToken)),
		persistedConfig: node.Config(),
		subscribers:     make(map[chan []byte]struct{}),
		triggerReseed:   node.TriggerReseed,
	}, nil
}

func parseWebUIAccessPolicy(listenAddress, bearerToken string) (webUIAccessPolicy, error) {
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return webUIAccessPolicy{}, fmt.Errorf("webui: listen address must include host and port: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return webUIAccessPolicy{loopback: true, listenHost: "localhost", requireAuth: bearerToken != ""}, nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return webUIAccessPolicy{loopback: true, listenHost: host, requireAuth: bearerToken != ""}, nil
	}
	if host != "0.0.0.0" {
		return webUIAccessPolicy{}, fmt.Errorf("webui: listen host %q is not allowed; use localhost, a loopback address, or explicit 0.0.0.0", host)
	}
	if len(bearerToken) < 16 {
		return webUIAccessPolicy{}, errors.New("webui: explicit 0.0.0.0 requires IVNPD_WEBUI_TOKEN with at least 16 bytes")
	}
	return webUIAccessPolicy{listenHost: host, requireAuth: true}, nil
}

// Start opens the listener and starts the telemetry stream.
func (s *WebUIServer) Start(parent context.Context) error {
	if s.server != nil {
		return errors.New("webui: already started")
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
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
	mux.HandleFunc("/api/netdb", s.handleNetDB)
	mux.HandleFunc("/api/destinations", s.handleDestinations)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/actions/reseed", s.handleActionReseed)
	mux.HandleFunc("/api/actions/tunnel-probe", s.handleActionTunnelProbe)
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

	s.sampleTraffic(time.Now(), s.node.RegistrySnapshot())
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
func (s *WebUIServer) startReseedAction() error {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	timeout := s.node.Config().Reseed.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	actionContext, cancel := context.WithTimeout(parent, timeout)
	done, err := s.triggerReseed(actionContext)
	if err != nil {
		cancel()
		return err
	}
	if done == nil {
		cancel()
		return errors.New("reseed attempt did not start; an attempt may be backed off or unnecessary")
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
		result = s.server.Shutdown(ctx)
		cancel()
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

func (s *WebUIServer) wrapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setSecurityHeaders(w)
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
			return "", errors.New("unterminated script opening tag")
		}
		bodyStart := tagStart + relativeTagEnd + 1
		relativeBodyEnd := bytes.Index(lowerDocument[bodyStart:], []byte(closingTag))
		if relativeBodyEnd < 0 {
			return "", errors.New("unterminated script body")
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
	}{Type: "metrics", Metrics: s.currentMetricsResponse()})
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
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			snapshot := s.node.RegistrySnapshot()
			s.sampleTraffic(now, snapshot)
			payload, err := json.Marshal(struct {
				Type    string          `json:"type"`
				Metrics metricsResponse `json:"metrics"`
			}{Type: "metrics", Metrics: s.metricsResponse(snapshot)})
			if err == nil {
				s.broadcast(payload)
			}
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
