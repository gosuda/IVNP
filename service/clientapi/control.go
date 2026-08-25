package clientapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"gosuda.org/ivnp/internal/ingress"
)

const defaultControlAddress = "127.0.0.1:7657"

// Status is the observable router state reported by a control StatusProvider.
type Status struct {
	Ready bool   `json:"ready"`
	State string `json:"state,omitempty"`
	// RouterHash is the public I2P-base64 router identity hash used to
	// configure deliberate native-peer tunnel routes.
	RouterHash string           `json:"router_hash,omitempty"`
	Readiness  ReadinessDetails `json:"readiness"`
}

// ReadinessDetails is the authenticated, non-sensitive evidence behind Ready.
type ReadinessDetails struct {
	BootstrapStage             uint64 `json:"bootstrap_stage"`
	NetDBRouters               uint64 `json:"netdb_routers"`
	RouterInfoPublications     uint64 `json:"router_info_publications"`
	LeaseSet2Publications      uint64 `json:"lease_set2_publications"`
	ExploratoryInboundTunnels  uint64 `json:"exploratory_inbound_tunnels"`
	ExploratoryOutboundTunnels uint64 `json:"exploratory_outbound_tunnels"`
	ClientInboundTunnels       uint64 `json:"client_inbound_tunnels"`
	ClientOutboundTunnels      uint64 `json:"client_outbound_tunnels"`
	RouterReachable            bool   `json:"router_reachable"`
	SSU2VectorIO               bool   `json:"ssu2_vector_io"`
	SSU2KernelDropAccounting   bool   `json:"ssu2_kernel_drop_accounting"`
	ProcessGoroutines          uint64 `json:"process_goroutines"`
	ProcessHeapInuseBytes      uint64 `json:"process_heap_inuse_bytes"`
	ProcessHeapObjects         uint64 `json:"process_heap_objects"`
}

// StatusProvider supplies current state without exposing a router implementation.
type StatusProvider interface {
	ClientStatus(context.Context) (Status, error)
}

// Destination is one publicly listable local destination.
type Destination struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Default bool   `json:"default"`
}

// DestinationCatalog supplies destination metadata without creation or deletion.
type DestinationCatalog interface {
	ListDestinations(context.Context) ([]Destination, error)
}

// ControlConfig configures the authenticated HTTP control API.
type ControlConfig struct {
	ListenAddress     string
	AllowRemote       bool
	BearerToken       string
	Status            StatusProvider
	Catalog           DestinationCatalog
	MaxConnections    int
	MaxHeaderBytes    int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	Listen            func(context.Context, string, string) (net.Listener, error)
	PanicReporter     ingress.Reporter
}

// Control serves read-only readiness, status, and destination-list operations.
type Control struct {
	config ControlConfig
	server server
	token  [32]byte
}

func NewControl(config ControlConfig) (*Control, error) {
	if !validBearerToken(config.BearerToken) {
		return nil, ErrInvalidConfig
	}
	if config.ListenAddress == "" {
		config.ListenAddress = defaultControlAddress
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if config.ReadHeaderTimeout == 0 {
		config.ReadHeaderTimeout = 10 * time.Second
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.MaxConnections < 1 || config.MaxHeaderBytes < 1024 || config.ReadHeaderTimeout < 1 || config.ReadTimeout < 1 || config.WriteTimeout < 1 || config.IdleTimeout < 1 {
		return nil, ErrInvalidConfig
	}
	return &Control{config: config, token: sha256.Sum256([]byte(config.BearerToken))}, nil
}

func (c *Control) Start(ctx context.Context) error {
	if c == nil {
		return net.ErrClosed
	}
	httpServer := &http.Server{
		Handler: recoverHTTP(c.config.PanicReporter, func(w http.ResponseWriter, request *http.Request) {
			c.server.serveActivity(func() {
				c.serveHTTP(w, request)
			})
		}),
		ReadHeaderTimeout: c.config.ReadHeaderTimeout,
		ReadTimeout:       c.config.ReadTimeout,
		WriteTimeout:      c.config.WriteTimeout,
		IdleTimeout:       c.config.IdleTimeout,
		MaxHeaderBytes:    c.config.MaxHeaderBytes,
		ConnState:         c.server.connState,
		BaseContext: func(net.Listener) context.Context {
			return c.server.runningContext()
		},
	}
	return c.server.start(ctx, c.config.ListenAddress, c.config.AllowRemote, c.config.MaxConnections, c.config.Listen, func(listener net.Listener) {
		_ = httpServer.Serve(listener)
	})
}

func (c *Control) Close() error {
	if c == nil {
		return nil
	}
	return c.server.close()
}

func (c *Control) Wait() error {
	if c == nil {
		return net.ErrClosed
	}
	return c.server.wait()

}

func (c *Control) Addr() net.Addr {
	if c == nil {
		return nil
	}
	return c.server.addr()
}

func (c *Control) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if !c.authorized(request.Header.Get("Authorization")) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ivnp"`)
		rejectHTTP(w, request, "unauthorized", http.StatusUnauthorized)
		return
	}
	if request.Method != http.MethodGet || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		rejectHTTP(w, request, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch request.URL.Path {
	case "/readyz":
		status, ok := c.status(request.Context(), w, request)
		if !ok {
			return
		}
		if !status.Ready {
			writeJSON(w, http.StatusServiceUnavailable, status)
			return
		}
		writeJSON(w, http.StatusOK, status)
	case "/status":
		status, ok := c.status(request.Context(), w, request)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, status)
	case "/destinations":
		if c.config.Catalog == nil {
			rejectHTTP(w, request, "destination catalog unavailable", http.StatusServiceUnavailable)
			return
		}
		destinations, err := c.config.Catalog.ListDestinations(request.Context())
		if err != nil {
			rejectHTTP(w, request, "destination catalog unavailable", http.StatusServiceUnavailable)
			return
		}
		if destinations == nil {
			destinations = []Destination{}
		}
		writeJSON(w, http.StatusOK, struct {
			Destinations []Destination `json:"destinations"`
		}{Destinations: destinations})
	default:
		rejectHTTP(w, request, "not found", http.StatusNotFound)
	}
}

func (c *Control) status(ctx context.Context, w http.ResponseWriter, request *http.Request) (Status, bool) {
	if c.config.Status == nil {
		return Status{Ready: false, State: "status-unavailable"}, true
	}
	status, err := c.config.Status.ClientStatus(ctx)
	if err != nil {
		rejectHTTP(w, request, "status unavailable", http.StatusServiceUnavailable)
		return Status{}, false
	}
	return status, true
}

func (c *Control) authorized(value string) bool {
	kind, token, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(kind, "Bearer") || !validBearerToken(token) {
		return false
	}
	provided := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(provided[:], c.token[:]) == 1
}

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	for _, char := range token {
		if char <= ' ' || char == 0x7f {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
