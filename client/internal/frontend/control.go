package frontend

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/internal/ingress"
)

const defaultControlAddress = "127.0.0.1:7657"

// StatusProvider provides current status and readiness information.
type StatusProvider interface {
	ClientStatus(context.Context) (controlplane.ManagementStatus, error)
}

// DestinationCatalog lists local destinations.
type DestinationCatalog interface {
	ListDestinations(context.Context) ([]controlplane.DestinationSummary, error)
}

// ControlConfig configures the local HTTP control server.
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

// Control is an authenticated HTTP server exposing readiness and destination endpoints.
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
	newControlRejected := config.MaxConnections < 1 || config.MaxHeaderBytes < 1024 || config.ReadHeaderTimeout < 1 || config.ReadTimeout < 1 || config.WriteTimeout < 1
	if !newControlRejected {
		newControlRejected = config.IdleTimeout < 1
	}
	if newControlRejected {
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
			destinations = []controlplane.DestinationSummary{}
		}
		writeJSON(w, http.StatusOK, struct {
			Destinations []controlplane.DestinationSummary `json:"destinations"`
		}{Destinations: destinations})
	default:
		rejectHTTP(w, request, "not found", http.StatusNotFound)
	}
}

func (c *Control) status(ctx context.Context, w http.ResponseWriter, request *http.Request) (controlplane.ManagementStatus, bool) {
	if c.config.Status == nil {
		return controlplane.ManagementStatus{Ready: false, State: "status-unavailable"}, true
	}
	status, err := c.config.Status.ClientStatus(ctx)
	if err != nil {
		rejectHTTP(w, request, "status unavailable", http.StatusServiceUnavailable)
		return controlplane.ManagementStatus{}, false
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
