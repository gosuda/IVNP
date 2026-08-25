package frontend

import (
	"bufio"
	"context"
	"fmt"
	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/internal/ingress"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPProxyAddress = "127.0.0.1:4444"
	defaultMaxConnections   = 64
	defaultMaxHeaderBytes   = 32 << 10
	defaultMaxRequestBytes  = 8 << 20
)

// HTTPProxyConfig configures a local HTTP CONNECT and absolute-form proxy.
type HTTPProxyConfig struct {
	Network           stream.StreamNetwork
	Resolver          DestinationResolver
	ListenAddress     string
	AllowRemote       bool
	MaxConnections    int
	MaxHeaderBytes    int
	MaxRequestBytes   int64
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	DialTimeout       time.Duration
	Listen            func(context.Context, string, string) (net.Listener, error)
	PanicReporter     ingress.Reporter
}

// HTTPProxy forwards HTTP proxy requests only to validated I2P destinations.
type HTTPProxy struct {
	config HTTPProxyConfig
	server server
}

func NewHTTPProxy(config HTTPProxyConfig) (*HTTPProxy, error) {
	if config.Network == nil {
		return nil, fmt.Errorf("%w: stream network", ErrInvalidConfig)
	}
	if config.ListenAddress == "" {
		config.ListenAddress = defaultHTTPProxyAddress
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.ReadHeaderTimeout == 0 {
		config.ReadHeaderTimeout = 10 * time.Second
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 3 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 2 * time.Minute
	}
	newHTTPProxyRejected := config.MaxConnections < 1 || config.MaxHeaderBytes < 1024 || config.MaxRequestBytes < 1 || config.ReadHeaderTimeout < 1 || config.ReadTimeout < 1 || config.WriteTimeout < 1 || config.IdleTimeout < 1
	if !newHTTPProxyRejected {
		newHTTPProxyRejected = config.DialTimeout < 1
	}
	if newHTTPProxyRejected {
		return nil, fmt.Errorf("%w: proxy bounds", ErrInvalidConfig)
	}
	return &HTTPProxy{config: config}, nil
}

func (p *HTTPProxy) Start(ctx context.Context) error {
	if p == nil {
		return net.ErrClosed
	}
	httpServer := &http.Server{
		Handler: recoverHTTP(p.config.PanicReporter, func(w http.ResponseWriter, request *http.Request) {
			p.server.serveActivity(func() {
				p.serveHTTP(w, request)
			})
		}),
		ReadHeaderTimeout: p.config.ReadHeaderTimeout,
		ReadTimeout:       p.config.ReadTimeout,
		WriteTimeout:      p.config.WriteTimeout,
		IdleTimeout:       p.config.IdleTimeout,
		MaxHeaderBytes:    p.config.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return p.server.runningContext()
		},
		ConnState: p.server.connState,
	}
	return p.server.start(ctx, p.config.ListenAddress, p.config.AllowRemote, p.config.MaxConnections, p.config.Listen, func(listener net.Listener) {
		_ = httpServer.Serve(listener)
	})
}

func (p *HTTPProxy) Close() error {
	if p == nil {
		return nil
	}
	return p.server.close()
}

func (p *HTTPProxy) Wait() error {
	if p == nil {
		return net.ErrClosed
	}
	return p.server.wait()
}

func (p *HTTPProxy) Addr() net.Addr {
	if p == nil {
		return nil
	}
	return p.server.addr()
}

func (p *HTTPProxy) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		p.serveConnect(w, request)
		return
	}
	if !request.URL.IsAbs() || !strings.EqualFold(request.URL.Scheme, "http") {
		rejectHTTP(w, request, "only HTTP absolute-form requests are supported", http.StatusBadRequest)
		return
	}
	if request.ContentLength > p.config.MaxRequestBytes {
		rejectHTTP(w, request, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	port := uint16(80)
	if raw := request.URL.Port(); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || parsed == 0 {
			rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
			return
		}
		port = uint16(parsed)
	}
	address, err := p.resolveAddress(request.Context(), request.URL.Hostname(), port)
	if err != nil {
		rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
		return
	}
	p.forwardRequest(w, request, address)
}

func (p *HTTPProxy) serveConnect(w http.ResponseWriter, request *http.Request) {
	host, rawPort, err := net.SplitHostPort(request.Host)
	port, parseErr := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || parseErr != nil || port == 0 {
		rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
		return
	}
	address, err := p.resolveAddress(request.Context(), host, uint16(port))
	if err != nil {
		rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
		return
	}
	p.forwardRequest(w, request, address)
}

func (p *HTTPProxy) resolveAddress(ctx context.Context, host string, port uint16) (string, error) {
	if address, err := targetAddress(host, port); err == nil {
		return address, nil
	}
	if p.config.Resolver == nil || !strings.HasSuffix(strings.ToLower(strings.TrimSpace(host)), ".i2p") {
		return "", ErrI2PTarget
	}
	destination, err := p.config.Resolver.ResolveDestination(ctx, host)
	if err != nil {
		return "", ErrI2PTarget
	}
	return targetAddress(destination, port)
}

func (p *HTTPProxy) forwardRequest(w http.ResponseWriter, request *http.Request, address string) {
	ctx, cancel := context.WithTimeout(request.Context(), p.config.DialTimeout)
	outbound, err := p.config.Network.DialI2P(ctx, address)
	cancel()
	if err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	defer outbound.Close()

	if request.Method == http.MethodConnect {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			rejectHTTP(w, request, "connection hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		relayConnections(client, outbound, buffered.Reader)
		return
	}

	request.Close = true
	removeHopByHopHeaders(request.Header)
	request.Header.Del("Proxy-Authorization")
	request.Body = http.MaxBytesReader(w, request.Body, p.config.MaxRequestBytes)
	if err := outbound.SetDeadline(time.Now().Add(p.config.ReadTimeout)); err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	if err := request.Write(outbound); err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(outbound), request)
	if err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	for name, values := range response.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func removeHopByHopHeaders(header http.Header) {
	for name := range strings.SplitSeq(header.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			header.Del(name)
		}
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func rejectHTTP(w http.ResponseWriter, request *http.Request, message string, status int) {
	request.Close = true
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}
