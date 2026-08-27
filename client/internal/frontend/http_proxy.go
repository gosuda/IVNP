package frontend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/internal/ingress"
)

const (
	defaultHTTPProxyAddress       = "127.0.0.1:4444"
	defaultMaxConnections         = 64
	defaultMaxHeaderBytes         = 32 << 10
	defaultMaxRequestBytes        = 8 << 20
	defaultOutproxyWarmupInterval = 5 * time.Minute
	defaultOutproxyWarmupRetry    = 30 * time.Second
	defaultOutproxyWarmupTimeout  = 30 * time.Second
	maxHTTPOutproxies             = 16
	i2pHTTPUserAgent              = "MYOB/6.66 (AN/ON)"
	outproxyHTTPUserAgent         = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
	defaultHTTPOutproxy           = "exit.stormycloud.i2p"
)

// HTTPProxyConfig configures the local HTTP proxy and outproxy connections.
type HTTPProxyConfig struct {
	Network                     stream.StreamNetwork
	Resolver                    DestinationResolver
	ListenAddress               string
	AllowRemote                 bool
	MaxConnections              int
	MaxHeaderBytes              int
	MaxRequestBytes             int64
	ReadHeaderTimeout           time.Duration
	ReadTimeout                 time.Duration
	WriteTimeout                time.Duration
	IdleTimeout                 time.Duration
	DialTimeout                 time.Duration
	Outproxies                  []string
	OutproxyWarmupInterval      time.Duration
	OutproxyWarmupRetryInterval time.Duration
	OutproxyWarmupTimeout       time.Duration
	OutproxyWarmupReady         func() bool
	Listen                      func(context.Context, string, string) (net.Listener, error)
	PanicReporter               ingress.Reporter
}

// HTTPProxy proxies HTTP requests to I2P destinations or through configured outproxies.
type HTTPProxy struct {
	config       HTTPProxyConfig
	server       server
	nextOutproxy atomic.Uint64
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
	if config.OutproxyWarmupInterval == 0 {
		config.OutproxyWarmupInterval = defaultOutproxyWarmupInterval
	}
	if config.OutproxyWarmupRetryInterval == 0 {
		config.OutproxyWarmupRetryInterval = defaultOutproxyWarmupRetry
	}
	if config.OutproxyWarmupTimeout == 0 {
		config.OutproxyWarmupTimeout = defaultOutproxyWarmupTimeout
	}
	outproxies, err := normalizeHTTPOutproxies(config.Outproxies)
	if err != nil {
		return nil, fmt.Errorf("%w: outproxies", ErrInvalidConfig)
	}
	config.Outproxies = outproxies
	newHTTPProxyRejected := config.MaxConnections < 1 || config.MaxHeaderBytes < 1024 || config.MaxRequestBytes < 1 || config.ReadHeaderTimeout < 1 || config.ReadTimeout < 1 || config.WriteTimeout < 1 || config.IdleTimeout < 1
	if !newHTTPProxyRejected {
		newHTTPProxyRejected = config.DialTimeout < 1 || config.OutproxyWarmupInterval < 1 || config.OutproxyWarmupRetryInterval < 1 || config.OutproxyWarmupTimeout < 1
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
		if len(p.config.Outproxies) != 0 {
			p.server.goServeActivity(func() {
				p.warmOutproxyLoop(p.server.runningContext())
			})
		}
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
			rejectHTTP(w, request, "invalid proxy target", http.StatusBadRequest)
			return
		}
		port = uint16(parsed)
	}
	host := request.URL.Hostname()
	if address, err := p.resolveAddress(request.Context(), host, port); err == nil {
		p.forwardDirectRequest(w, request, address)
		return
	}
	if strings.HasSuffix(normalizeProxyHost(host), ".i2p") || !validClearnetHost(host) {
		rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
		return
	}
	p.forwardOutproxyRequest(w, request)
}

func (p *HTTPProxy) serveConnect(w http.ResponseWriter, request *http.Request) {
	host, rawPort, err := net.SplitHostPort(request.Host)
	port, parseErr := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || parseErr != nil || port == 0 {
		rejectHTTP(w, request, "invalid proxy target", http.StatusBadRequest)
		return
	}
	if address, resolveErr := p.resolveAddress(request.Context(), host, uint16(port)); resolveErr == nil {
		p.forwardDirectRequest(w, request, address)
		return
	}
	if strings.HasSuffix(normalizeProxyHost(host), ".i2p") || !validClearnetHost(host) {
		rejectHTTP(w, request, "invalid I2P target", http.StatusBadRequest)
		return
	}
	p.forwardOutproxyConnect(w, request)
}

func (p *HTTPProxy) resolveAddress(ctx context.Context, host string, port uint16) (string, error) {
	host = normalizeProxyHost(host)
	if address, err := targetAddress(host, port); err == nil {
		return address, nil
	}
	if p.config.Resolver == nil || !strings.HasSuffix(host, ".i2p") {
		return "", ErrI2PTarget
	}
	destination, err := p.config.Resolver.ResolveDestination(ctx, host)
	if err != nil {
		return "", ErrI2PTarget
	}
	return targetAddress(destination, port)
}

func (p *HTTPProxy) forwardDirectRequest(w http.ResponseWriter, request *http.Request, address string) {
	ctx, cancel := context.WithTimeout(request.Context(), p.config.DialTimeout)
	outbound, err := p.config.Network.DialI2P(ctx, address)
	cancel()
	if err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	defer outbound.Close()

	if request.Method == http.MethodConnect {
		p.relayDirectConnect(w, request, outbound)
		return
	}
	p.exchangeHTTP(w, request, outbound, false)
}

func (p *HTTPProxy) forwardOutproxyRequest(w http.ResponseWriter, request *http.Request) {
	outbound, err := p.dialOutproxy(request.Context())
	if err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
	defer outbound.Close()
	p.exchangeHTTP(w, request, outbound, true)
}

func (p *HTTPProxy) forwardOutproxyConnect(w http.ResponseWriter, request *http.Request) {
	outbound, err := p.dialOutproxy(request.Context())
	if err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
	defer outbound.Close()
	if err = outbound.SetDeadline(time.Now().Add(p.config.ReadTimeout)); err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
	request.Header.Del("Proxy-Authorization")
	removeForwardingHeaders(request.Header)
	if _, err = fmt.Fprintf(outbound, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", request.Host, request.Host, outproxyHTTPUserAgent); err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
	outproxyReader := bufio.NewReader(outbound)
	response, err := http.ReadResponse(outproxyReader, request)
	if err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		writeHTTPResponse(w, response)
		return
	}
	if err = outbound.SetDeadline(time.Time{}); err != nil {
		rejectHTTP(w, request, "I2P outproxy unavailable", http.StatusBadGateway)
		return
	}
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
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffered.Flush(); err != nil {
		return
	}
	relayConnections(client, &readerConn{Conn: outbound, reader: outproxyReader}, buffered.Reader)
}

func (p *HTTPProxy) relayDirectConnect(w http.ResponseWriter, request *http.Request, outbound net.Conn) {
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
}

func (p *HTTPProxy) exchangeHTTP(w http.ResponseWriter, request *http.Request, outbound net.Conn, outproxy bool) {
	request.Close = true
	removeHopByHopHeaders(request.Header)
	request.Header.Del("Proxy-Authorization")
	removeForwardingHeaders(request.Header)
	if outproxy {
		request.Header.Set("User-Agent", outproxyHTTPUserAgent)
	} else {
		request.Header.Set("User-Agent", i2pHTTPUserAgent)
	}
	request.Body = http.MaxBytesReader(w, request.Body, p.config.MaxRequestBytes)
	if err := outbound.SetDeadline(time.Now().Add(p.config.ReadTimeout)); err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	var err error
	if outproxy {
		err = request.WriteProxy(outbound)
	} else {
		err = request.Write(outbound)
	}
	if err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(outbound), request)
	if err != nil {
		rejectHTTP(w, request, "I2P destination unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	writeHTTPResponse(w, response)
}

func writeHTTPResponse(w http.ResponseWriter, response *http.Response) {
	removeHopByHopHeaders(response.Header)
	for name, values := range response.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *HTTPProxy) dialOutproxy(parent context.Context) (net.Conn, error) {
	if len(p.config.Outproxies) == 0 {
		return nil, ErrI2PTarget
	}
	ctx, cancel := context.WithTimeout(parent, p.config.DialTimeout)
	defer cancel()
	start := int(p.nextOutproxy.Add(1)-1) % len(p.config.Outproxies)
	var lastErr error
	for offset := range len(p.config.Outproxies) {
		host := p.config.Outproxies[(start+offset)%len(p.config.Outproxies)]
		address, err := p.resolveAddress(ctx, host, 80)
		if err != nil {
			lastErr = err
			continue
		}
		connection, err := p.config.Network.DialI2P(ctx, address)
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrI2PTarget
	}
	return nil, lastErr
}

func (p *HTTPProxy) warmOutproxyLoop(ctx context.Context) {
	delay := time.Duration(0)
	for {
		if delay != 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		if p.config.OutproxyWarmupReady != nil && !p.config.OutproxyWarmupReady() {
			delay = p.config.OutproxyWarmupRetryInterval
			continue
		}
		if p.warmOutproxies(ctx) {
			delay = p.config.OutproxyWarmupInterval
		} else {
			delay = p.config.OutproxyWarmupRetryInterval
		}
	}
}

func (p *HTTPProxy) warmOutproxies(parent context.Context) bool {
	allReady := true
	for _, host := range p.config.Outproxies {
		ctx, cancel := context.WithTimeout(parent, p.config.OutproxyWarmupTimeout)
		address, err := p.resolveAddress(ctx, host, 80)
		var connection net.Conn
		if err == nil {
			connection, err = p.config.Network.DialI2P(ctx, address)
		}
		cancel()
		if connection != nil {
			_ = connection.Close()
		}
		if err != nil {
			allReady = false
		}
		if parent.Err() != nil {
			return false
		}
	}
	return allReady
}

func normalizeHTTPOutproxies(configured []string) ([]string, error) {
	if configured == nil {
		configured = []string{defaultHTTPOutproxy}
	}
	outproxies := make([]string, 0, len(configured))
	for _, candidate := range configured {
		candidate = normalizeProxyHost(candidate)
		if !validI2PProxyName(candidate) {
			return nil, ErrInvalidConfig
		}
		for _, existing := range outproxies {
			if existing == candidate {
				return nil, ErrInvalidConfig
			}
		}
		outproxies = append(outproxies, candidate)
	}
	if len(outproxies) > maxHTTPOutproxies {
		return nil, ErrInvalidConfig
	}
	return outproxies, nil
}

func normalizeProxyHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func validI2PProxyName(host string) bool {
	return strings.HasSuffix(host, ".i2p") && validDNSName(host)
}

func validClearnetHost(host string) bool {
	host = normalizeProxyHost(host)
	return net.ParseIP(host) != nil || validDNSName(host)
}

func validDNSName(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !validDNSCharacter(character) {
				return false
			}
		}
	}
	return true
}

func validDNSCharacter(character rune) bool {
	isLetter := character >= 'a' && character <= 'z'
	isDigit := character >= '0' && character <= '9'
	return isLetter || isDigit || character == '-'
}

type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
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

func removeForwardingHeaders(header http.Header) {
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server"} {
		header.Del(name)
	}
}

func rejectHTTP(w http.ResponseWriter, request *http.Request, message string, status int) {
	request.Close = true
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}
