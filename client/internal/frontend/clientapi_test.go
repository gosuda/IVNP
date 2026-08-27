package frontend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp/internal/ingress"
)

const testB32 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p"

type fixedDestinationResolver string

func (r fixedDestinationResolver) ResolveDestination(context.Context, string) (string, error) {
	return string(r), nil
}

type destinationResolverFunc func(context.Context, string) (string, error)

func (resolve destinationResolverFunc) ResolveDestination(ctx context.Context, name string) (string, error) {
	return resolve(ctx, name)
}

type testNetwork struct {
	mu        sync.Mutex
	addresses []string
	dial      func(context.Context, string) (net.Conn, error)
}

func (n *testNetwork) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	n.mu.Lock()
	n.addresses = append(n.addresses, address)
	n.mu.Unlock()
	return n.dial(ctx, address)
}

func (n *testNetwork) ListenI2P(context.Context, string) (net.Listener, error) {
	return nil, errors.New("not implemented")
}

func (n *testNetwork) calls() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.addresses...)
}

func pipeNetwork(handler func(net.Conn)) *testNetwork {
	return &testNetwork{dial: func(_ context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go handler(server)
		return client, nil
	}}
}

func startHTTPProxy(t *testing.T, network *testNetwork) *HTTPProxy {
	t.Helper()
	proxy, err := NewHTTPProxy(HTTPProxyConfig{Network: network, ListenAddress: "127.0.0.1:0", Outproxies: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		if err := proxy.Wait(); err != nil {
			t.Error(err)
		}
	})
	return proxy
}

func startSOCKS5Proxy(t *testing.T, network *testNetwork, maxConnections int) *SOCKS5Proxy {
	t.Helper()
	proxy, err := NewSOCKS5Proxy(SOCKS5Config{Network: network, ListenAddress: "127.0.0.1:0", MaxConnections: maxConnections})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		if err := proxy.Wait(); err != nil {
			t.Error(err)
		}
	})
	return proxy
}

func TestHTTPProxyForwardsCONNECTAndAbsoluteForm(t *testing.T) {
	var dial atomic.Int32
	proxy := startHTTPProxy(t, pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		if dial.Add(1) == 1 {
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(connection, buffer); err == nil && string(buffer) == "ping" {
				_, _ = io.WriteString(connection, "pong")
			}
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil || request.Method == http.MethodConnect {
			return
		}
		if request.Header.Get("User-Agent") != "MYOB/6.66 (AN/ON)" {
			_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			return
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server"} {
			if request.Header.Get(name) != "" {
				_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
				return
			}
		}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}))

	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(connection, "CONNECT "+testB32+":80 HTTP/1.1\r\nHost: "+testB32+":80\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v, %v", response, err)
	}
	_, _ = io.WriteString(connection, "ping")
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("CONNECT relay = %q, %v", buffer, err)
	}
	_ = connection.Close()

	connection, err = net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://"+testB32+"/path HTTP/1.1\r\nHost: "+testB32+"\r\nUser-Agent: identifying-client/1.0\r\nForwarded: for=192.0.2.1\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-Host: proxy.example\r\nX-Forwarded-Server: proxy.example\r\n\r\n")
	response, err = http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("absolute-form response = %d, %q, %v", response.StatusCode, body, err)
	}
	calls := proxy.config.Network.(*testNetwork).calls()
	if len(calls) != 2 || calls[0] != testB32+":80" || calls[1] != testB32+":80" {
		t.Fatalf("dialed addresses = %q", calls)
	}
}

func TestHTTPProxyRejectsClearnet(t *testing.T) {
	network := pipeNetwork(func(net.Conn) {})
	proxy := startHTTPProxy(t, network)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || len(network.calls()) != 0 {
		t.Fatalf("clearnet response = %d, calls = %d", response.StatusCode, len(network.calls()))
	}
}

func TestHTTPProxyResolvesI2PHostnames(t *testing.T) {
	network := pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		if _, err := http.ReadRequest(bufio.NewReader(connection)); err == nil {
			_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	proxy, err := NewHTTPProxy(HTTPProxyConfig{
		Network: network, Resolver: fixedDestinationResolver(testB32), ListenAddress: "127.0.0.1:0", Outproxies: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	})
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://i2pd.i2p/ HTTP/1.1\r\nHost: i2pd.i2p\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("resolved response = %d, %q, %v", response.StatusCode, body, err)
	}
	if calls := network.calls(); len(calls) != 1 || calls[0] != testB32+":80" {
		t.Fatalf("resolved dials = %q", calls)
	}
}

func TestHTTPProxyRoutesClearnetThroughOutproxy(t *testing.T) {
	warmed := make(chan struct{})
	handled := make(chan string, 1)
	var dials atomic.Int32
	network := pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		if dials.Add(1) == 1 {
			close(warmed)
			_, _ = io.Copy(io.Discard, connection)
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			handled <- err.Error()
			return
		}
		if request.RequestURI != "http://example.com/path?value=1" || request.Host != "example.com" {
			handled <- "outproxy request was not absolute-form"
			return
		}
		if request.Header.Get("User-Agent") != outproxyHTTPUserAgent || request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("X-Forwarded-For") != "" {
			handled <- "outproxy request leaked identifying proxy headers"
			return
		}
		handled <- ""
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	proxy, err := NewHTTPProxy(HTTPProxyConfig{
		Network: network, Resolver: fixedDestinationResolver(testB32), ListenAddress: "127.0.0.1:0",
		Outproxies: []string{"exit.stormycloud.i2p"}, OutproxyWarmupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	})
	select {
	case <-warmed:
	case <-time.After(time.Second):
		t.Fatal("outproxy warmup did not dial immediately")
	}

	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://example.com/path?value=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: identifying-client/1.0\r\nProxy-Authorization: secret\r\nX-Forwarded-For: 192.0.2.1\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("outproxy HTTP response = %d, %q, %v", response.StatusCode, body, err)
	}
	if failure := <-handled; failure != "" {
		t.Fatal(failure)
	}
	if calls := network.calls(); len(calls) != 2 || calls[0] != testB32+":80" || calls[1] != testB32+":80" {
		t.Fatalf("outproxy dials = %q", calls)
	}
}

func TestHTTPProxyRoutesConnectThroughOutproxy(t *testing.T) {
	warmed := make(chan struct{})
	handled := make(chan string, 1)
	var dials atomic.Int32
	network := pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		if dials.Add(1) == 1 {
			close(warmed)
			_, _ = io.Copy(io.Discard, connection)
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			handled <- err.Error()
			return
		}
		if request.Method != http.MethodConnect || request.RequestURI != "example.com:443" || request.Host != "example.com:443" {
			handled <- "outproxy CONNECT request was malformed"
			return
		}
		if request.Header.Get("User-Agent") != outproxyHTTPUserAgent {
			handled <- "outproxy CONNECT user agent was not normalized"
			return
		}
		if _, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			handled <- err.Error()
			return
		}
		buffer := make([]byte, 4)
		if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != "ping" {
			handled <- "outproxy CONNECT relay did not receive payload"
			return
		}
		handled <- ""
		_, _ = io.WriteString(connection, "pong")
	})
	proxy, err := NewHTTPProxy(HTTPProxyConfig{
		Network: network, Resolver: fixedDestinationResolver(testB32), ListenAddress: "127.0.0.1:0",
		Outproxies: []string{"exit.stormycloud.i2p"}, OutproxyWarmupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	})
	select {
	case <-warmed:
	case <-time.After(time.Second):
		t.Fatal("outproxy warmup did not dial immediately")
	}

	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("outproxy CONNECT response = %v, %v", response, err)
	}
	_, _ = io.WriteString(connection, "ping")
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("outproxy CONNECT relay = %q, %v", buffer, err)
	}
	if failure := <-handled; failure != "" {
		t.Fatal(failure)
	}
}

func TestHTTPProxyOutproxyFailover(t *testing.T) {
	const secondB32 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p"
	network := &testNetwork{dial: func(_ context.Context, address string) (net.Conn, error) {
		if address == testB32+":80" {
			return nil, errors.New("first outproxy unavailable")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
	resolver := destinationResolverFunc(func(_ context.Context, name string) (string, error) {
		if name == "first.i2p" {
			return testB32, nil
		}
		return secondB32, nil
	})
	proxy, err := NewHTTPProxy(HTTPProxyConfig{Network: network, Resolver: resolver, Outproxies: []string{"first.i2p", "second.i2p"}})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := proxy.dialOutproxy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if calls := network.calls(); len(calls) != 2 || calls[0] != testB32+":80" || calls[1] != secondB32+":80" {
		t.Fatalf("outproxy failover dials = %q", calls)
	}
}

func TestHTTPProxyRetriesOutproxyWarmup(t *testing.T) {
	attempted := make(chan struct{}, 2)
	network := &testNetwork{dial: func(context.Context, string) (net.Conn, error) {
		attempted <- struct{}{}
		return nil, errors.New("warming outproxy failed")
	}}
	proxy, err := NewHTTPProxy(HTTPProxyConfig{
		Network: network, Resolver: fixedDestinationResolver(testB32), ListenAddress: "127.0.0.1:0",
		Outproxies: []string{"exit.stormycloud.i2p"}, OutproxyWarmupInterval: time.Hour,
		OutproxyWarmupRetryInterval: 10 * time.Millisecond, OutproxyWarmupTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-attempted:
		case <-time.After(time.Second):
			t.Fatal("outproxy warmup was not retried")
		}
	}
	if err = proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err = proxy.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPProxyWaitsForDataPlaneBeforeWarmup(t *testing.T) {
	readyChecked := make(chan struct{})
	releaseReady := make(chan struct{})
	dialed := make(chan struct{}, 1)
	var (
		ready       atomic.Bool
		checkedOnce sync.Once
		releaseOnce sync.Once
	)
	network := &testNetwork{dial: func(context.Context, string) (net.Conn, error) {
		dialed <- struct{}{}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
	proxy, err := NewHTTPProxy(HTTPProxyConfig{
		Network: network, Resolver: fixedDestinationResolver(testB32), ListenAddress: "127.0.0.1:0",
		Outproxies: []string{"exit.stormycloud.i2p"}, OutproxyWarmupInterval: time.Hour,
		OutproxyWarmupRetryInterval: 10 * time.Millisecond,
		OutproxyWarmupReady: func() bool {
			checkedOnce.Do(func() { close(readyChecked) })
			<-releaseReady
			return ready.Load()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseReady) })
		_ = proxy.Close()
		if waitErr := proxy.Wait(); waitErr != nil {
			t.Error(waitErr)
		}
	})
	<-readyChecked
	if calls := network.calls(); len(calls) != 0 {
		t.Fatalf("warmup dialed before readiness: %q", calls)
	}
	ready.Store(true)
	releaseOnce.Do(func() { close(releaseReady) })
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("warmup did not dial after readiness")
	}
}

func TestSOCKS5NegotiatesAndRelaysDomainConnect(t *testing.T) {
	proxy := startSOCKS5Proxy(t, pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(connection, buffer); err == nil && string(buffer) == "ping" {
			_, _ = io.WriteString(connection, "pong")
		}
	}), 1)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil || string(method) != string([]byte{5, 0}) {
		t.Fatalf("SOCKS method = %v, %v", method, err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(testB32))}, []byte(testB32)...)
	request = append(request, 0, 80)
	_, _ = connection.Write(request)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS connect = %v, %v", reply, err)
	}
	_, _ = io.WriteString(connection, "ping")
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("SOCKS relay = %q, %v", buffer, err)
	}
}

func TestSOCKS5RejectsIP(t *testing.T) {
	proxy := startSOCKS5Proxy(t, pipeNetwork(func(net.Conn) {}), 1)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 8 {
		t.Fatalf("IP target reply = %v, %v", reply, err)
	}
}

func TestSOCKS5HonorsCapacity(t *testing.T) {
	proxy := startSOCKS5Proxy(t, pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		_, _ = io.Copy(io.Discard, connection)
	}), 1)
	first, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _ = first.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(first, method); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(testB32))}, []byte(testB32)...)
	request = append(request, 0, 80)
	_, _ = first.Write(request)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(first, reply); err != nil || reply[1] != 0 {
		t.Fatalf("first SOCKS connect = %v, %v", reply, err)
	}
	second, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = second.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(second, method); err == nil {
		t.Fatal("second connection bypassed capacity")
	}
}

type testStatus struct{ status Status }

func (s testStatus) ClientStatus(context.Context) (Status, error) { return s.status, nil }

type blockingStatus struct {
	started  chan<- struct{}
	canceled chan<- struct{}
	release  <-chan struct{}
}

func (s blockingStatus) ClientStatus(ctx context.Context) (Status, error) {
	s.started <- struct{}{}
	<-ctx.Done()
	s.canceled <- struct{}{}
	<-s.release
	return Status{}, ctx.Err()
}

type testCatalog []Destination

func (c testCatalog) ListDestinations(context.Context) ([]Destination, error) { return c, nil }

type panicCatalog struct{}

func (panicCatalog) ListDestinations(context.Context) ([]Destination, error) {
	panic("fault injection")
}

type panicReports struct {
	mu      sync.Mutex
	reports []ingress.Panic
}

func (r *panicReports) ReportRecoveredPanic(report ingress.Panic) {
	r.mu.Lock()
	r.reports = append(r.reports, report)
	r.mu.Unlock()
}

func TestControlContainsPanickingCatalogHandler(t *testing.T) {
	reporter := new(panicReports)
	control, err := NewControl(ControlConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   "secret",
		Status:        testStatus{Status{Ready: true, State: "running"}},
		Catalog:       panicCatalog{},
		PanicReporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = control.Close(); _ = control.Wait() }()

	client := &http.Client{}
	request, _ := http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/destinations", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panicking catalog response = %v, %v", response, err)
	}
	_ = response.Body.Close()
	request, _ = http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("sibling request response = %v, %v", response, err)
	}
	_ = response.Body.Close()
	reporter.mu.Lock()
	reports := append([]ingress.Panic(nil), reporter.reports...)
	reporter.mu.Unlock()
	if len(reports) != 1 || reports[0].Boundary != ingress.BoundaryHTTPHandler {
		t.Fatalf("panic reports = %#v", reports)
	}
}

func TestControlAuthenticatesAndListsStatus(t *testing.T) {
	control, err := NewControl(ControlConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   "secret",
		Status: testStatus{Status{Ready: false, State: "starting", Readiness: ReadinessDetails{
			BootstrapStage: 3, NetDBRouters: 50, ProcessGoroutines: 7,
		}}},
		Catalog: testCatalog{{Name: "main", Address: testB32, Default: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = control.Close(); _ = control.Wait() }()
	client := &http.Client{}
	request, _ := http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/readyz", nil)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated response = %v, %v", response, err)
	}
	_ = response.Body.Close()
	request, _ = http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/readyz", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readiness response = %v, %v", response, err)
	}
	var readiness Status
	if err := json.NewDecoder(response.Body).Decode(&readiness); err != nil {
		t.Fatal(err)
	}
	if readiness.Readiness.BootstrapStage != 3 || readiness.Readiness.NetDBRouters != 50 || readiness.Readiness.ProcessGoroutines != 7 {
		t.Fatalf("authenticated readiness details = %+v", readiness.Readiness)
	}
	_ = response.Body.Close()
	request, _ = http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("status response = %v, %v", response, err)
	}
	_ = response.Body.Close()
	request, _ = http.NewRequest(http.MethodGet, "http://"+control.Addr().String()+"/destinations", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("destinations response = %v, %v", response, err)
	}
	var payload struct {
		Destinations []Destination `json:"destinations"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil || len(payload.Destinations) != 1 || payload.Destinations[0].Address != testB32 {
		t.Fatalf("destination listing = %#v, %v", payload, err)
	}
	_ = response.Body.Close()
}

func TestSOCKS5CancellationAndShutdown(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	network := &testNetwork{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}}
	proxy := startSOCKS5Proxy(t, network, 1)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(testB32))}, []byte(testB32)...)
	request = append(request, 0, 80)
	_, _ = connection.Write(request)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("dial context was not canceled")
	}
	if err := proxy.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPProxyClosesAfterAbsoluteFormRequest(t *testing.T) {
	proxy := startHTTPProxy(t, pipeNetwork(func(connection net.Conn) {
		defer connection.Close()
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err == nil && request.URL.Path == "/one" {
			_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	}))
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://"+testB32+"/one HTTP/1.1\r\nHost: "+testB32+"\r\n\r\nGET http://"+testB32+"/two HTTP/1.1\r\nHost: "+testB32+"\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ok" || !response.Close {
		t.Fatalf("response = %d %q, close = %t", response.StatusCode, body, response.Close)
	}
	if calls := proxy.config.Network.(*testNetwork).calls(); len(calls) != 1 {
		t.Fatalf("dial count = %d", len(calls))
	}
}

func TestHTTPProxyRejectsWithConnectionClose(t *testing.T) {
	proxy := startHTTPProxy(t, pipeNetwork(func(net.Conn) {}))
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || !response.Close {
		t.Fatalf("response = %d, close = %t", response.StatusCode, response.Close)
	}
}

func TestControlRejectsWithConnectionClose(t *testing.T) {
	control, err := NewControl(ControlConfig{ListenAddress: "127.0.0.1:0", BearerToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = control.Close()
		_ = control.Wait()
	})
	connection, err := net.Dial("tcp", control.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET /readyz HTTP/1.1\r\nHost: control\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !response.Close {
		t.Fatalf("response = %d, close = %t", response.StatusCode, response.Close)
	}
}

func TestControlRejectsUnpresentableBearerToken(t *testing.T) {
	for _, token := range []string{"", "has space", "line\nbreak", "\x00"} {
		if control, err := NewControl(ControlConfig{BearerToken: token}); err == nil || control != nil {
			t.Fatalf("token %q was accepted", token)
		}
	}
}

func TestSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	proxy := startSOCKS5Proxy(t, pipeNetwork(func(net.Conn) {}), 1)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write([]byte{5, 2, 0, 3})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 7 {
		t.Fatalf("SOCKS command reply = %v, %v", reply, err)
	}
}

func TestSOCKS5HandshakeLimitAdmitsB32Target(t *testing.T) {
	if proxy, err := NewSOCKS5Proxy(SOCKS5Config{Network: pipeNetwork(func(net.Conn) {}), MaxHandshakeBytes: minSOCKS5HandshakeBytes - 1}); err == nil || proxy != nil {
		t.Fatal("undersized handshake limit was accepted")
	}
	if proxy, err := NewSOCKS5Proxy(SOCKS5Config{Network: pipeNetwork(func(net.Conn) {}), MaxHandshakeBytes: minSOCKS5HandshakeBytes}); err != nil || proxy == nil {
		t.Fatalf("valid b32 handshake limit = %v, %v", proxy, err)
	}
}

func TestSOCKS5DialCancelsWhenClientDisconnects(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	proxy := startSOCKS5Proxy(t, &testNetwork{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}}, 1)
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(testB32))}, []byte(testB32)...)
	request = append(request, 0, 80)
	_, _ = connection.Write(request)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	_ = connection.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("client disconnect did not cancel dial")
	}
}

func TestSOCKS5ResetsHandshakeDeadlineForDialFailure(t *testing.T) {
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	proxy, err := NewSOCKS5Proxy(SOCKS5Config{
		Network: &testNetwork{dial: func(context.Context, string) (net.Conn, error) {
			close(dialStarted)
			<-releaseDial
			return nil, errors.New("dial failed")
		}},
		ListenAddress:    "127.0.0.1:0",
		HandshakeTimeout: 5 * time.Millisecond,
		DialTimeout:      100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	})
	connection, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = connection.Write([]byte{5, 1, 0})
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(testB32))}, []byte(testB32)...)
	request = append(request, 0, 80)
	_, _ = connection.Write(request)
	<-dialStarted
	timer := time.NewTimer(20 * time.Millisecond)
	<-timer.C
	close(releaseDial)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 4 {
		t.Fatalf("SOCKS dial reply = %v, %v", reply, err)
	}
}

func TestControlWaitIncludesActiveHandler(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	release := make(chan struct{})
	control, err := NewControl(ControlConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   "secret",
		Status:        blockingStatus{started: started, canceled: canceled, release: release},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp", control.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET /status HTTP/1.1\r\nHost: control\r\nAuthorization: Bearer secret\r\n\r\n")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("status handler did not start")
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("status handler context was not canceled")
	}
	waited := make(chan error, 1)
	go func() { waited <- control.Wait() }()
	select {
	case err := <-waited:
		t.Fatalf("Wait returned before handler finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-waited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not finish with handler")
	}
}

func TestRelayPreservesHalfClose(t *testing.T) {
	leftClient, leftRelay := testTCPPair(t)
	defer leftClient.Close()
	rightClient, rightRelay := testTCPPair(t)
	defer rightClient.Close()
	relayDone := make(chan struct{})
	go func() {
		relayConnections(leftRelay, rightRelay, leftRelay)
		close(relayDone)
	}()
	if _, err := io.WriteString(leftClient, "request"); err != nil {
		t.Fatal(err)
	}
	if err := leftClient.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(rightClient)
	if err != nil || string(request) != "request" {
		t.Fatalf("relayed request = %q, %v", request, err)
	}
	if _, err := io.WriteString(rightClient, "response"); err != nil {
		t.Fatal(err)
	}
	if err := rightClient.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(leftClient)
	if err != nil || string(response) != "response" {
		t.Fatalf("relayed response = %q, %v", response, err)
	}
	select {
	case <-relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay did not finish")
	}
}

func testTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case connection := <-accepted:
		return client, connection
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("listener did not accept")
		return nil, nil
	}
}
