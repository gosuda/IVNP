//go:build integration

package sam

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp/interfaces/stream"
)

const javaI2PIntegrationTimeout = 10 * time.Minute

// TestJavaI2PHTTPProxyB32Integration proves an IVNP-hosted HTTP service is
// reachable through the Java I2P HTTP proxy. IVNP_SAM_ADDRESS selects whether
// the destination uses Java's SAM bridge or an independently running ivnpd.
func TestJavaI2PHTTPProxyB32Integration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P SAM/HTTP proxy available")
	}
	context, cancel := context.WithTimeout(context.Background(), javaI2PIntegrationTimeout)
	defer cancel()
	network, err := New(Config{Address: integrationSAMAddress()})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if err := network.Start(context); err != nil {
		t.Fatal(err)
	}
	listener, err := network.ListenI2P(context, ":80")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ivnp-e2e" {
			http.NotFound(writer, request)
			return
		}
		_, _ = io.WriteString(writer, "ivnp-java-i2p-e2e")
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	defer func() {
		_ = server.Shutdown(context)
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("HTTP server did not stop")
		}
	}()

	proxy, err := url.Parse(integrationHTTPProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 30 * time.Second}
	targetURL := "http://" + network.B32() + "/ivnp-e2e"
	if os.Getenv("IVNP_JAVA_ADDRESS_HELPER") == "1" {
		helperHost := "ivnp-e2e-" + network.B32()[:8] + ".i2p"
		targetURL = "http://" + helperHost + "/ivnp-e2e?i2paddresshelper=" + url.QueryEscape(network.PublicDestination())
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastStatus int
	var lastBody []byte
	for {
		response, requestErr := client.Get(targetURL)
		if requestErr == nil {
			lastStatus = response.StatusCode
			lastBody, requestErr = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if requestErr == nil && lastStatus == http.StatusOK && string(lastBody) == "ivnp-java-i2p-e2e" {
				return
			}
		}
		select {
		case <-context.Done():
			t.Fatalf("Java proxy did not reach IVNP eepsite: status=%d body=%q error=%v: %v", lastStatus, lastBody, requestErr, context.Err())
		case <-ticker.C:
		}
	}
}

// TestJavaI2PEepsiteReachedByIVNPIntegration proves the IVNP SAM backend can
// reach an HTTP server tunnel hosted by the Java I2P router.
func TestJavaI2PEepsiteReachedByIVNPIntegration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P SAM available")
	}
	host := os.Getenv("IVNP_JAVA_EEPSITE_B32")
	if host == "" {
		t.Skip("set IVNP_JAVA_EEPSITE_B32 to a Java I2P-hosted HTTP server tunnel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), javaI2PIntegrationTimeout)
	defer cancel()
	network, err := New(Config{Address: integrationSAMAddress()})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if err = network.Start(ctx); err != nil {
		t.Fatal(err)
	}
	connection, err := network.DialI2P(ctx, net.JoinHostPort(host, "80"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("Java eepsite response = %d, %d bytes", response.StatusCode, len(body))
	}
}

// TestJavaI2PEepsiteReachedByIVNPHTTPProxyIntegration proves an independently
// running ivnpd data plane can reach a Java I2P-hosted HTTP server tunnel.
func TestJavaI2PEepsiteReachedByIVNPHTTPProxyIntegration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P and ivnpd available")
	}
	host := os.Getenv("IVNP_JAVA_EEPSITE_B32")
	proxyRaw := os.Getenv("IVNP_HTTP_PROXY")
	if host == "" || proxyRaw == "" {
		t.Skip("set IVNP_JAVA_EEPSITE_B32 and IVNP_HTTP_PROXY")
	}
	proxy, err := url.Parse(proxyRaw)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: javaI2PIntegrationTimeout}
	response, err := client.Get("http://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("Java eepsite through IVNP proxy = %d, %d bytes", response.StatusCode, len(body))
	}
}

// TestJavaI2PStreamDialIntegration proves two sessions on the configured SAM
// backend establish a real I2P stream.
func TestJavaI2PStreamDialIntegration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P SAM available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), javaI2PIntegrationTimeout)
	defer cancel()
	serverNetwork, err := New(Config{Address: integrationSAMAddress()})
	if err != nil {
		t.Fatal(err)
	}
	defer serverNetwork.Close()
	clientNetwork, err := New(Config{Address: integrationSAMAddress()})
	if err != nil {
		t.Fatal(err)
	}
	defer clientNetwork.Close()
	if err = serverNetwork.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err = clientNetwork.Start(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := (stream.ListenerConfig{Network: serverNetwork}).Listen(ctx, ":23191")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		request := make([]byte, 4)
		if _, err = io.ReadFull(conn, request); err != nil {
			serverDone <- err
			return
		}
		if string(request) != "ping" {
			serverDone <- &streamIntegrationError{got: string(request)}
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverDone <- err
	}()

	conn, err := (stream.Dialer{Network: clientNetwork}).DialContext(ctx, "i2p", net.JoinHostPort(serverNetwork.B32(), "23191"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("I2P stream reply = %q, want pong", reply)
	}
	select {
	case err = <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func integrationSAMAddress() string {
	if address := os.Getenv("IVNP_SAM_ADDRESS"); address != "" {
		return address
	}
	return "127.0.0.1:7656"
}

func integrationHTTPProxyURL() string {
	if address := os.Getenv("IVNP_JAVA_HTTP_PROXY"); address != "" {
		return address
	}
	return "http://127.0.0.1:4444"
}

type streamIntegrationError struct{ got string }

func (e *streamIntegrationError) Error() string {
	return "SAM listener received " + e.got + ", want ping"
}
