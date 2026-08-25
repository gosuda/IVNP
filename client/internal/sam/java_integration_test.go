//go:build integration

package sam

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp/interfaces/stream"
)

// TestJavaI2PHTTPProxyB32Integration proves the public net.Listener-shaped
// SAM backend can serve HTTP at its generated b32 and that the official Java
// router's HTTP proxy reaches it. It is opt-in because initial router reseed
// and tunnel construction require a live I2P network and may take minutes.
func TestJavaI2PHTTPProxyB32Integration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P SAM/HTTP proxy available")
	}
	context, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	network, err := New(Config{Address: "127.0.0.1:7656"})
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
			if err != nil && err != http.ErrServerClosed {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("HTTP server did not stop")
		}
	}()

	proxy, err := url.Parse("http://127.0.0.1:4444")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 4 * time.Minute}
	response, err := client.Get("http://" + network.B32() + "/ivnp-e2e")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ivnp-java-i2p-e2e" {
		t.Fatalf("proxy response = %d %q", response.StatusCode, body)
	}
}

// TestJavaI2PStreamDialIntegration proves Dialer and ListenerConfig establish
// a real I2P stream between two IVNP SAM sessions through the Java router.
func TestJavaI2PStreamDialIntegration(t *testing.T) {
	if os.Getenv("IVNP_SAM_INTEGRATION") != "1" {
		t.Skip("set IVNP_SAM_INTEGRATION=1 with Java I2P SAM available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	serverNetwork, err := New(Config{Address: "127.0.0.1:7656"})
	if err != nil {
		t.Fatal(err)
	}
	defer serverNetwork.Close()
	clientNetwork, err := New(Config{Address: "127.0.0.1:7656"})
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

type streamIntegrationError struct{ got string }

func (e *streamIntegrationError) Error() string {
	return "SAM listener received " + e.got + ", want ping"
}
