//go:build integration

package ivnp_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/interfaces/stream"
)

func TestHTTPProxyCompletesI2PChallengeRoundTrip(t *testing.T) {
	proxyAddress := os.Getenv("IVNP_EEPSITE_PROXY")
	samAddress := os.Getenv("IVNP_SAM_ADDRESS")
	if proxyAddress == "" || samAddress == "" {
		t.Fatal("integration requires IVNP_EEPSITE_PROXY (running IVNP HTTP proxy URL) and IVNP_SAM_ADDRESS (I2P-connected SAM host:port)")
	}
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() == "" || proxyURL.User != nil || (proxyURL.Path != "" && proxyURL.Path != "/") || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		t.Fatal("IVNP_EEPSITE_PROXY must be an http://host:port URL without credentials, query, or fragment")
	}
	if host, port, err := net.SplitHostPort(samAddress); err != nil || host == "" || port == "" {
		t.Fatal("IVNP_SAM_ADDRESS must be a SAM bridge host:port")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	network, err := client.SimpleAnonymousMessagingNew(client.SimpleAnonymousMessagingConfig{Address: samAddress})
	if err != nil {
		t.Fatalf("configure responder SAM session: %v", err)
	}
	defer func() {
		if err := network.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close responder SAM session: %v", err)
		}
	}()
	if err := network.Start(ctx); err != nil {
		t.Fatalf("start responder SAM session (requires an I2P-connected bridge): %v", err)
	}
	listener, err := (stream.ListenerConfig{Network: network}).Listen(ctx, ":80")
	if err != nil {
		t.Fatalf("listen on responder I2P destination: %v", err)
	}

	challenge := rand.Text()
	// The response nonce is never sent in the request; an echo or canned 200 cannot pass.
	wantBody := rand.Text() + ":" + challenge
	host := network.B32()
	server := &http.Server{
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    4 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.Host != host || request.URL.Path != "/ivnp-challenge" || request.URL.RawQuery != "" {
				http.Error(w, "unexpected challenge request", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(request.Body, int64(len(challenge)+1)))
			if err != nil || string(body) != challenge {
				http.Error(w, "invalid challenge", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			if _, err := io.WriteString(w, wantBody); err != nil {
				t.Errorf("write challenge response: %v", err)
			}
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shut down I2P responder: %v", err)
		}
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close I2P responder: %v", err)
		}
		if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve I2P responder: %v", err)
		}
	}()

	targetURL := "http://" + host + "/ivnp-challenge"
	if err := proxyChallengeRoundTrip(ctx, proxyURL, targetURL, challenge, wantBody); err != nil {
		t.Fatalf("IVNP proxy did not complete challenge round trip to %s: %v", targetURL, err)
	}
}

func proxyChallengeRoundTrip(ctx context.Context, proxyURL *url.URL, targetURL, challenge, wantBody string) error {
	transport := &http.Transport{
		Proxy:                  http.ProxyURL(proxyURL),
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout:  5 * time.Minute,
		MaxResponseHeaderBytes: 4 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(challenge))
	if err != nil {
		return fmt.Errorf("create challenge request: %w", err)
	}
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("Cache-Control", "no-store")
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(wantBody)+1)))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return fmt.Errorf("read challenge response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("challenge response status = %d, want 200", response.StatusCode)
	}
	if string(body) != wantBody {
		return errors.New("challenge response does not match the responder-only nonce and request challenge")
	}
	return nil
}
