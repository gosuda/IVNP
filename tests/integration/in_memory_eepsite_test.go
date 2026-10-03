//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// memoryDaemonProxyAddress is the default local HTTP proxy listener the daemon
// binds when no configuration file overrides it.
const memoryDaemonProxyAddress = "127.0.0.1:4444"

// TestInMemoryDaemonFetchesPublicEepsite runs the ivnpd binary exactly as an
// operator would (ivnpd -memory), waits for the readiness the embedded WebUI
// reports, and fetches the official I2P project eepsite through the local HTTP
// proxy. It covers the memory-mode daemon path end to end: live reseed, NetDB
// bootstrap, exploratory tunnels, the automatically maintained default client
// destination, and proxied eepsite access.
func TestInMemoryDaemonFetchesPublicEepsite(t *testing.T) {
	if os.Getenv("IVNP_LIVE_MEMORY_EEPSITE") != "1" {
		t.Skip("set IVNP_LIVE_MEMORY_EEPSITE=1 to run the in-memory daemon eepsite access test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Minute)
	defer cancel()

	binary := buildMemoryDaemon(t, ctx)
	webuiAddress := "127.0.0.1:" + freeTCPPort(t)

	log := &bytes.Buffer{}
	daemon := exec.CommandContext(ctx, binary, "-memory", "-webui-listen", webuiAddress)
	daemon.Stdout = log
	daemon.Stderr = log
	if err := daemon.Start(); err != nil {
		t.Fatalf("start ivnpd -memory: %v", err)
	}
	var waitErr error
	exit := make(chan struct{})
	go func() {
		waitErr = daemon.Wait()
		close(exit)
	}()
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		select {
		case <-exit:
		case <-time.After(30 * time.Second):
			t.Logf("ivnpd did not exit after kill; log:\n%s", log.String())
		}
	})

	waitMemoryDaemonReady(t, ctx, webuiAddress, exit, func() error { return waitErr }, log)
	fetchPublicEepsiteThroughProxy(t, ctx, log)
}

// buildMemoryDaemon compiles the daemon binary under test from the current
// checkout so the test always exercises the committed code.
func buildMemoryDaemon(t *testing.T, ctx context.Context) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ivnpd")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "gosuda.org/ivnp/cmd/ivnpd")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gosuda.org/ivnp/cmd/ivnpd: %v\n%s", err, output)
	}
	return binary
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve ephemeral port: %v", err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split ephemeral address %s: %v", listener.Addr(), err)
	}
	return port
}

// waitMemoryDaemonReady polls the embedded WebUI status API until the daemon
// reports full data-plane readiness: NetDB populated, router published,
// exploratory and client tunnels built, and LeaseSet2 published.
func waitMemoryDaemonReady(t *testing.T, ctx context.Context, webuiAddress string, exit <-chan struct{}, waitErr func() error, log *bytes.Buffer) {
	t.Helper()
	statusURL := "http://" + webuiAddress + "/api/status"
	var ready atomic.Bool
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("daemon not ready before deadline; ivnpd log:\n%s", log.String())
		case <-exit:
			t.Fatalf("ivnpd exited early: %v; log:\n%s", waitErr(), log.String())
		case <-ticker.C:
			if !ready.Load() && memoryDaemonReady(ctx, statusURL, &ready) {
				t.Log("ivnpd -memory reported data-plane readiness.")
				return
			}
		}
	}
}

func memoryDaemonReady(ctx context.Context, statusURL string, ready *atomic.Bool) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return false
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var status struct {
		Ready bool   `json:"ready"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		return false
	}
	if status.Ready {
		ready.Store(true)
	}
	return status.Ready
}

// fetchPublicEepsiteThroughProxy retrieves the official I2P project site via
// the daemon's local HTTP proxy, following redirects, and verifies real page
// content so an error page cannot satisfy the test. Remote eepsites can be
// briefly unreachable, so transient failures retry a bounded number of times.
func fetchPublicEepsiteThroughProxy(t *testing.T, ctx context.Context, log *bytes.Buffer) {
	t.Helper()
	proxyURL, err := url.Parse("http://" + memoryDaemonProxyAddress)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout:   3 * time.Minute,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	const target = "http://i2p-projekt.i2p/"
	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		if body, fetchErr := fetchEepsitePage(ctx, client, target); fetchErr == nil {
			t.Logf("fetched %s through ivnpd -memory proxy: %d bytes", target, len(body))
			return
		} else if attempt == attempts {
			t.Fatalf("fetch %s through in-memory daemon failed after %d attempts: %v; ivnpd log:\n%s",
				target, attempts, fetchErr, log.String())
		} else {
			t.Logf("attempt %d/%d for %s failed: %v", attempt, attempts, target, fetchErr)
			select {
			case <-ctx.Done():
				t.Fatalf("context done between retries: %v", ctx.Err())
			case <-time.After(15 * time.Second):
			}
		}
	}
}

func fetchEepsitePage(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	if !strings.Contains(string(body), "Invisible Internet Project") {
		return nil, fmt.Errorf("page content missing expected project title (status %d, %d bytes)", response.StatusCode, len(body))
	}
	return body, nil
}
