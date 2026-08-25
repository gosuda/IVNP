package addressbook

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	ivnp "gosuda.org/ivnp"
)

func newDestinationString(t *testing.T) string {
	t.Helper()
	local, err := ivnp.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	return string(local.Destination())
}

func TestLocalPrecedenceNormalizationAndSubscriptionRefresh(t *testing.T) {
	privateDestination, userDestination, remoteDestination := newDestinationString(t), newDestinationString(t), newDestinationString(t)
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "privatehosts.txt")
	userPath := filepath.Join(directory, "userhosts.txt")
	hostsPath := filepath.Join(directory, "hosts.txt")
	statePath := filepath.Join(directory, "state.json")
	if err := os.WriteFile(privatePath, []byte("service.i2p="+privateDestination+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte("service.i2p="+userDestination+"\nuser.i2p="+userDestination+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsPath, []byte("service.i2p="+remoteDestination+"\nlocal.i2p="+userDestination+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("If-None-Match") == "book-v1" {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", "book-v1")
		_, _ = fmt.Fprintf(writer, "service.i2p=%s\nremote.i2p=%s\n", remoteDestination, remoteDestination)
	}))
	defer server.Close()
	service, err := NewService(Config{PrivateHostsPath: privatePath, UserHostsPath: userPath, HostsPath: hostsPath, StatePath: statePath, Subscriptions: []string{server.URL}, HTTPClient: server.Client(), RefreshInterval: 20 * time.Millisecond, RetryInterval: 20 * time.Millisecond, RequestTimeout: time.Second, MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxRedirects: 2})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := service.ResolveDestination(context.Background(), "SERVICE.I2P.ALT"); err != nil || value != privateDestination {
		t.Fatalf("private precedence = %q, %v", value, err)
	}
	if err = service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close(); _ = service.Wait() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		value, lookupErr := service.ResolveDestination(context.Background(), "remote.i2p")
		if lookupErr == nil && value == remoteDestination {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("remote refresh = %q, %v", value, lookupErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if value, err := service.ResolveDestination(context.Background(), "service.i2p"); err != nil || value != privateDestination {
		t.Fatalf("remote overwrote local = %q, %v", value, err)
	}
	deadline = time.Now().Add(time.Second)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if requests.Load() < 2 {
		t.Fatal("conditional refresh did not run")
	}
	if _, err = os.Stat(statePath); err != nil {
		t.Fatalf("atomic state missing: %v", err)
	}
}

func TestSubscriptionTransportPolicy(t *testing.T) {
	for _, raw := range []string{"http://example.com/hosts.txt", "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.b32.i2p/hosts.txt", "ftp://host.i2p/hosts.txt", "https://user:pass@example.com/hosts.txt"} {
		if _, err := subscriptionURL(raw); err == nil {
			t.Fatalf("subscriptionURL(%q) accepted", raw)
		}
	}
	if _, err := subscriptionURL("https://example.com/hosts.txt"); err != nil {
		t.Fatal(err)
	}
}
