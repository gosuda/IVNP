package addressbook

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newDestinationString(t *testing.T) string {
	t.Helper()
	local, err := foundation.GenerateLocalDestination()
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
	synctest.Test(t, func(t *testing.T) {
		var requests atomic.Int32
		client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			if request.Header.Get("If-None-Match") == "book-v1" {
				return &http.Response{
					StatusCode: http.StatusNotModified,
					Header:     make(http.Header),
					Body:       http.NoBody,
					Request:    request,
				}, nil
			}
			header := make(http.Header)
			header.Set("ETag", "book-v1")
			body := fmt.Sprintf("service.i2p=%s\nremote.i2p=%s\n", remoteDestination, remoteDestination)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    request,
			}, nil
		})}
		service, err := NewService(Config{
			PrivateHostsPath: privatePath, UserHostsPath: userPath, HostsPath: hostsPath, StatePath: statePath,
			Subscriptions: []string{"https://subscriptions.example/hosts.txt"}, HTTPClient: client,
			RefreshInterval: time.Minute, RetryInterval: time.Minute, RequestTimeout: time.Second,
			MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxRedirects: 2,
		})
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
		synctest.Wait()
		if value, lookupErr := service.ResolveDestination(context.Background(), "remote.i2p"); lookupErr != nil || value != remoteDestination {
			t.Fatalf("remote subscription refresh = %q, %v", value, lookupErr)
		}
		if value, err := service.ResolveDestination(context.Background(), "service.i2p"); err != nil || value != privateDestination {
			t.Fatalf("remote overwrote local = %q, %v", value, err)
		}
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		<-timer.C
		synctest.Wait()
		if got := requests.Load(); got < 2 {
			t.Fatalf("conditional refresh requests = %d, want >= 2", got)
		}
		if _, err = os.Stat(statePath); err != nil {
			t.Fatalf("atomic state missing: %v", err)
		}
	})
}

func TestSubscriptionTransportPolicy(t *testing.T) {
	for _, raw := range []string{"http://example.com/hosts.txt", "ftp://host.i2p/hosts.txt", "https://user:pass@example.com/hosts.txt"} {
		if _, err := subscriptionURL(raw); err == nil {
			t.Fatalf("subscriptionURL(%q) accepted", raw)
		}
	}
	for _, raw := range []string{"https://example.com/hosts.txt", "http://reg.i2p/export/hosts.txt", "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.b32.i2p/hosts.txt", "http://127.0.0.1/hosts.txt", "http://localhost/hosts.txt"} {
		if _, err := subscriptionURL(raw); err != nil {
			t.Fatalf("subscriptionURL(%q) rejected: %v", raw, err)
		}
	}
}

func TestBootstrapHostsResolveOnColdStart(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts.txt")
	service, err := NewService(Config{
		HostsPath: hostsPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"reg.i2p", "stats.i2p", "identiguy.i2p", "exit.stormycloud.i2p", "i2p-projekt.i2p", "zzz.i2p"} {
		dest, resErr := service.ResolveDestination(context.Background(), host)
		if resErr != nil {
			t.Errorf("ResolveDestination(%q) failed: %v", host, resErr)
		}
		if dest == "" {
			t.Errorf("ResolveDestination(%q) returned empty destination", host)
		}
	}

	if _, err := os.Stat(hostsPath); err != nil {
		t.Fatalf("ensureDefaultHostsFile did not create hosts.txt: %v", err)
	}
}

func TestCanonicalDestinationSupportsB32(t *testing.T) {
	validB32Addr := "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p"
	canonical, ok := canonicalDestination(validB32Addr)
	if !ok || canonical != validB32Addr {
		t.Errorf("canonicalDestination(%q) = (%q, %t), want (%q, true)", validB32Addr, canonical, ok, validB32Addr)
	}

	invalidB32Addr := "short.b32.i2p"
	if _, ok := canonicalDestination(invalidB32Addr); ok {
		t.Errorf("canonicalDestination(%q) accepted invalid length", invalidB32Addr)
	}
}
