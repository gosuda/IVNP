package addressbook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultiSubscription304PreservesPerSourceSnapshot(t *testing.T) {
	firstDestination := newDestinationString(t)
	secondV1 := newDestinationString(t)
	secondV2 := newDestinationString(t)
	var phase atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/first":
			if request.Header.Get("If-None-Match") == "first-v1" {
				writer.WriteHeader(http.StatusNotModified)
				return
			}
			writer.Header().Set("ETag", "first-v1")
			_, _ = fmt.Fprintf(writer, "first.i2p=%s\n", firstDestination)
		case "/second":
			if phase.Load() == 0 {
				writer.Header().Set("ETag", "second-v1")
				_, _ = fmt.Fprintf(writer, "second.i2p=%s\n", secondV1)
				return
			}
			writer.Header().Set("ETag", "second-v2")
			_, _ = fmt.Fprintf(writer, "second.i2p=%s\n", secondV2)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	service, err := NewService(Config{
		StatePath: filepath.Join(t.TempDir(), "state.json"), Subscriptions: []string{server.URL + "/first", server.URL + "/second"}, HTTPClient: server.Client(),
		RequestTimeout: time.Second, MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxRedirects: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	phase.Store(1)
	if err = service.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, lookupErr := service.ResolveDestination(context.Background(), "first.i2p"); lookupErr != nil || got != firstDestination {
		t.Fatalf("304 source = %q, %v", got, lookupErr)
	}
	if got, lookupErr := service.ResolveDestination(context.Background(), "second.i2p"); lookupErr != nil || got != secondV2 {
		t.Fatalf("updated source = %q, %v", got, lookupErr)
	}
}

func TestPersistedSourcesAreFilteredToCurrentHTTPSSubscriptions(t *testing.T) {
	currentDestination := newDestinationString(t)
	staleDestination := newDestinationString(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	current := "https://current.example/hosts.txt"
	removed := "https://removed.example/hosts.txt"
	sources := map[string]map[string]string{
		current: {"current.i2p": currentDestination},
		removed: {"stale.i2p": staleDestination},
	}
	entries := map[string]string{"current.i2p": currentDestination, "stale.i2p": staleDestination}
	if err := saveState(statePath, entries, sources, map[string]string{current: "current-tag", removed: "stale-tag"}, map[string]string{removed: "yesterday"}, 1<<20); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{StatePath: statePath, Subscriptions: []string{current}, MaxEntries: 100, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if got, lookupErr := service.ResolveDestination(context.Background(), "current.i2p"); lookupErr != nil || got != currentDestination {
		t.Fatalf("current source = %q, %v", got, lookupErr)
	}
	if _, lookupErr := service.ResolveDestination(context.Background(), "stale.i2p"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("removed source remained resolvable: %v", lookupErr)
	}
	if len(service.sources) != 1 || service.sources[current] == nil || service.etag[current] != "current-tag" || service.modified[removed] != "" {
		t.Fatalf("filtered state = sources %#v etag %#v modified %#v", service.sources, service.etag, service.modified)
	}
	readded, err := NewService(Config{StatePath: statePath, Subscriptions: []string{removed}, MaxEntries: 100, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, lookupErr := readded.ResolveDestination(context.Background(), "stale.i2p"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("removed source snapshot resurrected when subscription was re-added: %v", lookupErr)
	}

	localOnly, err := NewService(Config{StatePath: statePath, MaxEntries: 100, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, lookupErr := localOnly.ResolveDestination(context.Background(), "current.i2p"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("local-only service loaded remote state: %v", lookupErr)
	}
	if len(localOnly.sources) != 0 || len(localOnly.remote) != 0 {
		t.Fatalf("local-only persisted remote = %#v %#v", localOnly.sources, localOnly.remote)
	}
}

func TestPersistedNonHTTPSSourceIsNeverAuthoritative(t *testing.T) {
	destination := newDestinationString(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	insecure := "http://removed.example/hosts.txt"
	if err := saveState(
		statePath,
		map[string]string{"stale.i2p": destination},
		map[string]map[string]string{insecure: {"stale.i2p": destination}},
		map[string]string{insecure: "stale-tag"},
		nil,
		1<<20,
	); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{
		StatePath:     statePath,
		Subscriptions: []string{"https://current.example/hosts.txt"},
		MaxEntries:    100,
		MaxFileBytes:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, lookupErr := service.ResolveDestination(context.Background(), "stale.i2p"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("insecure persisted source remained resolvable: %v", lookupErr)
	}
	if len(service.sources) != 0 || len(service.remote) != 0 || len(service.etag) != 0 {
		t.Fatalf("insecure persisted state loaded: sources=%#v remote=%#v etag=%#v", service.sources, service.remote, service.etag)
	}
}
