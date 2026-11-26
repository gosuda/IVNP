package addressbook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubscriptionSkipsMalformedLines(t *testing.T) {
	first, second, duplicate := newDestinationString(t), newDestinationString(t), newDestinationString(t)
	body := strings.Join([]string{
		"#!sig=abc",
		"first.i2p=" + first,
		"no-separator-line",
		"bad name.i2p=" + first,
		"baddest.i2p=not-a-destination",
		"first.i2p=" + duplicate,
		"#!action=remove#!name=second.i2p",
		"second.i2p=" + second,
		"",
	}, "\n")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}
	service, err := NewService(Config{
		Subscriptions: []string{"https://feed.example/hosts.txt"}, HTTPClient: client,
		RequestTimeout: time.Second, MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.refresh(context.Background()); err != nil {
		t.Fatalf("refresh with malformed lines: %v", err)
	}
	for name, want := range map[string]string{"first.i2p": first, "second.i2p": second} {
		if got, lookupErr := service.ResolveDestination(context.Background(), name); lookupErr != nil || got != want {
			t.Fatalf("%s resolved to the wrong destination (err %v)", name, lookupErr)
		}
	}
	if _, lookupErr := service.ResolveDestination(context.Background(), "baddest.i2p"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("malformed entry resolved: %v", lookupErr)
	}
}

func TestFailedSubscriptionDoesNotBlockOtherFeeds(t *testing.T) {
	good, added, kept := newDestinationString(t), newDestinationString(t), newDestinationString(t)
	var phase atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: request}
		switch {
		case request.URL.Host == "good.example" && phase.Load() == 0:
			response.Body = io.NopCloser(strings.NewReader("good.i2p=" + good + "\n"))
		case request.URL.Host == "good.example":
			response.Body = io.NopCloser(strings.NewReader("good.i2p=" + good + "\nadded.i2p=" + added + "\n"))
		case phase.Load() == 0:
			response.Body = io.NopCloser(strings.NewReader("kept.i2p=" + kept + "\n"))
		default:
			response.StatusCode, response.Body = http.StatusInternalServerError, http.NoBody
		}
		return response, nil
	})}
	statePath := filepath.Join(t.TempDir(), "state.json")
	service, err := NewService(Config{
		StatePath: statePath, Subscriptions: []string{"https://good.example/hosts.txt", "https://broken.example/hosts.txt"},
		HTTPClient: client, RequestTimeout: time.Second, MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	phase.Store(1)
	if err = service.refresh(context.Background()); err == nil {
		t.Fatal("refresh with a failed subscription reported success")
	}
	for name, want := range map[string]string{"good.i2p": good, "added.i2p": added, "kept.i2p": kept} {
		if got, lookupErr := service.ResolveDestination(context.Background(), name); lookupErr != nil || got != want {
			t.Fatalf("%s resolved to the wrong destination (err %v)", name, lookupErr)
		}
	}
	if _, err = os.Stat(statePath); err != nil {
		t.Fatalf("state not saved after partial refresh: %v", err)
	}
}

func TestLocalHostsFileStaysStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("#!sig=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostsFile(path, 1<<20, 100); !errors.Is(err, ErrMutation) {
		t.Fatalf("loadHostsFile accepted a mutation command: %v", err)
	}
}
