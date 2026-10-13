package main

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebUIConnectionLimit(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited := newWebUILimitedListener(listener, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = limited
	server.Start()
	t.Cleanup(server.Close)

	first, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial first connection: %v", err)
	}
	defer first.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := request.Write(first); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(first), request)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close first response: %v", err)
	}
	if response.StatusCode != http.StatusNoContent || len(limited.slots) != 1 {
		t.Fatalf("first connection: status = %d, slots = %d", response.StatusCode, len(limited.slots))
	}

	excess, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial excess connection: %v", err)
	}
	defer excess.Close()
	_ = excess.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = request.Write(excess)
	excessResponse, err := http.ReadResponse(bufio.NewReader(excess), request)
	if err == nil {
		_ = excessResponse.Body.Close()
		t.Fatalf("excess connection unexpectedly accepted: HTTP %d", excessResponse.StatusCode)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("excess connection was not promptly rejected: %v", err)
	}
	if len(limited.slots) != 1 {
		t.Fatalf("excess connection consumed a slot: %d", len(limited.slots))
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(limited.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(limited.slots) != 0 {
		t.Fatalf("closed connection did not free a slot")
	}

	client := &http.Client{Timeout: 2 * time.Second}
	response, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("request after release: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("request after release: HTTP %d", response.StatusCode)
	}
}

func TestWebUILimitedConnCloseReleasesSlotOnce(t *testing.T) {
	t.Parallel()
	first, second := net.Pipe()
	defer second.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	conn := &webUILimitedConn{Conn: first, slots: slots}
	if err := conn.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if len(slots) != 0 {
		t.Fatalf("first close retained a slot")
	}
	slots <- struct{}{}
	if err := conn.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if len(slots) != 1 {
		t.Fatalf("second close released another connection's slot")
	}
}

func TestWebUISubscriberLimit(t *testing.T) {
	const token = "subscriber-limit-token"
	server := newTestWebUIServer(t, WebUIConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   token,
	})
	baseURL := startTestWebUIServer(t, server)
	client := &http.Client{Timeout: 15 * time.Second}

	getEvents := func(authenticated bool) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, baseURL+"/api/events", nil)
		if err != nil {
			t.Fatalf("new SSE request: %v", err)
		}
		if authenticated {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("GET events: %v", err)
		}
		return response
	}

	streams := make([]*http.Response, 0, maxWebUISubscribers)
	t.Cleanup(func() {
		for _, response := range streams {
			_ = response.Body.Close()
		}
	})
	for range maxWebUISubscribers {
		response := getEvents(true)
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			t.Fatalf("SSE admission at capacity: status = %d, want 200", response.StatusCode)
		}
		streams = append(streams, response)
	}

	unauthorized := getEvents(false)
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthorized request at capacity: status = %d, want 401", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	rejected := getEvents(true)
	if rejected.StatusCode != http.StatusServiceUnavailable || rejected.Header.Get("Retry-After") == "" {
		t.Errorf("SSE overload: status = %d, retry-after = %q", rejected.StatusCode, rejected.Header.Get("Retry-After"))
	}
	_ = rejected.Body.Close()
	server.subscribersMu.Lock()
	count := len(server.subscribers)
	server.subscribersMu.Unlock()
	if count != maxWebUISubscribers {
		t.Fatalf("subscriber count after rejection = %d, want %d", count, maxWebUISubscribers)
	}

	if err := streams[0].Body.Close(); err != nil {
		t.Fatalf("close SSE subscription: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		server.subscribersMu.Lock()
		count = len(server.subscribers)
		server.subscribersMu.Unlock()
		if count == maxWebUISubscribers-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("subscriber slot not released: count = %d", count)
		}
		time.Sleep(time.Millisecond)
	}

	admitted := getEvents(true)
	defer admitted.Body.Close()
	if admitted.StatusCode != http.StatusOK {
		t.Fatalf("SSE admission after release: status = %d, want 200", admitted.StatusCode)
	}
}
