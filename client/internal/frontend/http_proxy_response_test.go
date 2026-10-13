package frontend

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testPaddedUpstreamResponse(headerBytes int) string {
	prefix := "HTTP/1.1 200 OK\r\nX-Pad: "
	suffix := "\r\nContent-Length: 2\r\n\r\n"
	return prefix + strings.Repeat("a", headerBytes-len(prefix)-len(suffix)) + suffix + "ok"
}

func TestReadBoundedHTTPResponseHeaderLimit(t *testing.T) {
	const limit = 8192
	for _, test := range []struct {
		name   string
		size   int
		reject bool
	}{
		{name: "below", size: limit - 1},
		{name: "exact", size: limit},
		{name: "above", size: limit + 1, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := bufio.NewReader(strings.NewReader(testPaddedUpstreamResponse(test.size)))
			response, _, err := readBoundedHTTPResponse(upstream, &http.Request{Method: http.MethodGet}, limit)
			if test.reject {
				if !errors.Is(err, errHTTPResponseHeadersTooLarge) || response != nil {
					t.Fatalf("oversized response = %v, %v", response, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "ok" {
				t.Fatalf("response body = %q, %v", body, err)
			}
		})
	}
}

func TestReadBoundedHTTPResponseAllowsLFLineEndings(t *testing.T) {
	const header = "HTTP/1.1 200 OK\nContent-Length: 2\n\n"
	response, _, err := readBoundedHTTPResponse(bufio.NewReader(strings.NewReader(header+"ok")), &http.Request{Method: http.MethodGet}, len(header))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("response body = %q, %v", body, err)
	}
}

func TestReadBoundedHTTPResponsePreservesCONNECTPayload(t *testing.T) {
	const header = "HTTP/1.1 200 Connection Established\r\n\r\n"
	response, buffered, err := readBoundedHTTPResponse(bufio.NewReader(strings.NewReader(header+"pong")), &http.Request{Method: http.MethodConnect}, len(header))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	payload := make([]byte, 4)
	if _, err = io.ReadFull(buffered, payload); err != nil || string(payload) != "pong" {
		t.Fatalf("buffered tunnel payload = %q, %v", payload, err)
	}
}

func TestReadBoundedHTTPResponseRejectsUnterminatedHeaders(t *testing.T) {
	upstream := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", 65536)))
	_, _, err := readBoundedHTTPResponse(upstream, nil, 1024)
	if !errors.Is(err, errHTTPResponseHeadersTooLarge) {
		t.Fatalf("unterminated header error = %v", err)
	}
}

func TestReadBoundedHTTPResponseRejectsTruncatedHeaders(t *testing.T) {
	upstream := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"))
	_, _, err := readBoundedHTTPResponse(upstream, nil, 1024)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("truncated header error = %v", err)
	}
}

func TestHTTPProxyRejectsOversizedUpstreamHeaders(t *testing.T) {
	for _, test := range []struct {
		name     string
		outproxy bool
		connect  bool
	}{
		{name: "direct HTTP"},
		{name: "outproxy HTTP", outproxy: true},
		{name: "outproxy CONNECT", outproxy: true, connect: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			network := pipeNetwork(func(connection net.Conn) {
				defer connection.Close()
				if _, err := http.ReadRequest(bufio.NewReader(connection)); err != nil {
					return
				}
				_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nX-Pad: "+strings.Repeat("x", 2048)+"\r\n\r\n")
			})
			config := HTTPProxyConfig{
				Network: network, Resolver: fixedDestinationResolver(testB32),
				ListenAddress: "127.0.0.1:0", MaxHeaderBytes: 1024, Outproxies: []string{},
			}
			if test.outproxy {
				config.Outproxies = []string{"exit.stormycloud.i2p"}
				config.OutproxyWarmupReady = func() bool { return false }
			}
			proxy, err := NewHTTPProxy(config)
			if err != nil {
				t.Fatal(err)
			}
			if err = proxy.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = proxy.Close()
				if err := proxy.Wait(); err != nil {
					t.Error(err)
				}
			})
			client, err := net.Dial("tcp", proxy.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request := "GET http://" + testB32 + "/ HTTP/1.1\r\nHost: " + testB32 + "\r\n\r\n"
			if test.outproxy {
				request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
			}
			if test.connect {
				request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
			}
			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadGateway {
				t.Fatalf("oversized upstream header status = %d; want 502", response.StatusCode)
			}
		})
	}
}
