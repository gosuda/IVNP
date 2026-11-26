package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePprofAddrRequiresLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:6060", "127.0.0.2:0", "[::1]:6060", "localhost:6060"} {
		if err := validatePprofAddr(addr); err != nil {
			t.Errorf("validatePprofAddr(%q) = %v, want nil", addr, err)
		}
	}
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.1:6060", "[2001:db8::1]:6060", "example.com:6060", "6060", ""} {
		if err := validatePprofAddr(addr); err == nil {
			t.Errorf("validatePprofAddr(%q) = nil, want loopback rejection", addr)
		}
	}
}

func TestRunRejectsNonLoopbackPprofAddr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-pprof", "0.0.0.0:0", "-once", "-no-router", "-listen", "", "-data-dir", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(-pprof 0.0.0.0:0) = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("stderr = %q, want a loopback error", stderr.String())
	}
}

func TestPprofServerOmitsCmdline(t *testing.T) {
	srv := newPprofServer("127.0.0.1:0")
	for path, want := range map[string]int{
		"/debug/pprof/":          http.StatusOK,
		"/debug/pprof/goroutine": http.StatusOK,
		"/debug/pprof/cmdline":   http.StatusNotFound,
	} {
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
		if strings.Contains(rec.Body.String(), "-test.") {
			t.Errorf("GET %s leaked process arguments: %q", path, rec.Body.String())
		}
	}
}
