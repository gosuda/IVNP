package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"time"
)

var errPprofNotLoopback = errors.New("-pprof must bind a loopback address such as 127.0.0.1:6060, [::1]:6060, or localhost:6060")

// validatePprofAddr accepts only loopback IP literals and "localhost", so the
// profiling endpoints are never reachable from another host.
func validatePprofAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %v", errPprofNotLoopback, err)
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errPprofNotLoopback
	}
	return nil
}

// newPprofServer serves the profiling endpoints except /debug/pprof/cmdline,
// which would reveal process arguments such as -seed-phrase.
func newPprofServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/cmdline", http.NotFound)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// servePprof binds srv.Addr, refuses to serve when the bound address is not
// loopback (for example when "localhost" resolves elsewhere), and serves srv.
func servePprof(srv *http.Server) error {
	if err := validatePprofAddr(srv.Addr); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	bound, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !bound.IP.IsLoopback() {
		_ = listener.Close()
		return fmt.Errorf("%w: bound %s", errPprofNotLoopback, listener.Addr())
	}
	return srv.Serve(listener)
}
