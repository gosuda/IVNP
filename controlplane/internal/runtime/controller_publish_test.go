package noderuntime

import (
	"testing"
	"time"

	"gosuda.org/ivnp/state"
)

func TestHealthProbeConfigFallsBackToDaemonDefaults(t *testing.T) {
	var cfg state.ConfigurationOperating
	if got := healthProbeTimeout(cfg); got != daemonHealthProbeTimeoutMillis {
		t.Fatalf("zero probe timeout = %dms, want %d", got, daemonHealthProbeTimeoutMillis)
	}
	if got := healthProbeFailureThreshold(cfg); got != daemonHealthFailureThreshold {
		t.Fatalf("zero failure threshold = %d, want %d", got, daemonHealthFailureThreshold)
	}
	cfg.Tunnel.ProbeTimeout = 12 * time.Second
	cfg.Tunnel.ProbeFailureThreshold = 1
	if got := healthProbeTimeout(cfg); got != 12000 {
		t.Fatalf("configured probe timeout = %dms, want 12000", got)
	}
	if got := healthProbeFailureThreshold(cfg); got != 1 {
		t.Fatalf("configured failure threshold = %d, want 1", got)
	}
	cfg.Tunnel.ProbeFailureThreshold = -3
	if got := healthProbeFailureThreshold(cfg); got != 1 {
		t.Fatalf("negative failure threshold = %d, want clamped 1", got)
	}
	cfg.Tunnel.ProbeFailureThreshold = 999
	if got := healthProbeFailureThreshold(cfg); got != 255 {
		t.Fatalf("overflow failure threshold = %d, want clamped 255", got)
	}
}

func TestRequestDestinationPublicationDebounces(t *testing.T) {
	d := &Controller{
		ctx:                    t.Context(),
		destinationPublishWake: make(chan *destinationRuntime, 4),
		publishDebounce:        5 * time.Millisecond,
	}
	runtime := &destinationRuntime{}
	readWake := func(timeout time.Duration) *destinationRuntime {
		t.Helper()
		select {
		case queued := <-d.destinationPublishWake:
			queued.publishQueued.Store(destinationMaintenanceIdle)
			return queued
		case <-time.After(timeout):
			return nil
		}
	}
	d.requestDestinationPublication(runtime)
	if got := readWake(time.Second); got != runtime {
		t.Fatalf("leading publish wake = %v, want destination runtime", got)
	}
	d.requestDestinationPublication(runtime)
	d.requestDestinationPublication(runtime)
	if got := readWake(2 * time.Second); got != runtime {
		t.Fatalf("trailing publish wake = %v, want destination runtime", got)
	}
	select {
	case <-d.destinationPublishWake:
		t.Fatal("publication wake storm: uncoalesced event inside debounce window")
	case <-time.After(4 * d.publishDebounce):
	}
}
