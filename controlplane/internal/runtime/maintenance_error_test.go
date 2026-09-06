package noderuntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/router"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
)

type maintenanceErrorSource struct {
	err  error
	next func()
}

func (s maintenanceErrorSource) NextInbound(context.Context, uint64, uint32) (tunnel.InboundBuild, error) {
	if s.next != nil {
		s.next()
	}
	return tunnel.InboundBuild{}, s.err
}

func (s maintenanceErrorSource) NextOutboundForReply(context.Context, uint64, tunnel.ReplyRoute) (tunnel.OutboundBuild, error) {
	return tunnel.OutboundBuild{}, s.err
}

func newMaintenanceErrorRuntime(t *testing.T, source maintenanceErrorSource) *destinationRuntime {
	t.Helper()
	const now = uint64(100)
	pool := tunnel.NewPool(2)
	sender := new(requestDirectCapture)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: sender, Now: func() uint64 { return now }})
	builder, err := tunnel.NewBuildManager(tunnel.BuildManagerConfig{
		Runtime: runtime, Pool: pool, Sender: sender,
		ReplyKeys: dataplane.GarlicNewReplyKeyRegistry(4), Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(builder.ReleaseSensitive)
	maintainer, err := tunnel.NewPairedPoolMaintainer(tunnel.PairedPoolMaintainerConfig{
		Pool: pool, Runtime: runtime, Builder: builder, InboundSource: source, OutboundSource: source,
		Now: func() uint64 { return now }, InboundTarget: 1, OutboundTarget: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := maintainer.Close(); err != nil {
			t.Error(err)
		}
	})
	return &destinationRuntime{maintainer: maintainer}
}

func TestMaintenanceErrorsPreserveIndependentFailures(t *testing.T) {
	failure := errors.New("invalid destination tunnel configuration")
	transients := errors.Join(
		tunnel.ErrBuildPending, context.Canceled, context.DeadlineExceeded, net.ErrClosed,
		tunnel.ErrNoEligiblePeers, netdb.ErrNoFloodfill, router.ErrTransportUnavailable,
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
	)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "pending", err: tunnel.ErrBuildPending},
		{name: "wrapped pending", err: fmt.Errorf("renew destination: %w", tunnel.ErrBuildPending)},
		{name: "transient siblings", err: fmt.Errorf("renew destination: %w", transients)},
		{name: "pending with failure", err: errors.Join(tunnel.ErrBuildPending, failure), want: failure},
		{name: "wrapper over join", err: fmt.Errorf("renew destination: %w", errors.Join(tunnel.ErrBuildPending, failure)), want: failure},
		{name: "transient siblings with failure", err: fmt.Errorf("renew destination: %w", errors.Join(transients, fmt.Errorf("select inbound path: %w", failure))), want: failure},
	}
	paths := []struct {
		name string
		run  func(*testing.T, *Controller, *destinationRuntime)
	}{
		{name: "destination", run: func(_ *testing.T, d *Controller, runtime *destinationRuntime) {
			d.maintainDestination(runtime)
		}},
		{name: "destination tunnels", run: func(_ *testing.T, d *Controller, runtime *destinationRuntime) {
			d.maintainDestinationTunnels(runtime)
		}},
		{name: "exploratory tunnels", run: func(t *testing.T, d *Controller, runtime *destinationRuntime) {
			ctx, cancel := context.WithCancel(d.ctx)
			d.ctx = ctx
			d.maintainer = runtime.maintainer
			d.tunnelWake = make(chan struct{}, 1)
			d.wg.Add(1)
			go d.tunnelMaintenanceLoop()
			defer func() { cancel(); d.wg.Wait() }()
			d.requestExploratoryMaintenance()
			synctest.Wait()
		}},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						d, err := NewController(daemonTestConfig(t), ControllerOptions{
							SocketRuntime: new(recordingSockets), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
						})
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if err := d.Close(); err != nil {
								t.Error(err)
							}
						})
						d.ctx = t.Context()
						runtime := newMaintenanceErrorRuntime(t, maintenanceErrorSource{err: test.err})
						path.run(t, d, runtime)
						status := d.Status()
						if test.want == nil {
							if status.Error != nil {
								t.Fatalf("expected maintenance condition poisoned status: %v", status.Error)
							}
							if failures := d.registry.Snapshot().Lifecycle.Failures; failures != 0 {
								t.Fatalf("expected maintenance condition recorded %d lifecycle failures", failures)
							}
							return
						}
						if !errors.Is(status.Error, test.want) || !errors.Is(status.Error, test.err) {
							t.Fatalf("status error = %v, want genuine failure and original diagnostic context %v", status.Error, test.err)
						}
						if failures := d.registry.Snapshot().Lifecycle.Failures; failures != 1 {
							t.Fatalf("genuine maintenance failure recorded %d lifecycle failures, want 1", failures)
						}
					})
				})
			}
		})
	}
}

func TestDestinationMaintenanceSuppressesNodeShutdownErrors(t *testing.T) {
	d, err := NewController(daemonTestConfig(t), ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d.ctx = ctx
	runtime := newMaintenanceErrorRuntime(t, maintenanceErrorSource{
		err: errors.New("source closed during node shutdown"), next: cancel,
	})
	d.maintainDestination(runtime)
	if err := d.Status().Error; err != nil {
		t.Fatalf("node shutdown poisoned status: %v", err)
	}
	if failures := d.registry.Snapshot().Lifecycle.Failures; failures != 0 {
		t.Fatalf("node shutdown recorded %d lifecycle failures", failures)
	}
}
