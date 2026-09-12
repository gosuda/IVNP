package noderuntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/state"
)

type nodeSockets struct{}

func (nodeSockets) ListenStream(context.Context, dataplane.RouterEndpoint) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
func (nodeSockets) DialStream(ctx context.Context, endpoint dataplane.RouterEndpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, endpoint.Network, endpoint.Address)
}
func (nodeSockets) ListenUDP(context.Context, dataplane.RouterEndpoint) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}
func TestStartRollsBackWhenMetricsListenerFails(t *testing.T) {
	cfg := nodeTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 4}
	listenErr := errors.New("metrics listener failed")
	d, err := New(cfg, Options{
		SocketRuntime: nodeSockets{},
		Listener: ListenerFunc(func(context.Context, string, string) (net.Listener, error) {
			return nil, listenErr
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); !errors.Is(err, listenErr) {
		t.Fatalf("Start error = %v, want %v", err, listenErr)
	}
	status := d.Status()
	if status.Running || !errors.Is(status.Error, listenErr) {
		t.Fatal("failed Start left router running or did not retain the listener error")
	}
	if err := d.Wait(); !errors.Is(err, listenErr) {
		t.Fatalf("Wait error = %v, want %v", err, listenErr)
	}
}
func TestWaitDoesNotRaceStartRegistration(t *testing.T) {
	cfg := nodeTestConfig(t)
	cfg.NTCP2.Enabled = false
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		d, err := New(cfg, Options{
			Transport: &idleNodeTransport{},
			Listener: ListenerFunc(func(context.Context, string, string) (net.Listener, error) {
				close(entered)
				<-release
				return listener, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			select {
			case <-release:
			default:
				close(release)
			}
			if err := d.Close(); err != nil {
				t.Error(err)
			}
			if err := d.Wait(); err != nil {
				t.Error(err)
			}
			synctest.Wait()
		}()
		if err := d.Wait(); err != nil {
			t.Fatalf("Wait before Start = %v", err)
		}
		started := make(chan error, 1)
		go func() { started <- d.Start(ctx) }()
		<-entered
		waited := make(chan error, 1)
		go func() { waited <- d.Wait() }()
		// Finish the controller so its Wait cannot mask a missing node startup barrier.
		cancel()
		if err := d.Controller.Wait(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-waited:
			t.Fatalf("Wait returned before Start registered workers: %v", err)
		default:
		}
		close(release)
		if err := <-started; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Start error = %v, want closed", err)
		}
		if err := <-waited; err != nil {
			t.Fatal(err)
		}
	})
}

func TestCloseWaitsForStartupBeforeReleasingResources(t *testing.T) {
	cfg := nodeTestConfig(t)
	cfg.NTCP2.Enabled = false
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 1}
	returned, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := returned.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		canceled := make(chan struct{})
		release := make(chan struct{})
		d, err := New(cfg, Options{
			Transport: &idleNodeTransport{},
			Listener: ListenerFunc(func(ctx context.Context, _, _ string) (net.Listener, error) {
				close(entered)
				<-ctx.Done()
				close(canceled)
				<-release
				return returned, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			select {
			case <-release:
			default:
				close(release)
			}
			if err := d.Close(); err != nil {
				t.Error(err)
			}
			if err := d.Wait(); err != nil {
				t.Error(err)
			}
			synctest.Wait()
		}()
		started := make(chan error, 1)
		go func() { started <- d.Start(ctx) }()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- d.Close() }()
		<-canceled
		if err := d.Controller.Wait(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatalf("Close returned before Start completed registration: %v", err)
		default:
		}
		close(release)
		if err := <-started; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Start error = %v, want closed", err)
		}
		if err := <-closed; err != nil {
			t.Fatalf("Close error = %v", err)
		}
		if err := returned.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("returned listener remained open: Close() = %v", err)
		}
		if d.Status().Running {
			t.Fatal("canceled startup left a listener or server running")
		}
	})
	second, err := New(cfg, Options{Transport: &idleNodeTransport{}})
	if err != nil {
		t.Fatalf("New after concurrent Close error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestMetricsBearerAuthentication(t *testing.T) {
	cfg := nodeTestConfig(t)
	cfg.Metrics = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, BearerToken: "metrics-token", MaxConnections: 1}
	d, err := New(cfg, Options{SocketRuntime: nodeSockets{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
		_ = d.Wait()
	})
	url := "http://" + d.metricsListener.Addr().String() + "/metrics"
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d", response.StatusCode)
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer metrics-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated metrics status = %d", response.StatusCode)
	}
}

func nodeTestConfig(t *testing.T) state.ConfigurationOperating {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	return state.ConfigurationOperating{
		StatePath: filepath.Join(base, "router.state"), KeyPath: filepath.Join(base, "router.keys"),
		Network: state.ConfigurationNetwork{ID: 2, IPv4: true},
		Router:  state.ConfigurationRouter{Version: "0.9.70"},
		State:   state.ConfigurationState{MaxBytes: 1 << 20, MaxDestinations: 16, MaxNameBytes: 64},
		NetDB:   state.ConfigurationNetDB{BucketCapacity: 4, LookupCapacity: 8},
		Tunnel: state.ConfigurationTunnel{
			Hops: 1, ExploratoryInboundTarget: 1, ExploratoryOutboundTarget: 1, ExploratoryPoolCapacity: 4,
			ClientInboundTarget: 1, ClientOutboundTarget: 1, ClientPoolCapacity: 4, BuildPendingCapacity: 4,
			Lifetime: 10 * time.Minute, RenewBefore: 10 * time.Second, MaintenanceInterval: time.Minute,
			BandwidthRateBytesPerSecond: 64 * 1024,
		},
		NTCP2: state.ConfigurationTransport{Enabled: true, Bind: state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 12345}, MaxSessions: 4},
	}
}

func TestTaintedCopyAllowsConcurrentInstancesWithoutLockConflict(t *testing.T) {
	cfg := nodeTestConfig(t)
	primary, err := New(cfg, Options{SocketRuntime: nodeSockets{}})
	if err != nil {
		t.Fatalf("primary New error = %v", err)
	}
	defer func() {
		_ = primary.Close()
		_ = primary.Wait()
	}()

	// Second instance without tainted copy must fail due to locked state directory
	_, err = New(cfg, Options{SocketRuntime: nodeSockets{}})
	if err == nil {
		t.Fatal("expected second instance without tainted copy to fail with lock conflict, got nil")
	}

	// Second instance with TaintedCopy = true must succeed
	taintedCfg := cfg
	taintedCfg.State.TaintedCopy = true
	secondary, err := New(taintedCfg, Options{SocketRuntime: nodeSockets{}, TaintedCopy: true})
	if err != nil {
		t.Fatalf("secondary New with TaintedCopy error = %v", err)
	}

	taintedDir := secondary.TaintedDir()
	if taintedDir == "" {
		t.Fatal("expected non-empty TaintedDir")
	}
	if _, err := os.Stat(taintedDir); err != nil {
		t.Fatalf("expected tainted directory to exist, err = %v", err)
	}

	if secondary.Hash() != primary.Hash() {
		t.Fatalf("secondary router hash %x != primary router hash %x", secondary.Hash(), primary.Hash())
	}

	if err := secondary.Close(); err != nil {
		t.Fatalf("secondary Close error = %v", err)
	}
	_ = secondary.Wait()

	if _, err := os.Stat(taintedDir); !os.IsNotExist(err) {
		t.Fatalf("expected tainted directory %s to be deleted after close, err = %v", taintedDir, err)
	}
}

func TestTaintedCopyCustomTempDir(t *testing.T) {
	cfg := nodeTestConfig(t)
	customTemp := filepath.Join(t.TempDir(), "custom-tmp")
	cfg.TempDir = customTemp
	cfg.State.TaintedCopy = true

	d, err := New(cfg, Options{SocketRuntime: nodeSockets{}, TaintedCopy: true})
	if err != nil {
		t.Fatalf("New error = %v", err)
	}
	defer func() {
		_ = d.Close()
		_ = d.Wait()
	}()

	taintedDir := d.TaintedDir()
	if taintedDir == "" {
		t.Fatal("expected non-empty TaintedDir")
	}
	if !filepath.HasPrefix(taintedDir, customTemp) {
		t.Fatalf("expected taintedDir %s to be inside custom temp dir %s", taintedDir, customTemp)
	}
}

func TestTaintedCopyOpportunisticMasterPromotion(t *testing.T) {
	cfg := nodeTestConfig(t)

	// 1. Start primary daemon holding the master lock
	primary, err := New(cfg, Options{SocketRuntime: nodeSockets{}})
	if err != nil {
		t.Fatalf("primary New error = %v", err)
	}

	// 2. Start secondary daemon with TaintedCopy = true and short LockRetryInterval
	taintedCfg := cfg
	taintedCfg.State.TaintedCopy = true
	taintedCfg.State.PromoteToMaster = true
	taintedCfg.State.LockRetryInterval = 50 * time.Millisecond

	secondary, err := New(taintedCfg, Options{
		SocketRuntime:     nodeSockets{},
		TaintedCopy:       true,
		LockRetryInterval: 50 * time.Millisecond,
	})
	if err != nil {
		_ = primary.Close()
		t.Fatalf("secondary New error = %v", err)
	}
	defer func() {
		_ = secondary.Close()
		_ = secondary.Wait()
	}()

	if err := secondary.Start(context.Background()); err != nil {
		_ = primary.Close()
		t.Fatalf("secondary Start error = %v", err)
	}

	taintedDir := secondary.TaintedDir()
	if taintedDir == "" {
		t.Fatal("expected secondary to have non-empty TaintedDir")
	}
	if secondary.IsPromoted() {
		t.Fatal("secondary should not be promoted while primary is alive")
	}

	// 3. Stop primary daemon (simulating old container shutdown in rolling update)
	if err := primary.Close(); err != nil {
		t.Fatalf("primary Close error = %v", err)
	}
	_ = primary.Wait()

	// 4. Secondary's background retry loop should detect primary's exit and promote itself to master!
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(3 * time.Second)
	for !secondary.IsPromoted() {
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatal("secondary failed to promote to master within deadline")
		}
	}

	if secondary.TaintedDir() != "" {
		t.Fatalf("expected TaintedDir to be empty after promotion, got %s", secondary.TaintedDir())
	}

	if _, err := os.Stat(taintedDir); !os.IsNotExist(err) {
		t.Fatalf("expected tainted dir %s to be deleted after promotion, err = %v", taintedDir, err)
	}

	// 5. Verify that secondary now holds the master lock
	third, err := New(cfg, Options{SocketRuntime: nodeSockets{}})
	if third != nil {
		_ = third.Close()
		t.Fatal("third instance should have failed to lock master")
	}
	if err == nil {
		t.Fatal("third instance should have failed with lock error")
	}

	// 6. Stop secondary daemon cleanly
	if err := secondary.Close(); err != nil {
		t.Fatalf("secondary Close error = %v", err)
	}
	_ = secondary.Wait()

	// 7. After secondary stops, master lock is released so a fresh daemon can open master
	fourth, err := New(cfg, Options{SocketRuntime: nodeSockets{}})
	if err != nil {
		t.Fatalf("fourth instance failed to open master state: %v", err)
	}
	defer func() {
		_ = fourth.Close()
		_ = fourth.Wait()
	}()

	if fourth.Hash() != secondary.Hash() {
		t.Fatalf("fourth router hash %x != promoted router hash %x", fourth.Hash(), secondary.Hash())
	}
}
