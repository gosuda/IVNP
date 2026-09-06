package noderuntime

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"gosuda.org/ivnp/client"
	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/observability"
	"gosuda.org/ivnp/state"
)

type Options struct {
	SocketRuntime dataplane.RouterSocketRuntime
	Transport     dataplane.RouterTransportManager
	HTTPClient    *http.Client
	Clock         dataplane.RouterClock
	Logger        *slog.Logger
	Listener      Listener
	NAT           controlplane.NATRuntime
	PanicReporter ingress.Reporter
}

type nodeService interface {
	Start(context.Context) error
	Close() error
	Wait() error
}

type Daemon struct {
	*controlplane.Controller
	config          state.ConfigurationOperating
	registry        *observability.Registry
	listener        Listener
	services        []nodeService
	addressBook     *client.AddressBookService
	samServer       *client.SimpleAnonymousMessagingServer
	control         *client.ClientControl
	httpProxy       *client.ClientHTTPProxy
	socks5          *client.ClientSOCKS5Proxy
	metrics         *http.Server
	metricsListener net.Listener
	mu              sync.Mutex
	started         bool
	closed          bool
	ctx             context.Context
	cancel          context.CancelFunc
	startReady      chan struct{}
	closeOnce       sync.Once
	closeErr        error
	err             error
	wg              sync.WaitGroup
}

func New(cfg state.ConfigurationOperating, options Options) (*Daemon, error) {
	invalid := (cfg.HTTPProxy.BearerToken != "" || cfg.SOCKS5.BearerToken != "") ||
		(cfg.HTTPProxy.Enabled && !loopbackEndpoint(cfg.HTTPProxy.Address)) ||
		(cfg.SOCKS5.Enabled && !loopbackEndpoint(cfg.SOCKS5.Address)) ||
		(cfg.SAM.Enabled && (!loopbackEndpoint(cfg.SAM.Address) || (cfg.SAM.UDPAddress.Host != "" && !loopbackEndpoint(cfg.SAM.UDPAddress)))) ||
		(cfg.Metrics.Enabled && !loopbackEndpoint(cfg.Metrics.Address) && cfg.Metrics.BearerToken == "")
	if invalid {
		return nil, client.ClientErrInvalidConfig
	}
	registry := observability.NewRegistry()
	core, err := controlplane.NewController(cfg, controlplane.ControllerOptions{
		SocketRuntime: options.SocketRuntime, Transport: options.Transport, HTTPClient: options.HTTPClient,
		Clock: options.Clock, Logger: options.Logger, NAT: options.NAT, PanicReporter: options.PanicReporter, Registry: registry,
	})
	if err != nil {
		return nil, err
	}
	listener := options.Listener
	if listener == nil {
		listener = nativeListener{}
	}
	d := &Daemon{Controller: core, config: cfg, registry: registry, listener: listener, startReady: make(chan struct{})}
	complete := false
	defer func() {
		if !complete {
			_ = d.Close()
		}
	}()
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	reporter := nodePanicReporter{registry: registry, logger: logger, next: options.PanicReporter}
	if cfg.AddressBook.Enabled {
		d.addressBook, err = client.AddressBookNewService(client.AddressBookConfig{
			PrivateHostsPath: cfg.AddressBook.PrivateHostsPath, UserHostsPath: cfg.AddressBook.UserHostsPath,
			HostsPath: cfg.AddressBook.HostsPath, StatePath: cfg.AddressBook.StatePath,
			Subscriptions:   append([]string(nil), cfg.AddressBook.Subscriptions...),
			RefreshInterval: cfg.AddressBook.RefreshInterval, RetryInterval: cfg.AddressBook.RetryInterval,
			RequestTimeout: cfg.AddressBook.RequestTimeout, MaxEntries: cfg.AddressBook.MaxEntries,
			MaxFileBytes: cfg.AddressBook.MaxFileBytes, MaxResponseBytes: cfg.AddressBook.MaxResponseBytes,
			MaxRedirects: cfg.AddressBook.MaxRedirects, HTTPClient: options.HTTPClient,
		})
		if err != nil {
			return nil, err
		}
		d.services = append(d.services, d.addressBook)
	}
	if cfg.SAM.Enabled {
		if !cfg.Tunnel.Enabled {
			return nil, dataplane.RouterErrDefaultDestination
		}
		udpAddress := ""
		if cfg.SAM.UDPAddress.Host != "" {
			udpAddress = cfg.SAM.UDPAddress.String()
		}
		d.samServer, err = client.SimpleAnonymousMessagingNewServer(client.SimpleAnonymousMessagingServerConfig{
			Address: cfg.SAM.Address.String(), UDPAddress: udpAddress, Listen: client.SimpleAnonymousMessagingListenFunc(listener.Listen),
			ListenPacket: client.SimpleAnonymousMessagingListenPacketFunc(listener.ListenPacket), Controller: core.DestinationController(), Resolver: d.addressBook,
			PanicReporter: reporter, Metrics: registry, MaxConnections: cfg.SAM.MaxConnections,
			MaxSessions: cfg.State.MaxDestinations, ReadinessTimeout: cfg.SAM.ReadinessTimeout, SessionQueue: cfg.SAM.SessionQueue,
			MaxSessionQueueBytes: cfg.SAM.MaxSessionQueueBytes, MaxServerQueueBytes: cfg.SAM.MaxServerQueueBytes, AllowLoopbackForward: true,
		})
		if err != nil {
			return nil, err
		}
		d.services = append(d.services, d.samServer)
	}
	if cfg.Control.Enabled {
		d.control, err = client.ClientNewControl(client.ClientControlConfig{
			ListenAddress: cfg.Control.Address.String(), AllowRemote: true, BearerToken: cfg.Control.BearerToken,
			MaxConnections: cfg.Control.MaxConnections, Status: d, Catalog: d, Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
		d.services = append(d.services, d.control)
	}
	if cfg.HTTPProxy.Enabled {
		d.httpProxy, err = client.ClientNewHTTPProxy(client.ClientHTTPProxyConfig{
			Network: core, Resolver: d.addressBook, Outproxies: cfg.HTTPProxy.Outproxies,
			OutproxyWarmupReady: core.OutproxyReady,
			ListenAddress:       cfg.HTTPProxy.Address.String(), MaxConnections: cfg.HTTPProxy.MaxConnections,
			Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
		d.services = append(d.services, d.httpProxy)
	}
	if cfg.SOCKS5.Enabled {
		d.socks5, err = client.ClientNewSOCKS5Proxy(client.ClientSOCKS5Config{
			Network: core, ListenAddress: cfg.SOCKS5.Address.String(), MaxConnections: cfg.SOCKS5.MaxConnections,
			Listen: listener.Listen, PanicReporter: reporter,
		})
		if err != nil {
			return nil, err
		}
		d.services = append(d.services, d.socks5)
	}
	complete = true
	return d, nil
}

func (d *Daemon) Start(parent context.Context) error {
	if d == nil {
		return net.ErrClosed
	}
	if parent == nil {
		parent = context.Background()
	}
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return controlplane.ErrStarted
	}
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.started = true
	d.ctx, d.cancel = context.WithCancel(parent)
	d.mu.Unlock()
	defer close(d.startReady)
	fail := func(err error) error {
		d.recordNodeError(err)
		d.mu.Lock()
		d.closed = true
		d.cancel()
		d.mu.Unlock()
		_ = d.closeResources()
		return err
	}
	if err := d.Controller.Start(d.ctx); err != nil {
		return fail(err)
	}
	for _, service := range d.services {
		if err := d.startNodeAllowed(); err != nil {
			return fail(err)
		}
		if err := service.Start(d.ctx); err != nil {
			return fail(err)
		}
		d.wg.Go(func() { d.recordNodeError(service.Wait()) })
	}
	if d.config.Metrics.Enabled {
		listener, err := d.listener.Listen(d.ctx, "tcp", d.config.Metrics.Address.String())
		if err != nil {
			return fail(err)
		}
		if err := d.startNodeAllowed(); err != nil {
			_ = listener.Close()
			return fail(err)
		}
		limit := max(1, d.config.Metrics.MaxConnections)
		d.metricsListener = client.ClientNewConnectionLimitedListener(listener, limit)
		handler := observability.NewHandler(d.registry, func(context.Context) observability.HealthStatus {
			if d.Status().Running {
				return observability.HealthOK
			}
			return observability.HealthUnavailable
		})
		if d.config.Metrics.BearerToken != "" {
			handler = observability.RequireBearer(handler, d.config.Metrics.BearerToken)
		}
		d.metrics = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
		d.wg.Go(func() {
			if err := d.metrics.Serve(d.metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				d.recordNodeError(err)
			}
		})
	}
	if err := d.startNodeAllowed(); err != nil {
		return fail(err)
	}
	d.wg.Go(func() { <-d.ctx.Done(); _ = d.Close() })
	d.wg.Go(func() { d.recordNodeError(d.Controller.Wait()); d.mu.Lock(); d.cancel(); d.mu.Unlock() })
	return nil
}

func (d *Daemon) startNodeAllowed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		return net.ErrClosed
	}
	return nil
}

func (d *Daemon) recordNodeError(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	d.mu.Lock()
	if d.err == nil {
		d.err = err
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
}

func (d *Daemon) closeResources() error {
	d.closeOnce.Do(func() {
		var result error
		for i := len(d.services) - 1; i >= 0; i-- {
			result = errors.Join(result, d.services[i].Close())
		}
		if d.metrics != nil {
			result = errors.Join(result, d.metrics.Close())
		} else if d.metricsListener != nil {
			result = errors.Join(result, d.metricsListener.Close())
		}
		d.closeErr = errors.Join(result, d.Controller.Close())
	})
	return d.closeErr
}

func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	d.closed = true
	started := d.started
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	if started {
		<-d.startReady
	}
	return d.closeResources()
}

func (d *Daemon) Wait() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	started := d.started
	d.mu.Unlock()
	if started {
		<-d.startReady
	}
	d.wg.Wait()
	coreErr := d.Controller.Wait()
	d.mu.Lock()
	err := d.err
	d.mu.Unlock()
	return errors.Join(err, coreErr)
}

func (d *Daemon) Status() controlplane.Status {
	if d == nil {
		return controlplane.Status{}
	}
	status := d.Controller.Status()
	d.mu.Lock()
	status.Running = status.Running && d.started && !d.closed
	status.Error = errors.Join(status.Error, d.err)
	d.mu.Unlock()
	return status
}

func (d *Daemon) ClientStatus(ctx context.Context) (controlplane.ManagementStatus, error) {
	status, err := d.Controller.ClientStatus(ctx)
	nodeStatus := d.Status()
	status.Ready = status.Ready && nodeStatus.Running
	return status, errors.Join(err, nodeStatus.Error)
}

// Listener provides stream and packet listening interfaces for node services.
type Listener interface {
	Listen(context.Context, string, string) (net.Listener, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
}

// ListenerFunc adapts a stream-only listener function to the Listener interface.
type ListenerFunc func(context.Context, string, string) (net.Listener, error)

func (f ListenerFunc) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return f(ctx, network, address)
}
func (ListenerFunc) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, ErrPacketListenerUnsupported
}

type PacketListenerFunc func(context.Context, string, string) (net.PacketConn, error)

type ListenerFuncs struct {
	Stream ListenerFunc
	Packet PacketListenerFunc
}

func (f ListenerFuncs) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if f.Stream == nil {
		return nil, net.ErrClosed
	}
	return f.Stream(ctx, network, address)
}
func (f ListenerFuncs) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if f.Packet == nil {
		return nil, ErrPacketListenerUnsupported
	}
	return f.Packet(ctx, network, address)
}

type nativeListener struct{}

func (nativeListener) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, network, address)
}
func (nativeListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

var ErrPacketListenerUnsupported = errors.New("node: packet listener edge not configured")

type nodePanicReporter struct {
	registry *observability.Registry
	logger   *slog.Logger
	next     ingress.Reporter
}

func (r nodePanicReporter) ReportRecoveredPanic(p ingress.Panic) {
	r.registry.IncIngressRecoveredPanics()
	if r.next != nil {
		r.next.ReportRecoveredPanic(p)
		return
	}
	r.logger.Error("contained untrusted ingress panic", "boundary", p.Boundary, "peer", p.Peer, "type", p.ValueType)
}

func loopbackEndpoint(endpoint state.ConfigurationEndpoint) bool {
	if endpoint.Host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(endpoint.Host)
	return err == nil && address.IsLoopback()
}
