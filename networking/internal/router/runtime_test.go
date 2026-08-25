package router

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
)

var _ stream.StreamNetwork = (*Router)(nil)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *eventLog) index(event string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, current := range l.events {
		if current == event {
			return i
		}
	}
	return -1
}

type fakeListener struct{ log *eventLog }

func (l *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *fakeListener) Close() error              { l.log.add("listener-close"); return nil }
func (l *fakeListener) Addr() net.Addr            { return fakeAddr("ntcp2") }

type fakePacketConn struct{ log *eventLog }

func (p *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (p *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *fakePacketConn) Close() error                              { p.log.add("packet-close"); return nil }
func (p *fakePacketConn) LocalAddr() net.Addr                       { return fakeAddr("ssu2") }
func (p *fakePacketConn) SetDeadline(time.Time) error               { return nil }
func (p *fakePacketConn) SetReadDeadline(time.Time) error           { return nil }
func (p *fakePacketConn) SetWriteDeadline(time.Time) error          { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

type fakeSockets struct {
	log       *eventLog
	packetErr error
}

func (s *fakeSockets) ListenStream(context.Context, Endpoint) (net.Listener, error) {
	s.log.add("listen-stream")
	return &fakeListener{log: s.log}, nil
}
func (s *fakeSockets) DialStream(context.Context, Endpoint) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}
func (s *fakeSockets) ListenUDP(context.Context, Endpoint) (*net.UDPConn, error) {
	s.log.add("listen-packet")
	if s.packetErr != nil {
		return nil, s.packetErr
	}
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

type fakeLocalInfo struct{ log *eventLog }

func (l *fakeLocalInfo) Hash() foundation.Hash      { return foundation.Hash{} }
func (l *fakeLocalInfo) Snapshot() netdb.RouterInfo { return netdb.RouterInfo{} }
func (l *fakeLocalInfo) ReplaceAddresses([]PublishedAddress) error {
	l.log.add("replace-addresses")
	return nil
}
func (l *fakeLocalInfo) SetReachability(Reachability)  {}
func (l *fakeLocalInfo) Publish(context.Context) error { l.log.add("publish"); return nil }

type fakeAddresses struct{ log *eventLog }

func (a *fakeAddresses) Addresses(context.Context) ([]PublishedAddress, error) {
	a.log.add("addresses")
	return []PublishedAddress{{Transport: "NTCP2"}}, nil
}

type fakeTransport struct {
	log       *eventLog
	wait      chan struct{}
	closeOnce sync.Once
	waitErr   error
	startErr  error
	bindings  TransportBindings
}

func newFakeTransport(log *eventLog) *fakeTransport {
	return &fakeTransport{log: log, wait: make(chan struct{})}
}

func (t *fakeTransport) Start(_ context.Context, bindings TransportBindings) error {
	t.bindings = bindings
	t.log.add("transport-start")
	return t.startErr
}
func (t *fakeTransport) Close() error {
	t.log.add("transport-close")
	t.closeOnce.Do(func() { close(t.wait) })
	return nil
}
func (t *fakeTransport) complete(err error) {
	t.waitErr = err
	t.closeOnce.Do(func() { close(t.wait) })
}
func (t *fakeTransport) Wait() error {
	<-t.wait
	t.log.add("transport-wait")
	return t.waitErr
}
func (t *fakeTransport) Send(context.Context, foundation.Hash, i2np.Message) error { return nil }
func (t *fakeTransport) Status() TransportStatus                                   { return TransportStatus{} }

type fakeStreamBackend struct {
	dialContext   context.Context
	dialAddress   string
	listenContext context.Context
	listenAddress string
	conn          net.Conn
	listener      net.Listener
}

func (b *fakeStreamBackend) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	b.dialContext = ctx
	b.dialAddress = address
	return b.conn, nil
}

func (b *fakeStreamBackend) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	b.listenContext = ctx
	b.listenAddress = address
	return b.listener, nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeReseed struct {
	log       *eventLog
	called    chan struct{}
	release   <-chan struct{}
	completed chan struct{}
	err       error

	mu        sync.Mutex
	context   context.Context
	endpoints []string
	database  *netdb.Database
	seenAt    uint64
	calls     int
}

func (r *fakeReseed) FetchAny(ctx context.Context, endpoints []string, database *netdb.Database, seenAt uint64) (int, error) {
	if r.completed != nil {
		defer close(r.completed)
	}
	r.mu.Lock()
	r.context = ctx
	r.endpoints = endpoints
	r.database = database
	r.seenAt = seenAt
	r.calls++
	r.mu.Unlock()
	if r.log != nil {
		r.log.add("reseed")
	}
	if r.called != nil {
		r.called <- struct{}{}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return 0, r.err
}

func (r *fakeReseed) call() (context.Context, []string, *netdb.Database, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.context, r.endpoints, r.database, r.seenAt
}

func (r *fakeReseed) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func newRuntimeForTest(t *testing.T, sockets SocketRuntime, transport TransportManager, log *eventLog) *Router {
	t.Helper()
	database := netdb.NewDatabase(foundation.Hash{}, 1)
	router, err := New(Config{
		NTCP2: Endpoint{Network: "tcp", Address: "127.0.0.1:0"},
		SSU2:  Endpoint{Network: "udp", Address: "127.0.0.1:0"},
	}, Dependencies{
		Database: database, LocalInfo: &fakeLocalInfo{log: log}, Transport: transport,
		Sockets: sockets, Addresses: &fakeAddresses{log: log}, Clock: WallClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func newRuntimeWithStreamBackendForTest(t *testing.T, backend StreamBackend) *Router {
	t.Helper()
	log := new(eventLog)
	database := netdb.NewDatabase(foundation.Hash{}, 1)
	router, err := New(Config{}, Dependencies{
		Database: database, LocalInfo: &fakeLocalInfo{log: log}, Transport: newFakeTransport(log),
		Sockets: &fakeSockets{log: log}, Addresses: &fakeAddresses{log: log}, Clock: WallClock{},
		StreamBackend: backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func newReseedRuntimeForTest(t *testing.T, cfg Config, log *eventLog, reseed ReseedRunner, clock Clock) (*Router, *netdb.Database, *fakeTransport) {
	t.Helper()
	database := netdb.NewDatabase(foundation.Hash{}, 1)
	transport := newFakeTransport(log)
	router, err := New(cfg, Dependencies{
		Database: database, LocalInfo: &fakeLocalInfo{log: log}, Transport: transport,
		Sockets: &fakeSockets{log: log}, Addresses: &fakeAddresses{log: log},
		Reseed: reseed, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return router, database, transport
}

func TestRouterStreamForwardingLifecycle(t *testing.T) {
	if _, err := newRuntimeWithStreamBackendForTest(t, nil).DialI2P(context.Background(), "destination.i2p"); !errors.Is(err, ErrStreamUnavailable) {
		t.Fatalf("DialI2P() without backend error = %v, want ErrStreamUnavailable", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	log := new(eventLog)
	listener := &fakeListener{log: log}
	backend := &fakeStreamBackend{conn: client, listener: listener}
	router := newRuntimeWithStreamBackendForTest(t, backend)

	if _, err := router.ListenI2P(context.Background(), "service.i2p"); !errors.Is(err, ErrStreamUnavailable) {
		t.Fatalf("ListenI2P() before Start error = %v, want ErrStreamUnavailable", err)
	}
	if err := router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), "test", "value")
	if conn, err := router.DialI2P(ctx, "destination.i2p"); err != nil || conn != client {
		t.Fatalf("DialI2P() = (%v, %v), want (%v, nil)", conn, err, client)
	}
	if backend.dialContext != ctx || backend.dialAddress != "destination.i2p" {
		t.Fatalf("DialI2P() delegated (%v, %q), want (%v, %q)", backend.dialContext, backend.dialAddress, ctx, "destination.i2p")
	}
	if got, err := router.ListenI2P(ctx, "service.i2p"); err != nil || got != listener {
		t.Fatalf("ListenI2P() = (%v, %v), want (%v, nil)", got, err, listener)
	}
	if backend.listenContext != ctx || backend.listenAddress != "service.i2p" {
		t.Fatalf("ListenI2P() delegated (%v, %q), want (%v, %q)", backend.listenContext, backend.listenAddress, ctx, "service.i2p")
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := router.DialI2P(context.Background(), "destination.i2p"); !errors.Is(err, ErrStreamUnavailable) {
		t.Fatalf("DialI2P() after Close error = %v, want ErrStreamUnavailable", err)
	}
	if _, err := router.ListenI2P(context.Background(), "service.i2p"); !errors.Is(err, ErrStreamUnavailable) {
		t.Fatalf("ListenI2P() after Close error = %v, want ErrStreamUnavailable", err)
	}
}

func TestRouterClosesSocketsBeforeTransportAndWaits(t *testing.T) {
	log := new(eventLog)
	transport := newFakeTransport(log)
	router := newRuntimeForTest(t, &fakeSockets{log: log}, transport, log)
	if err := router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !router.Running() || transport.bindings.NTCP2 == nil || transport.bindings.SSU2 == nil {
		t.Fatal("router did not publish running transport bindings")
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if state := router.Status().State; state != StateStopped {
		t.Fatalf("state after Close = %v", state)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	listenerClose, transportClose := log.index("listener-close"), log.index("transport-close")
	if listenerClose < 0 || transportClose < 0 || listenerClose > transportClose {
		t.Fatalf("close ordering = %#v", log.events)
	}
	if log.index("addresses") > log.index("transport-start") || log.index("publish") > log.index("transport-start") {
		t.Fatalf("startup ordering = %#v", log.events)
	}
}

func TestRouterRollsBackSocketOnStartupFailure(t *testing.T) {
	log := new(eventLog)
	want := errors.New("packet bind failed")
	router := newRuntimeForTest(t, &fakeSockets{log: log, packetErr: want}, newFakeTransport(log), log)
	if err := router.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start = %v", err)
	}
	if err := router.Wait(); !errors.Is(err, want) {
		t.Fatalf("Wait = %v", err)
	}
	if log.index("listener-close") < 0 {
		t.Fatalf("listener was not rolled back: %#v", log.events)
	}
	if state := router.Status().State; state != StateStopped {
		t.Fatalf("state after rollback = %v", state)
	}
	if err := router.Start(context.Background()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start = %v", err)
	}
}

func TestRouterDoesNotCloseUnstartedTransport(t *testing.T) {
	log := new(eventLog)
	want := errors.New("transport start failed")
	transport := newFakeTransport(log)
	transport.startErr = want
	router := newRuntimeForTest(t, &fakeSockets{log: log}, transport, log)
	if err := router.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start = %v, want %v", err, want)
	}
	if err := router.Wait(); !errors.Is(err, want) {
		t.Fatalf("Wait = %v, want %v", err, want)
	}
	if log.index("transport-close") >= 0 {
		t.Fatalf("unstarted transport was closed: %#v", log.events)
	}
}

func TestRouterParentCancellationClosesResources(t *testing.T) {
	log := new(eventLog)
	transport := newFakeTransport(log)
	router := newRuntimeForTest(t, &fakeSockets{log: log}, transport, log)
	ctx, cancel := context.WithCancel(context.Background())
	if err := router.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := router.Wait(); err != nil {
		t.Fatalf("Wait after parent cancellation = %v", err)
	}
	if state := router.Status().State; state != StateStopped {
		t.Fatalf("state after parent cancellation = %v", state)
	}
	if log.index("listener-close") < 0 || log.index("transport-close") < 0 {
		t.Fatalf("cancellation did not close runtime resources: %#v", log.events)
	}
}

func TestRouterMarksUnexpectedTransportExitFailed(t *testing.T) {
	log := new(eventLog)
	transport := newFakeTransport(log)
	router := newRuntimeForTest(t, &fakeSockets{log: log}, transport, log)
	if err := router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	transport.complete(errors.New("transport failed"))
	if err := router.Wait(); !errors.Is(err, transport.waitErr) {
		t.Fatalf("Wait = %v", err)
	}
	if state := router.Status().State; state != StateFailed {
		t.Fatalf("state after transport failure = %v", state)
	}
	if log.index("listener-close") < 0 {
		t.Fatalf("fatal shutdown did not close sockets: %#v", log.events)
	}
}

func TestRouterOptionalReseedDoesNotBlockStartup(t *testing.T) {
	log := new(eventLog)
	release := make(chan struct{})
	reseedErr := errors.New("reseed unavailable")
	reseed := &fakeReseed{
		log: log, called: make(chan struct{}, 1), release: release,
		completed: make(chan struct{}), err: reseedErr,
	}
	router, _, _ := newReseedRuntimeForTest(t, Config{
		ReseedEndpoints: []string{"https://reseed.example/i2p"},
	}, log, reseed, fixedClock{now: time.Unix(1, 0)})
	outcomes := make(chan error, 1)
	router.deps.ReseedOutcome = func(err error) { outcomes <- err }
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan error, 1)
	go func() { started <- router.Start(parent) }()
	select {
	case <-reseed.called:
	case <-time.After(time.Second):
		t.Fatal("optional reseed was not invoked")
	}
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("Start = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start blocked on optional reseed")
	}
	if log.index("transport-start") < 0 || log.index("transport-start") > log.index("reseed") {
		t.Fatalf("reseed started before transport: %#v", log.events)
	}

	close(release)
	select {
	case <-reseed.completed:
	case <-time.After(time.Second):
		t.Fatal("optional reseed did not complete")
	}
	select {
	case err := <-outcomes:
		if !errors.Is(err, reseedErr) {
			t.Fatalf("reseed outcome = %v, want %v", err, reseedErr)
		}
	case <-time.After(time.Second):
		t.Fatal("optional reseed outcome was not reported")
	}
	if err := router.Status().Error; err != nil {
		t.Fatalf("Status().Error = %v, want nil", err)
	}
	if !router.Running() {
		t.Fatal("optional reseed failure stopped the router")
	}
	cancel()
	if err := router.Wait(); err != nil {
		t.Fatalf("Wait after cancellation = %v, want nil", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("Close after cancellation = %v, want nil", err)
	}
}

func TestRouterMaintenanceReseedCoalescesAndBacksOff(t *testing.T) {
	log := new(eventLog)
	release := make(chan struct{})
	reseed := &fakeReseed{
		log: log, called: make(chan struct{}, 1), release: release,
		completed: make(chan struct{}), err: errors.New("reseed unavailable"),
	}
	router, _, _ := newReseedRuntimeForTest(t, Config{
		ReseedEndpoints: []string{"https://reseed.example/i2p"},
	}, log, reseed, fixedClock{now: time.Unix(1, 0)})
	if err := router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reseed.called:
	case <-time.After(time.Second):
		t.Fatal("startup reseed was not invoked")
	}
	router.MaintainReseed(router.Context())
	if calls := reseed.callCount(); calls != 1 {
		t.Fatalf("concurrent maintenance reseed calls = %d, want 1", calls)
	}
	close(release)
	select {
	case <-reseed.completed:
	case <-time.After(time.Second):
		t.Fatal("startup reseed did not complete")
	}
	router.MaintainReseed(router.Context())
	if calls := reseed.callCount(); calls != 1 {
		t.Fatalf("backed-off maintenance reseed calls = %d, want 1", calls)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRouterReseedsWithFiftyTransportStaleRetainedPeers(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	log := new(eventLog)
	reseed := &fakeReseed{log: log, called: make(chan struct{}, 1), completed: make(chan struct{})}
	runtime, _, _ := newReseedRuntimeForTest(t, Config{
		ReseedEndpoints: []string{"https://reseed.example/i2p"},
	}, log, reseed, fixedClock{now: now})
	database := netdb.NewDatabase(foundation.Hash{}, 64)
	runtime.deps.Database = database

	published := uint64(now.UnixMilli()) - netdb.RouterInfoMaxAgeMillis - 1
	for range reseedBootstrapMinimum {
		local, err := foundation.GenerateLocalRouterAddress()
		if err != nil {
			t.Fatal(err)
		}
		identity, _, err := foundation.ParseIdentity(local.RouterIdentity)
		if err != nil {
			t.Fatal(err)
		}
		database.Routers().StoreVerified(netdb.RouterInfo{Identity: identity, Published: published}, false, uint64(now.UnixMilli()))
	}
	if got := database.Routers().Len(); got != reseedBootstrapMinimum {
		t.Fatalf("retained peers = %d, want %d", got, reseedBootstrapMinimum)
	}

	done := runtime.startReseed(context.Background())
	if done == nil {
		t.Fatal("transport-stale retained peers suppressed reseed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reseed did not complete")
	}
	if calls := reseed.callCount(); calls != 1 {
		t.Fatalf("reseed calls = %d, want 1", calls)
	}
}

func TestRouterRequiredReseedFailureRollsBackStartup(t *testing.T) {
	log := new(eventLog)
	reseedErr := errors.New("required reseed failed")
	reseed := &fakeReseed{
		log: log, called: make(chan struct{}, 1), completed: make(chan struct{}), err: reseedErr,
	}
	router, _, _ := newReseedRuntimeForTest(t, Config{
		ReseedEndpoints: []string{"https://reseed.example/i2p"},
		RequireReseed:   true,
	}, log, reseed, fixedClock{now: time.Unix(1, 0)})
	outcomes := make(chan error, 1)
	router.deps.ReseedOutcome = func(err error) { outcomes <- err }

	if err := router.Start(context.Background()); !errors.Is(err, reseedErr) {
		t.Fatalf("Start = %v, want %v", err, reseedErr)
	}
	select {
	case err := <-outcomes:
		if !errors.Is(err, reseedErr) {
			t.Fatalf("reseed outcome = %v, want %v", err, reseedErr)
		}
	case <-time.After(time.Second):
		t.Fatal("required reseed outcome was not reported")
	}
	if err := router.Wait(); !errors.Is(err, reseedErr) {
		t.Fatalf("Wait = %v, want %v", err, reseedErr)
	}
	if router.Running() || router.Status().State != StateStopped {
		t.Fatalf("state after required reseed failure = %v", router.Status().State)
	}
	if log.index("transport-start") < 0 || log.index("transport-start") > log.index("reseed") || log.index("transport-close") < 0 {
		t.Fatalf("required reseed failure did not roll back transport: %#v", log.events)
	}
}

func TestRouterReseedPropagatesRuntimeDependencies(t *testing.T) {
	log := new(eventLog)
	now := time.Unix(1_700_000_000, 987_000_000).UTC()
	endpoints := []string{"https://one.example/i2p", "https://two.example/i2p"}
	reseed := &fakeReseed{log: log, called: make(chan struct{}, 1), completed: make(chan struct{})}
	router, database, _ := newReseedRuntimeForTest(t, Config{
		ReseedEndpoints: endpoints,
		RequireReseed:   true,
	}, log, reseed, fixedClock{now: now})

	outcomes := make(chan error, 1)
	router.deps.ReseedOutcome = func(err error) { outcomes <- err }
	if err := router.Start(context.WithValue(context.Background(), "key", "value")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-outcomes:
		if err != nil {
			t.Fatalf("reseed outcome = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful reseed outcome was not reported")
	}
	ctx, gotEndpoints, gotDatabase, seenAt := reseed.call()
	if ctx != router.Context() {
		t.Fatal("reseed did not receive the router context")
	}
	if len(gotEndpoints) != len(endpoints) {
		t.Fatalf("reseed endpoints = %q, want %q", gotEndpoints, endpoints)
	}
	for i := range endpoints {
		if gotEndpoints[i] != endpoints[i] {
			t.Fatalf("reseed endpoint %d = %q, want %q", i, gotEndpoints[i], endpoints[i])
		}
	}
	if &gotEndpoints[0] != &endpoints[0] {
		t.Fatal("reseed endpoints were copied")
	}
	if gotDatabase != database {
		t.Fatalf("reseed database = %p, want %p", gotDatabase, database)
	}
	if want := uint64(now.UnixMilli()); seenAt != want {
		t.Fatalf("reseed timestamp = %d, want %d", seenAt, want)
	}
	if log.index("transport-start") < 0 || log.index("transport-start") > log.index("reseed") {
		t.Fatalf("reseed started before transport: %#v", log.events)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
}
