package router

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/tunnel"
)

var (
	ErrStarted           = errors.New("router: already started")
	ErrStreamUnavailable = errors.New("router: stream backend unavailable")
	ErrTransportStopped  = errors.New("router: transport stopped unexpectedly")
)

const (
	reseedBootstrapMinimum = 50
	reseedInitialBackoff   = time.Minute
	reseedMaximumBackoff   = time.Hour
)

// State is the lifecycle state of an embedded Router.
type State uint8

const (
	StateNew State = iota
	StateStarting
	StateRunning
	StateStopping
	StateStopped
	StateFailed
)

// Reachability is published by LocalInfo. A successful socket bind alone must
// not be treated as proof of reachability.
type Reachability uint8

const (
	ReachabilityUnknown Reachability = iota
	ReachabilityFirewalled
	ReachabilityReachable
)

// MappingOption is one opaque RouterInfo address option.
type MappingOption struct {
	Key   string
	Value string
}

// PublishedAddress is an address ready for inclusion in a local RouterInfo.
type PublishedAddress struct {
	Transport string
	Cost      uint8
	Options   []MappingOption
}

// AddressPublisher derives signed RouterInfo address material independently of
// socket binding. It may use mapping or peer-observation information, but a
// listener bind by itself is not a reachability claim.
type AddressPublisher interface {
	Addresses(context.Context) ([]PublishedAddress, error)
}

// SocketAddressPublisher may derive addresses from the sockets that Router
// actually bound. It is used when a zero bind port delegates port selection to
// the kernel or when a NAT mapper must publish the mapped external endpoint.
type SocketAddressPublisher interface {
	AddressesForSockets(context.Context, net.Listener, net.PacketConn) ([]PublishedAddress, error)
}

// AddressPublisherCloser releases mappings and waits for publisher workers.
type AddressPublisherCloser interface {
	Close() error
}

// LocalInfo owns immutable local RouterInfo snapshots and their publication.
type LocalInfo interface {
	Hash() foundation.Hash
	Snapshot() netdb.RouterInfo
	ReplaceAddresses([]PublishedAddress) error
	SetReachability(Reachability)
	Publish(context.Context) error
}

// Clock centralizes wall-clock conversion for protocol timestamps.
type Clock interface {
	Now() time.Time
}

// WallClock is the standard wall-clock implementation.
type WallClock struct{}

func (WallClock) Now() time.Time { return time.Now() }

// TransportStatus is reported by a TransportManager. Transport-specific state
// belongs to the manager rather than the Router.
type TransportStatus struct {
	Running bool
	Error   error
}

// TransportBindings are the resources a Router gives its transport manager.
// The manager owns session handling; it must not expose native connections as
// purported I2P streams. SSU2 ownership transfers only after Start succeeds.
type TransportBindings struct {
	NTCP2          net.Listener
	SSU2           *net.UDPConn
	LocalInfo      LocalInfo
	HandleI2NP     func(i2np.Message, uint64, bool) error
	HandleI2NPFrom func(foundation.Hash, i2np.Message, uint64, bool) error
	// HandleI2NPContext is the bounded SSU2 dispatch contract. Implementations
	// must return when ctx is canceled and must not retain message.Payload.
	HandleI2NPContext func(context.Context, foundation.Hash, i2np.Message, uint64, bool) error
	Clock             Clock
}

// TransportManager owns peer and session lifecycle around the router-bound
// transport sockets.
type TransportManager interface {
	Start(context.Context, TransportBindings) error
	Close() error
	Wait() error
	Send(context.Context, foundation.Hash, i2np.Message) error
	Status() TransportStatus
}

// StreamBackend provides optional tunnel-backed I2P stream operations.
// Router delegates to this backend; it does not implement streams itself.
type StreamBackend interface {
	DialI2P(context.Context, string) (net.Conn, error)
	ListenI2P(context.Context, string) (net.Listener, error)
}

// ReseedRunner is reserved for router-owned bootstrap work. It intentionally
// mirrors reseed.Client without adding a second admission path to netdb.
type ReseedRunner interface {
	FetchAny(context.Context, []string, *netdb.Database, uint64) (int, error)
}

// Config defines optional native transport bindings and bootstrap reseed
// settings. An empty Endpoint leaves that transport unbound; a partially
// specified endpoint is invalid.
type Config struct {
	NTCP2           Endpoint
	SSU2            Endpoint
	ReseedEndpoints []string
	RequireReseed   bool
}

// TunnelBuildReplyHandler claims destination-scoped creator replies. Short
// inbound replies retain their ShortTunnelBuild type and are distinguished by
// their pending message ID before transit processing.
type TunnelBuildReplyHandler interface {
	HandleInboundReply(i2np.Message) error
	HandleReply(i2np.Message) error
}

// NetDBRequestHandler advances all request domains which may own an admitted
// lookup result.
type NetDBRequestHandler interface {
	HandleDatabaseSearchReply(i2np.DatabaseSearchReplyMessage)
	HandleDatabaseStore(i2np.DatabaseStoreMessage)
}

type Dependencies struct {
	Database  *netdb.Database
	Service   *Service
	LocalInfo LocalInfo
	Transport TransportManager
	Sockets   SocketRuntime
	Addresses AddressPublisher
	Reseed    ReseedRunner
	// ReseedOutcome observes each completed reseed attempt.
	ReseedOutcome func(error)
	Clock         Clock
	StreamBackend StreamBackend
	Destinations  *DestinationManager
	Tunnels       *tunnel.Runtime
	BuildManager  *tunnel.BuildManager
	// ClientBuildReplies dynamically dispatches replies to destination-scoped
	// creator pools; inbound/transit build requests stay with BuildManager.
	ClientBuildReplies TunnelBuildReplyHandler

	// RequestHandler completes coalesced NetDB lookups after store admission
	// and advances every destination-local request domain.
	RequestHandler NetDBRequestHandler
	// LookupResponder owns bounded DatabaseLookup reply work.
	LookupResponder *netdb.LookupResponder
	// DeliveryStatusMux correlates confirmed publication and health tokens.
	DeliveryStatusMux *DeliveryStatusMux
	// TunnelTest handles live tunnel health probes.
	TunnelTest DeliveryStatusHandler
	// RouterDelivery and TunnelDelivery forward authenticated non-local Garlic
	// cloves to their selected production route.
	RouterDelivery func(foundation.Hash, i2np.Message) error
	TunnelDelivery func(foundation.Hash, uint32, i2np.Message) error
	// GarlicReceiver authenticates legacy ElGamal/AES Garlic, one-time ECIES
	// build and DatabaseLookup replies, and destination ratchet Garlic cloves.
	GarlicReceiver *GarlicReceiver
	// DatabaseStoreReply delivers successful store acknowledgements over the
	// caller's selected direct or tunnel reply path.
	DatabaseStoreReply func(foundation.Hash, uint32, i2np.DeliveryStatusMessage) error
}

// Status is a consistent lifecycle snapshot. Error is the first recorded
// non-context lifecycle error and remains available after shutdown.
type Status struct {
	State     State
	Error     error
	Transport TransportStatus
}

// Router owns an embedded transport runtime. Native transport sockets are not
// exposed as I2P streams; an optional StreamBackend provides that surface.
type Router struct {
	cfg  Config
	deps Dependencies

	startMu sync.Mutex
	mu      sync.Mutex
	state   State
	started bool
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	fatal   bool

	closeOnce  sync.Once
	finishOnce sync.Once
	wg         sync.WaitGroup

	listeners        []net.Listener
	ssu2Socket       *net.UDPConn
	transportStarted bool
	reseedMu         sync.Mutex
	reseedRunning    bool
	reseedDone       chan struct{}
	reseedErr        error
	reseedNext       time.Time
	reseedBackoff    time.Duration
}

// New validates and wires an embedded Router. It performs no network I/O.
func New(cfg Config, deps Dependencies) (*Router, error) {
	if deps.Database == nil {
		return nil, errors.New("router: missing database")
	}
	if deps.LocalInfo == nil {
		return nil, errors.New("router: missing local info")
	}
	if deps.Transport == nil {
		return nil, errors.New("router: missing transport manager")
	}
	if deps.Sockets == nil {
		return nil, errors.New("router: missing socket runtime")
	}
	if deps.Addresses == nil {
		return nil, errors.New("router: missing address publisher")
	}
	if deps.Clock == nil {
		return nil, errors.New("router: missing clock")
	}
	if err := validateEndpoint(cfg.NTCP2); err != nil {
		return nil, err
	}
	if err := validateEndpoint(cfg.SSU2); err != nil {
		return nil, err
	}
	if deps.Service != nil && deps.Service.database != deps.Database {
		return nil, errors.New("router: service uses a different database")
	}
	if deps.Service == nil {
		deps.Service = NewService(deps.Database)
	}
	if deps.Destinations != nil && deps.StreamBackend == nil {
		deps.StreamBackend = deps.Destinations
	}
	if deps.Tunnels != nil {
		deps.Tunnels.SetSender(deps.Transport)
		deps.Service.SetTunnelDataSink(deps.Tunnels.Handle)
		deps.Service.SetTunnelGatewaySink(deps.Tunnels.HandleGateway)
	}
	if deps.BuildManager != nil {
		handleReply := func(message i2np.Message) error {
			err := deps.BuildManager.HandleReply(message)
			if !errors.Is(err, tunnel.ErrBuildPending) {
				return err
			}
			if deps.ClientBuildReplies != nil {
				return deps.ClientBuildReplies.HandleReply(message)
			}
			return tunnel.ErrBuildPending
		}
		deps.Service.SetTunnelBuildSink(func(source I2NPSource, _ i2np.BuildRecords, message i2np.Message) error {
			if message.Header.Type == i2np.VariableTunnelBuildReply {
				return handleReply(message)
			}
			if message.Header.Type == i2np.ShortTunnelBuild && deps.ClientBuildReplies != nil {
				err := deps.ClientBuildReplies.HandleInboundReply(message)
				if !errors.Is(err, tunnel.ErrBuildPending) {
					return err
				}
			}
			if source.Direct {
				return deps.BuildManager.HandleBuildFrom(source.Peer, message)
			}
			return deps.BuildManager.HandleBuild(message)
		})
		deps.Service.SetOutboundTunnelBuildReplySink(handleReply)
	}
	if deps.RequestHandler != nil {
		deps.Service.SetDatabaseSearchReplySink(func(reply i2np.DatabaseSearchReplyMessage) error {
			deps.RequestHandler.HandleDatabaseSearchReply(reply)
			return nil
		})
		deps.Service.SetDatabaseStoreCompletedSink(deps.RequestHandler.HandleDatabaseStore)
	}
	if deps.LookupResponder != nil {
		deps.Service.SetDatabaseLookupSink(deps.LookupResponder.Enqueue)
	}
	if deps.DeliveryStatusMux != nil {
		deps.Service.SetDeliveryStatusSink(deps.DeliveryStatusMux.Sink)
	}
	if deps.TunnelTest != nil {
		deps.Service.SetTunnelTestSink(func(status i2np.DeliveryStatusMessage) error {
			deps.TunnelTest.HandleDeliveryStatus(status)
			return nil
		})
	}
	if deps.RouterDelivery != nil {
		deps.Service.SetRouterSink(deps.RouterDelivery)
	}
	if deps.TunnelDelivery != nil {
		deps.Service.SetTunnelSink(deps.TunnelDelivery)
	}
	if deps.GarlicReceiver != nil {
		if deps.GarlicReceiver.service != deps.Service {
			return nil, errors.New("router: Garlic receiver uses a different service")
		}
		deps.Service.SetGarlicSink(deps.GarlicReceiver.HandleGarlicFrom)
		if deps.Destinations != nil {
			deps.Service.SetDestinationSink(func(from, to foundation.Hash, message i2np.Message) error {
				return deps.GarlicReceiver.HandleDestinationData(from, to, message, deps.Destinations)
			})
		}
	}
	return &Router{cfg: cfg, deps: deps, state: StateNew, done: make(chan struct{})}, nil
}

func validateEndpoint(endpoint Endpoint) error {
	if (endpoint.Network == "") != (endpoint.Address == "") {
		return errors.New("router: endpoint requires network and address")
	}
	return nil
}

// Start opens configured sockets, publishes the current local address snapshot,
// and starts the transport manager. A Router is single-start only.
func (r *Router) Start(parent context.Context) error {
	if parent ==
		nil {
		parent = context.Background()
	}

	r.startMu.Lock()
	defer r.startMu.Unlock()

	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return ErrStarted
	}
	r.started = true
	r.state = StateStarting
	r.ctx, r.cancel = context.WithCancel(parent)
	ctx := r.ctx
	r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}
	var ntcpListener net.Listener
	var ssuSocket *net.UDPConn
	var err error
	if r.cfg.NTCP2.Network != "" {
		ntcpListener, err = r.deps.Sockets.ListenStream(ctx, r.cfg.NTCP2)
		if err != nil {
			r.stop(err, false)
			<-r.done
			return err
		}
		r.mu.Lock()
		r.listeners = append(r.listeners, ntcpListener)
		r.mu.Unlock()
	}
	if r.cfg.SSU2.Network != "" {
		ssuSocket, err = r.deps.Sockets.ListenUDP(ctx, r.cfg.SSU2)
		if err != nil {
			r.stop(err, false)
			<-r.done
			return err
		}
		r.mu.Lock()
		r.ssu2Socket = ssuSocket
		r.mu.Unlock()
	}
	var addresses []PublishedAddress
	if publisher, ok := r.deps.Addresses.(SocketAddressPublisher); ok {
		addresses, err = publisher.AddressesForSockets(ctx, ntcpListener, ssuSocket)
	} else {
		addresses, err = r.deps.Addresses.Addresses(ctx)
	}
	if err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}
	if err := r.deps.LocalInfo.ReplaceAddresses(addresses); err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}
	if err := r.deps.LocalInfo.Publish(ctx); err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}

	bindings := TransportBindings{
		LocalInfo:         r.deps.LocalInfo,
		HandleI2NP:        r.deps.Service.HandleI2NP,
		HandleI2NPFrom:    r.deps.Service.HandleI2NPFrom,
		HandleI2NPContext: r.deps.Service.HandleI2NPFromContext,
		Clock:             r.deps.Clock,
	}
	r.mu.Lock()
	if len(r.listeners) != 0 {
		bindings.NTCP2 = r.listeners[0]
	}
	if r.ssu2Socket != nil {
		bindings.SSU2 = r.ssu2Socket
	}
	r.mu.Unlock()
	if r.deps.LookupResponder != nil {
		if err := r.deps.LookupResponder.Start(ctx); err != nil {
			r.stop(err, false)
			<-r.done
			return err
		}
	}

	if err := r.deps.Transport.Start(ctx, bindings); err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}
	// A successful Start transfers SSU2 ownership to the transport.  Keep this
	// flag false while Router still owns the bound socket so rollback cannot
	// close an unstarted transport.
	r.mu.Lock()
	r.transportStarted = true
	r.mu.Unlock()
	// SSU2Manager now exclusively owns the successful UDP binding.
	r.mu.Lock()
	r.ssu2Socket = nil
	r.mu.Unlock()
	reseedDone := r.startReseed(ctx)
	if r.cfg.RequireReseed && reseedDone != nil {
		<-reseedDone
		if err := r.reseedResult(); err != nil {
			r.stop(err, false)
			<-r.done
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		r.stop(err, false)
		<-r.done
		return err
	}

	r.wg.Add(2)
	r.mu.Lock()
	r.state = StateRunning
	r.mu.Unlock()
	go r.watchTransport(ctx)
	go r.watchContext(ctx)
	return nil
}

// MaintainReseed starts a bounded asynchronous bootstrap attempt when the
// routing table is below the minimum useful peer population. Concurrent startup
// and maintenance calls share one attempt and failed attempts are backed off.
func (r *Router) MaintainReseed(ctx context.Context) {
	r.startReseed(ctx)
}

type usableReseedPeerCounter interface {
	UsableRemoteRouterInfos(time.Time) int
}

func (r *Router) usableReseedPeers(now time.Time) int {
	if counter, ok := r.deps.Transport.(usableReseedPeerCounter); ok {
		return counter.UsableRemoteRouterInfos(now)
	}
	// A custom transport that does not expose verified address capability is
	// conservatively counted as zero. Retained-table size is never a substitute
	// for proof that a remote peer is transport-usable.
	return 0
}

func (r *Router) startReseed(ctx context.Context) <-chan struct{} {
	if len(r.cfg.ReseedEndpoints) == 0 || r.deps.Reseed == nil {
		return nil
	}
	now := r.deps.Clock.Now()
	if r.usableReseedPeers(now) >= reseedBootstrapMinimum {
		return nil
	}
	r.reseedMu.Lock()
	if r.reseedRunning {
		done := r.reseedDone
		r.reseedMu.Unlock()
		return done
	}
	if now.Before(r.reseedNext) {
		r.reseedMu.Unlock()
		return nil
	}
	done := make(chan struct{})
	r.reseedRunning = true
	r.reseedDone = done
	r.reseedErr = nil
	r.reseedMu.Unlock()

	r.wg.Go(func() {
		_, err := r.deps.Reseed.FetchAny(ctx, r.cfg.ReseedEndpoints, r.deps.Database, uint64(now.UnixMilli()))
		if r.deps.ReseedOutcome != nil {
			r.deps.ReseedOutcome(err)
		}

		r.reseedMu.Lock()
		r.reseedErr = err
		r.reseedRunning = false
		if err == nil {
			r.reseedBackoff = 0
			r.reseedNext = time.Time{}
		} else {
			if r.reseedBackoff == 0 {
				r.reseedBackoff = reseedInitialBackoff
			} else {
				r.reseedBackoff = min(reseedMaximumBackoff, r.reseedBackoff*2)
			}
			r.reseedNext = r.deps.Clock.Now().Add(r.reseedBackoff)
		}
		close(done)
		r.reseedMu.Unlock()
	})
	return done
}

func (r *Router) reseedResult() error {
	r.reseedMu.Lock()
	defer r.reseedMu.Unlock()
	return r.reseedErr
}

// Close begins shutdown exactly once. Socket resources close before the
// transport manager, cancellation, and worker wait so native blocking calls
// are unblocked deterministically.
func (r *Router) Close() error {
	r.startMu.Lock()
	r.stop(nil, false)
	r.startMu.Unlock()
	return r.Wait()
}

// Wait blocks until all router-owned work has stopped and returns the first
// terminal non-context error.
func (r *Router) Wait() error {
	r.mu.Lock()
	if r.state == StateNew {
		r.mu.Unlock()
		return nil
	}
	done := r.done
	r.mu.Unlock()
	<-done
	r.mu.Lock()
	err := r.err
	r.mu.Unlock()
	return err
}

// Context returns the lifecycle context, or Background before Start.
func (r *Router) Context() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

func (r *Router) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state == StateRunning
}

func (r *Router) Status() Status {
	r.mu.Lock()
	status := Status{State: r.state, Error: r.err}
	r.mu.Unlock()
	status.Transport = r.deps.Transport.Status()
	return status
}

// DialI2P dials through the configured stream backend while the Router runs.
func (r *Router) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	r.mu.Lock()
	backend := r.deps.StreamBackend
	running := r.state == StateRunning
	r.mu.Unlock()
	if !running || backend == nil {
		return nil, ErrStreamUnavailable
	}
	return backend.DialI2P(ctx, address)
}

// ListenI2P listens through the configured stream backend while the Router runs.
func (r *Router) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	r.mu.Lock()
	backend := r.deps.StreamBackend
	running := r.state == StateRunning
	r.mu.Unlock()
	if !running || backend == nil {
		return nil, ErrStreamUnavailable
	}
	return backend.ListenI2P(ctx, address)
}

func (r *Router) watchContext(ctx context.Context) {
	defer r.wg.Done()
	<-ctx.Done()
	r.stop(ctx.Err(), false)
}

func (r *Router) watchTransport(ctx context.Context) {
	defer r.wg.Done()
	err := r.deps.Transport.Wait()
	if ctx.Err() != nil {
		return
	}

	if err == nil {
		err = ErrTransportStopped

	}
	r.stop(err, true)
}

func (r *Router) stop(cause error, fatal bool) {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		if r.state != StateFailed {
			r.state = StateStopping
		}
		if fatal {
			r.fatal = true
		}
		r.recordErrorLocked(cause)
		listeners := r.listeners
		ssu2Socket := r.ssu2Socket
		transportStarted := r.transportStarted
		destinations := r.deps.Destinations
		cancel := r.cancel
		r.mu.Unlock()

		if r.deps.LookupResponder != nil {
			r.recordCloseError(r.deps.LookupResponder.Close())
		}
		if destinations != nil {
			r.recordCloseError(destinations.Close())
		}
		for _, listener := range listeners {
			r.recordCloseError(listener.Close())
		}
		// Before Transport.Start succeeds Router owns the UDP socket; afterward
		// SSU2Manager closes it while draining its vector I/O workers.
		if ssu2Socket != nil {
			r.recordCloseError(ssu2Socket.Close())
		}
		if transportStarted {
			r.recordCloseError(r.deps.Transport.Close())
		}
		if cancel != nil {
			cancel()
		}
		if publisher, ok := r.deps.Addresses.(AddressPublisherCloser); ok {
			r.recordCloseError(publisher.Close())
		}
		r.finishOnce.Do(func() { go r.finish() })
	})
}

func (r *Router) finish() {
	r.wg.Wait()
	r.mu.Lock()
	if r.fatal {
		r.state = StateFailed
	} else {
		r.state = StateStopped
	}
	close(r.done)
	r.mu.Unlock()
}

func (r *Router) recordCloseError(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	r.mu.Lock()
	r.recordErrorLocked(err)
	r.mu.Unlock()
}

func (r *Router) recordErrorLocked(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || r.err != nil {
		return
	}
	r.err = err
}
