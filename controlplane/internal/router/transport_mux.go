package router

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	controlplanetunnel "gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

var (
	// ErrTransportMuxConfig reports a mux without the verified netdb needed to
	// select a peer transport, or without either supported transport manager.
	ErrTransportMuxConfig = errors.New("router: invalid transport mux configuration")
	// ErrTransportUnavailable reports a verified peer without an address usable
	// by one of the configured transports.
	ErrTransportUnavailable           = errors.New("router: supported transport unavailable for peer")
	errTransportSessionAttemptTimeout = errors.New("router: transport session attempt timed out")
)

type preferredSessionManager interface {
	dataplane.RouterTransportManager
	controlplanetunnel.SessionEnsurer
	HasSession(foundation.Hash) bool
	DropSession(foundation.Hash) bool
}

type activeSessionCounter interface {
	ActiveSessionCount() int
}

const (
	minimumSSU2IPv4Peers           = 10
	minimumSSU2IPv6Peers           = 30
	minimumIntroducers             = 5
	transportSessionAttemptTimeout = 10 * time.Second
)

type transportCapabilities struct {
	ntcp2          dataplane.RouterTransportManager
	ssu2           dataplane.RouterTransportManager
	directSSU2     bool
	ssu2IPv6       bool
	ssu2Introducer bool
}

// TransportMuxConfig supplies control-plane peer selection and owned transports.
type TransportMuxConfig struct {
	Database *controlplanenetdb.Database
	NTCP2    dataplane.RouterTransportManager
	SSU2     dataplane.RouterTransportManager
	Metrics  *observability.Registry
}

// TransportMux reuses an authenticated session before opening another
// transport. For an unestablished direct peer, Java-compatible transport bids
// select one handshake; an alternate is attempted only after a retryable
// pre-delivery failure.
type TransportMux struct {
	database *controlplanenetdb.Database
	ntcp2    dataplane.RouterTransportManager
	ssu2     dataplane.RouterTransportManager
	metrics  *observability.Registry

	lifecycleMu  sync.Mutex
	started      bool
	closed       bool
	managers     [2]dataplane.RouterTransportManager
	managerCount int
	closeOnce    sync.Once
	closeErr     error
	random       io.Reader
	setupSlots   chan struct{}
	dataSender   *dataplane.RouterEstablishedSender
}

var _ dataplane.RouterTransportManager = (*TransportMux)(nil)
var _ dataplane.TunnelSender = (*TransportMux)(nil)

// NewTransportMux constructs a direct-peer transport mux without starting its
// child managers.
func NewTransportMux(config TransportMuxConfig) (*TransportMux, error) {
	if config.Database == nil || (config.NTCP2 == nil && config.SSU2 == nil) {
		return nil, ErrTransportMuxConfig
	}
	providers := make([]dataplane.RouterEstablishedSessionRegistry, 0, 2)
	for _, manager := range []dataplane.RouterTransportManager{config.NTCP2, config.SSU2} {
		if provider, ok := manager.(dataplane.RouterEstablishedSessionRegistry); ok {
			providers = append(providers, provider)
		}
	}
	return &TransportMux{
		database:   config.Database,
		ntcp2:      config.NTCP2,
		ssu2:       config.SSU2,
		metrics:    config.Metrics,
		random:     rand.Reader,
		setupSlots: make(chan struct{}, 64),
		dataSender: dataplane.RouterNewEstablishedSender(providers...),
	}, nil
}

func (m *TransportMux) DataSender() *dataplane.RouterEstablishedSender { return m.dataSender }

// Start starts every configured transport with the router-owned bindings. If a
// later manager cannot start, already-started managers are closed before the
// combined start and cleanup errors are returned.
func (m *TransportMux) Start(ctx context.Context, bindings dataplane.RouterTransportBindings) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.started {
		return dataplane.RouterErrStarted
	}
	if m.closed {
		return ErrTransportStopped
	}
	m.started = true

	for _, manager := range m.configuredManagers() {
		if manager == nil {
			continue
		}
		if err := manager.Start(ctx, bindings); err != nil {
			m.closed = true
			return errors.Join(err, m.closeManagersLocked())
		}
		m.managers[m.managerCount] = manager
		m.managerCount++
	}
	return nil
}

// Close closes every successfully started child once and combines independent
// close failures. It is safe before Start and during Router shutdown.
func (m *TransportMux) Close() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.closed = true
	return m.closeManagersLocked()
}

func (m *TransportMux) closeManagersLocked() error {
	m.closeOnce.Do(func() {
		errs := make([]error, 0, m.managerCount)
		for index := range m.managerCount {
			manager := m.managers[index]
			if err := manager.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		m.closeErr = errors.Join(errs...)
	})
	return m.closeErr
}

// Wait waits for every successfully started child and coalesces their terminal
// errors with any error reported while closing them.
func (m *TransportMux) Wait() error {
	m.lifecycleMu.Lock()
	managers := m.managers
	managerCount := m.managerCount
	closeErr := m.closeErr
	m.lifecycleMu.Unlock()

	if managerCount == 0 {
		return closeErr
	}

	errs := make([]error, 0, managerCount+1)
	if closeErr != nil {
		errs = append(errs, closeErr)
	}
	results := make(chan error, managerCount)
	for _, manager := range managers[:managerCount] {
		go func(manager dataplane.RouterTransportManager) { results <- manager.Wait() }(manager)
	}
	for range managerCount {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Status combines child state without requiring both transports to be usable.
// A running child keeps the mux usable; child and mux lifecycle errors remain
// available together.
func (m *TransportMux) Status() dataplane.RouterTransportStatus {
	m.lifecycleMu.Lock()
	closed := m.closed
	closeErr := m.closeErr
	managers := m.configuredManagers()
	m.lifecycleMu.Unlock()

	errs := make([]error, 0, len(managers)+1)
	if closeErr != nil {
		errs = append(errs, closeErr)
	}
	status := dataplane.RouterTransportStatus{}
	for _, manager := range managers {
		if manager == nil {
			continue
		}
		child := manager.Status()
		status.Running = status.Running || child.Running
		if child.Error != nil {
			errs = append(errs, child.Error)
		}
	}
	if closed {
		status.Running = false
	}
	status.Error = errors.Join(errs...)
	return status
}

// Send uses the prepared handle's cancellation contract through serialized I/O.
// A write attempt is terminal for this message, including cancellation.
func (m *TransportMux) Send(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	sender, err := m.PrepareSession(ctx, peer)
	if err != nil {
		return err
	}
	return sender.Send(ctx, message)
}

// EnsureSession authenticates one selected public transport without sending an
// I2NP message.
func (m *TransportMux) EnsureSession(ctx context.Context, peer foundation.Hash) error {
	_, err := m.PrepareSession(ctx, peer)
	return err
}

// PrepareSession performs bounded setup and returns a borrowed delivery handle.
// Retry ends before the first write; the handle never reselects a transport.
func (m *TransportMux) PrepareSession(ctx context.Context, peer foundation.Hash) (dataplane.RouterSessionSender, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if manager, handled, err := m.sessionManager(ctx, peer); handled {
		if err != nil {
			return nil, err
		}
		return m.prepareTransportSession(manager, peer)
	}
	select {
	case m.setupSlots <- struct{}{}:
		defer func() { <-m.setupSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	primary, alternate, ok := m.selectManagers(peer)
	if !ok {
		return nil, ErrTransportUnavailable
	}
	attempts := 1
	if alternate != nil {
		attempts++
	}
	err := ensureTransportSession(ctx, primary, peer, attempts)
	if err == nil {
		return m.prepareTransportSession(primary, peer)
	}
	retryable := IsRetryableTransportError(err) || errors.Is(err, errTransportSessionAttemptTimeout)
	if alternate == nil || !retryable || ctx.Err() != nil {
		return nil, err
	}
	if alternateErr := ensureTransportSession(ctx, alternate, peer, 1); alternateErr != nil {
		return nil, errors.Join(err, alternateErr)
	}
	return m.prepareTransportSession(alternate, peer)
}

func (m *TransportMux) prepareTransportSession(manager dataplane.RouterTransportManager, peer foundation.Hash) (dataplane.RouterSessionSender, error) {
	provider, ok := manager.(dataplane.RouterSessionProvider)
	if !ok {
		return nil, dataplane.RouterErrSessionUnavailable
	}
	return provider.PreparedSession(peer)
}

func ensureTransportSession(ctx context.Context, manager dataplane.RouterTransportManager, peer foundation.Hash, attempts int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ensurer, ok := manager.(controlplanetunnel.SessionEnsurer)
	if !ok {
		return dataplane.RouterErrSessionUnavailable
	}
	timeout := transportSessionAttemptTimeout
	if deadline, ok := ctx.Deadline(); ok {
		// Keep an equal share of the remaining caller budget for the alternate.
		timeout = min(timeout, time.Until(deadline)/time.Duration(attempts))
	}
	attemptCtx, cancel := context.WithTimeoutCause(ctx, timeout, errTransportSessionAttemptTimeout)
	defer cancel()
	err := ensurer.EnsureSession(attemptCtx, peer)
	if parentErr := ctx.Err(); parentErr != nil {
		return parentErr
	}
	if errors.Is(err, context.DeadlineExceeded) && errors.Is(context.Cause(attemptCtx), errTransportSessionAttemptTimeout) {
		return errors.Join(err, errTransportSessionAttemptTimeout)
	}
	return err
}

func (m *TransportMux) sessionManager(_ context.Context, peer foundation.Hash) (dataplane.RouterTransportManager, bool, error) {
	ntcp2, ntcp2OK := m.ntcp2.(preferredSessionManager)
	ssu2, ssu2OK := m.ssu2.(preferredSessionManager)
	ntcp2Live := ntcp2OK && ntcp2.HasSession(peer)
	ssu2Live := ssu2OK && ssu2.HasSession(peer)
	if !ntcp2Live && !ssu2Live {
		return nil, false, nil
	}
	if m.metrics != nil {
		m.metrics.IncTransportSessionReuses()
	}
	if ntcp2Live {
		return ntcp2, true, nil
	}
	if m.metrics != nil {
		m.metrics.IncTransportSSU2Promotions()
	}
	return ssu2, true, nil
}

func (m *TransportMux) preferSSU2(capabilities transportCapabilities) bool {
	counter, ok := capabilities.ssu2.(activeSessionCounter)
	if !ok || !capabilities.directSSU2 {
		return false
	}
	minimum := minimumSSU2IPv4Peers
	if capabilities.ssu2IPv6 {
		minimum = minimumSSU2IPv6Peers
	}
	prefer := counter.ActiveSessionCount() < minimum
	if !prefer && capabilities.ssu2Introducer {
		if manager, concrete := capabilities.ssu2.(*dataplane.RouterSSU2Manager); concrete {
			required, count := manager.IntroducerStatus(capabilities.ssu2IPv6)
			prefer = required && count < minimumIntroducers
		}
	}
	if !prefer {
		return false
	}
	var choice [1]byte
	if _, err := io.ReadFull(m.random, choice[:]); err != nil {
		return false
	}
	return choice[0]&3 != 0
}

func (m *TransportMux) configuredManagers() [2]dataplane.RouterTransportManager {
	return [2]dataplane.RouterTransportManager{m.ssu2, m.ntcp2}
}

// UsableRemoteRouterInfos counts peers whose verified transport address can be
// used to bootstrap a live session. Reseed RouterInfos remain dialable for the
// bounded 24-hour reseed window so a cold router can fetch 90-minute-fresh
// replacements instead of deadlocking with a populated but unusable NetDB.
func (m *TransportMux) UsableRemoteRouterInfos(now time.Time) int {
	if m == nil || m.database == nil {
		return 0
	}
	nowMillis := uint64(now.UnixMilli())
	nowSeconds := uint64(now.Unix())
	_, peers := m.database.Routers().Snapshot()
	count := 0
	for _, peer := range peers {
		if controlplanenetdb.ReseedRouterInfoFresh(peer.Info, nowMillis) != nil {
			continue
		}
		if m.ntcp2 != nil && dataplane.RouterNTCP2PeerCapable(peer.Info, nowMillis) {
			count++
			continue
		}
		if m.ssu2 != nil && dataplane.RouterSSU2PeerCapable(peer.Info, nowSeconds) {
			count++
		}
	}
	return count
}

// HasSession reports whether any child transport has an authenticated session.
func (m *TransportMux) HasSession(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	for _, manager := range m.configuredManagers() {
		if sessions, ok := manager.(interface{ HasSession(foundation.Hash) bool }); ok && sessions.HasSession(peer) {
			return true
		}
	}
	return false
}

// CanSend reports whether the current verified RouterInfo has an address usable
// by one of this mux's configured transports.
func (m *TransportMux) CanSend(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	_, _, ok := m.selectManagers(peer)
	return ok
}

// CanBuildTunnel reports whether a peer has any directly reachable configured
// transport. Introducer-only SSU2 remains valid only for ordinary delivery.
func (m *TransportMux) CanBuildTunnel(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return false
	}
	now := time.Now()
	nowMillis := uint64(now.UnixMilli())
	ntcp2OK := m.ntcp2 != nil && dataplane.RouterNTCP2PeerCapable(ref.Info, nowMillis)
	if ntcp2OK {
		if manager, concrete := m.ntcp2.(*dataplane.RouterNTCP2Manager); concrete {
			ntcp2OK = manager.PeerReachable(ref.Info)
		}
	}
	ssu2OK := m.ssu2 != nil && m.directSSU2RouterInfoCapable(ref.Info, uint64(now.Unix()))
	return ntcp2OK || ssu2OK
}

func (m *TransportMux) selectManagers(peer foundation.Hash) (dataplane.RouterTransportManager, dataplane.RouterTransportManager, bool) {
	capabilities, ok := m.capabilities(peer)
	if !ok {
		return nil, nil, false
	}
	switch {
	case capabilities.ssu2 != nil && capabilities.ntcp2 != nil:
		if m.preferSSU2(capabilities) {
			return capabilities.ssu2, capabilities.ntcp2, true
		}
		return capabilities.ntcp2, capabilities.ssu2, true
	case capabilities.ssu2 != nil:
		return capabilities.ssu2, nil, true
	case capabilities.ntcp2 != nil:
		return capabilities.ntcp2, nil, true
	default:
		return nil, nil, false
	}
}

func (m *TransportMux) capabilities(peer foundation.Hash) (transportCapabilities, bool) {
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return transportCapabilities{}, false
	}
	now := time.Now()
	nowMillis := uint64(now.UnixMilli())
	if err := controlplanenetdb.ReseedRouterInfoFresh(ref.Info, nowMillis); err != nil {
		return transportCapabilities{}, false
	}
	var capabilities transportCapabilities
	if m.ntcp2 != nil && dataplane.RouterNTCP2PeerCapable(ref.Info, nowMillis) {
		capabilities.ntcp2 = m.ntcp2
	}
	if m.ssu2 != nil && dataplane.RouterSSU2PeerCapable(ref.Info, uint64(now.Unix())) {
		capabilities.ssu2 = m.ssu2
		inspection := dataplane.RouterInspectSSU2Peer(ref.Info, uint64(now.Unix()))
		if manager, concrete := m.ssu2.(*dataplane.RouterSSU2Manager); concrete {
			inspection = manager.InspectPeer(ref.Info, uint64(now.Unix()))
		}
		capabilities.directSSU2 = inspection.Direct
		capabilities.ssu2IPv6 = inspection.IPv6
		capabilities.ssu2Introducer = inspection.Introducer
	}
	return capabilities, capabilities.ntcp2 != nil || capabilities.ssu2 != nil
}

func (m *TransportMux) directSSU2RouterInfoCapable(info foundation.NetworkDatabaseRouterInfo, now uint64) bool {
	manager, concrete := m.ssu2.(*dataplane.RouterSSU2Manager)
	if !concrete {
		return dataplane.RouterSSU2DirectPeerCapable(info, now)
	}
	return manager.InspectPeer(info, now).Direct
}

// IsRetryableTransportError reports failures that occurred before an I2NP
// message could be delivered and are expected while selecting live peers.
func IsRetryableTransportError(err error) bool {
	unavailable := errors.Is(err, ErrTransportUnavailable) || errors.Is(err, dataplane.RouterErrSessionUnavailable)
	ntcpSetupFailure := errors.Is(err, dataplane.RouterErrNTCP2Peer) || errors.Is(err, dataplane.RouterErrNTCP2Session)
	ssuSetupFailure := errors.Is(err, dataplane.RouterErrSSU2Peer) || errors.Is(err, dataplane.RouterErrSSU2Session) || errors.Is(err, dataplane.RouterErrSSU2Introduction)
	if unavailable || ntcpSetupFailure || ssuSetupFailure {
		return true
	}
	var operation *net.OpError
	return errors.As(err, &operation) && operation.Op == "dial"
}
