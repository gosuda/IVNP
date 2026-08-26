package router

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/tunnel"
	"gosuda.org/ivnp/observability"
)

var (
	// ErrTransportMuxConfig reports a mux without the verified netdb needed to
	// select a peer transport, or without either supported transport manager.
	ErrTransportMuxConfig = errors.New("router: invalid transport mux configuration")
	// ErrTransportUnavailable reports a verified peer without an address usable
	// by one of the configured transports.
	ErrTransportUnavailable = errors.New("router: supported transport unavailable for peer")
)

const (
	transportBootstrapDialGrace = 750 * time.Millisecond
	transportReadyDialGrace     = 2 * time.Second
)

type preferredSessionManager interface {
	TransportManager
	tunnel.SessionEnsurer
	HasSession(foundation.Hash) bool
	DropSession(foundation.Hash) bool
}

type transportCapabilities struct {
	ntcp2      TransportManager
	ssu2       TransportManager
	directSSU2 bool
}

// TransportMuxConfig composes the direct-peer NTCP2 and SSU2 managers behind
// Router's single TransportManager dependency. Database is consulted on every
// Send so transport selection is based only on a RouterInfo admitted by netdb.
// Either manager may be nil, but not both.
type TransportMuxConfig struct {
	Database   *netdb.Database
	NTCP2      TransportManager
	SSU2       TransportManager
	PreferSSU2 func() bool
	Metrics    *observability.Registry
}

// TransportMux reuses an authenticated session before opening another
// transport. For a peer with direct NTCP2 and SSU2 addresses, it races both
// handshakes and retains SSU2 when both succeed. Introducer-only SSU2 remains a
// fallback because its relay setup is materially slower than a direct dial.
type TransportMux struct {
	database   *netdb.Database
	ntcp2      TransportManager
	ssu2       TransportManager
	preferSSU2 func() bool
	metrics    *observability.Registry

	lifecycleMu  sync.Mutex
	started      bool
	closed       bool
	managers     [2]TransportManager
	managerCount int
	closeOnce    sync.Once
	closeErr     error
}

var _ TransportManager = (*TransportMux)(nil)
var _ tunnel.Sender = (*TransportMux)(nil)

// NewTransportMux constructs a direct-peer transport mux without starting its
// child managers.
func NewTransportMux(config TransportMuxConfig) (*TransportMux, error) {
	if config.Database == nil || (config.NTCP2 == nil && config.SSU2 == nil) {
		return nil, ErrTransportMuxConfig
	}
	return &TransportMux{
		database:   config.Database,
		ntcp2:      config.NTCP2,
		ssu2:       config.SSU2,
		preferSSU2: config.PreferSSU2,
		metrics:    config.Metrics,
	}, nil
}

// Start starts every configured transport with the router-owned bindings. If a
// later manager cannot start, already-started managers are closed before the
// combined start and cleanup errors are returned.
func (m *TransportMux) Start(ctx context.Context, bindings TransportBindings) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.started {
		return ErrStarted
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
		go func(manager TransportManager) { results <- manager.Wait() }(manager)
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
func (m *TransportMux) Status() TransportStatus {
	m.lifecycleMu.Lock()
	closed := m.closed
	closeErr := m.closeErr
	managers := m.configuredManagers()
	m.lifecycleMu.Unlock()

	errs := make([]error, 0, len(managers)+1)
	if closeErr != nil {
		errs = append(errs, closeErr)
	}
	status := TransportStatus{}
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

// Send establishes at most one delivery path before writing the borrowed
// message. A raced alternate is never used after a write attempt.
func (m *TransportMux) Send(ctx context.Context, peer foundation.Hash, message i2np.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if manager, handled, err := m.sessionManager(ctx, peer); handled {
		if err != nil {
			return err
		}
		return manager.Send(ctx, peer, message)
	}
	primary, alternate, ok := m.selectManagers(peer)
	if !ok {
		return ErrTransportUnavailable
	}
	if err := primary.Send(ctx, peer, message); err != nil {
		if alternate == nil || !IsRetryableTransportError(err) || ctx.Err() != nil {
			return err
		}
		if alternateErr := alternate.Send(ctx, peer, message); alternateErr != nil {
			return errors.Join(err, alternateErr)
		}
	}
	return nil
}

// EnsureSession authenticates one selected public transport without sending an
// I2NP message.
func (m *TransportMux) EnsureSession(ctx context.Context, peer foundation.Hash) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, handled, err := m.sessionManager(ctx, peer); handled {
		return err
	}
	primary, alternate, ok := m.selectManagers(peer)
	if !ok {
		return ErrTransportUnavailable
	}
	err := ensureTransportSession(ctx, primary, peer)
	if err == nil {
		return nil
	}
	if alternate == nil || !IsRetryableTransportError(err) || ctx.Err() != nil {
		return err
	}
	if alternateErr := ensureTransportSession(ctx, alternate, peer); alternateErr != nil {
		return errors.Join(err, alternateErr)
	}
	return nil
}

func ensureTransportSession(ctx context.Context, manager TransportManager, peer foundation.Hash) error {
	ensurer, ok := manager.(tunnel.SessionEnsurer)
	if !ok {
		return nil
	}
	return ensurer.EnsureSession(ctx, peer)
}

func (m *TransportMux) sessionManager(ctx context.Context, peer foundation.Hash) (TransportManager, bool, error) {
	capabilities, ok := m.capabilities(peer)
	if !ok || capabilities.ntcp2 == nil || capabilities.ssu2 == nil || !capabilities.directSSU2 {
		return nil, false, nil
	}
	ntcp2, ntcp2OK := capabilities.ntcp2.(preferredSessionManager)
	ssu2, ssu2OK := capabilities.ssu2.(preferredSessionManager)
	if !ntcp2OK || !ssu2OK {
		return nil, false, nil
	}
	if ssu2.HasSession(peer) {
		if m.metrics != nil {
			m.metrics.IncTransportSessionReuses()
			m.metrics.IncTransportSSU2Promotions()
		}
		ntcp2.DropSession(peer)
		return ssu2, true, nil
	}
	if ntcp2.HasSession(peer) {
		if m.metrics != nil {
			m.metrics.IncTransportSessionReuses()
		}
		return ntcp2, true, nil
	}
	manager, err := m.raceDirectSessions(ctx, peer, ntcp2, ssu2)
	return manager, true, err
}

func (m *TransportMux) raceDirectSessions(ctx context.Context, peer foundation.Hash, ntcp2, ssu2 preferredSessionManager) (TransportManager, error) {
	type result struct {
		manager preferredSessionManager
		err     error
	}
	raceContext, cancel := context.WithCancel(ctx)
	defer cancel()
	if m.metrics != nil {
		m.metrics.IncTransportRaceAttempts()
	}
	results := make(chan result, 2)
	go func() { results <- result{manager: ntcp2, err: ntcp2.EnsureSession(raceContext, peer)} }()
	go func() { results <- result{manager: ssu2, err: ssu2.EnsureSession(raceContext, peer)} }()

	first := <-results
	if first.err != nil {
		second := <-results
		if second.err != nil {
			return nil, errors.Join(first.err, second.err)
		}
		if second.manager == ssu2 {
			ntcp2.DropSession(peer)
			m.recordSSU2RaceWin()
		} else if m.metrics != nil {
			m.metrics.IncTransportNTCP2RaceWins()
		}
		return second.manager, nil
	}
	if first.manager == ssu2 {
		cancel()
		second := <-results
		if second.err == nil {
			ntcp2.DropSession(peer)
		}
		m.recordSSU2RaceWin()
		return ssu2, nil
	}

	grace := m.dialGrace()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case second := <-results:
		if second.err == nil && second.manager == ssu2 {
			ntcp2.DropSession(peer)
			m.recordSSU2RaceWin()
			return ssu2, nil
		}
		if m.metrics != nil {
			m.metrics.IncTransportNTCP2RaceWins()
		}
		return ntcp2, nil
	case <-timer.C:
		cancel()
		if m.metrics != nil {
			m.metrics.IncTransportNTCP2RaceWins()
		}
		return ntcp2, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *TransportMux) dialGrace() time.Duration {
	if m.preferSSU2 != nil && m.preferSSU2() {
		return transportReadyDialGrace
	}
	return transportBootstrapDialGrace
}

func (m *TransportMux) recordSSU2RaceWin() {
	if m.metrics != nil {
		m.metrics.IncTransportSSU2RaceWins()
		m.metrics.IncTransportSSU2Promotions()
	}
}

func (m *TransportMux) configuredManagers() [2]TransportManager {
	return [2]TransportManager{m.ssu2, m.ntcp2}
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
		if netdb.ReseedRouterInfoFresh(peer.Info, nowMillis) != nil {
			continue
		}
		if m.ntcp2 != nil && ntcp2RouterInfoCapable(peer.Info, nowMillis) {
			count++
			continue
		}
		if m.ssu2 != nil && ssu2RouterInfoCapable(peer.Info, nowSeconds) {
			count++
		}
	}
	return count
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

// CanBuildTunnel reports whether the peer has a directly reachable address
// suitable for latency-bounded tunnel construction. When NTCP2 is configured,
// its reliable stream path is required; SSU2 is the direct-only fallback for
// SSU2-only nodes. Introducer-only SSU2 remains valid for ordinary delivery.
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
	if m.ntcp2 != nil {
		if !ntcp2RouterInfoCapable(ref.Info, nowMillis) {
			return false
		}
		manager, concrete := m.ntcp2.(*NTCP2Manager)
		if !concrete {
			return true
		}
		_, err := selectNTCP2AddressForNetwork(ref.Info, ntcp2IPv4Only(manager.currentBindings().NTCP2))
		return err == nil
	}
	return m.ssu2 != nil && ssu2DirectRouterInfoCapable(ref.Info, uint64(now.Unix()))
}

func (m *TransportMux) selectManagers(peer foundation.Hash) (TransportManager, TransportManager, bool) {
	capabilities, ok := m.capabilities(peer)
	if !ok {
		return nil, nil, false
	}
	switch {
	case capabilities.ssu2 != nil && capabilities.ntcp2 != nil:
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
	if err := netdb.ReseedRouterInfoFresh(ref.Info, nowMillis); err != nil {
		return transportCapabilities{}, false
	}
	var capabilities transportCapabilities
	if m.ntcp2 != nil && ntcp2RouterInfoCapable(ref.Info, nowMillis) {
		capabilities.ntcp2 = m.ntcp2
	}
	if m.ssu2 != nil && ssu2RouterInfoCapable(ref.Info, uint64(now.Unix())) {
		capabilities.ssu2 = m.ssu2
		capabilities.directSSU2 = ssu2DirectRouterInfoCapable(ref.Info, uint64(now.Unix()))
	}
	return capabilities, capabilities.ntcp2 != nil || capabilities.ssu2 != nil
}

func ntcp2RouterInfoCapable(info netdb.RouterInfo, nowMillis uint64) bool {
	if _, err := selectNTCP2Address(info); err != nil {
		return false
	}
	return hasCurrentTransportAddress(info, nowMillis, []byte("NTCP"), []byte("NTCP2"))
}

func ssu2DirectRouterInfoCapable(info netdb.RouterInfo, now uint64) bool {
	if _, err := selectSSU2Keys(info); err != nil {
		return false
	}
	_, err := selectSSU2Address(info)
	return err == nil && hasCurrentTransportAddress(info, now*1000, []byte("SSU"), []byte("SSU2"))
}

func ssu2RouterInfoCapable(info netdb.RouterInfo, now uint64) bool {
	if ssu2DirectRouterInfoCapable(info, now) {
		return true
	}
	if _, err := selectSSU2Keys(info); err != nil {
		return false
	}
	return len(selectSSU2Introducers(info, now)) != 0
}

func hasCurrentTransportAddress(info netdb.RouterInfo, nowMillis uint64, first, second []byte) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		if !bytes.Equal(address.TransportStyle, first) && !bytes.Equal(address.TransportStyle, second) {
			continue
		}
		if address.Expiration == 0 || address.Expiration > nowMillis {
			return true
		}
	}
}

// IsRetryableTransportError reports failures that occurred before an I2NP
// message could be delivered and are expected while selecting live peers.
func IsRetryableTransportError(err error) bool {
	isRetryableTransportErrorRejected := errors.Is(err, ErrTransportUnavailable) ||
		errors.Is(err, ErrNTCP2Peer) || errors.Is(err, ErrNTCP2Session) ||
		errors.Is(err, ErrSSU2Peer) || errors.Is(err, ErrSSU2Session)
	if !isRetryableTransportErrorRejected {
		isRetryableTransportErrorRejected = errors.Is(err, ErrSSU2Introduction)
	}
	if isRetryableTransportErrorRejected { // A failed TCP dial cannot have written the I2NP message. Do not classify
		// generic network errors as retryable: they may come from a session write.

		return true
	}

	var operation *net.OpError
	return errors.As(err, &operation) && operation.Op == "dial"
}

func routerHashDiagnostic(hash foundation.Hash) string {
	return foundation.EncodeI2PBase64(hash[:])
}
