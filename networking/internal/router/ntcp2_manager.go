package router

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/transport/ntcp2"
	"gosuda.org/ivnp/observability"
)

const (
	defaultNTCP2NetworkID        = 2
	defaultNTCP2HandshakeTimeout = 30 * time.Second
	defaultNTCP2MaxSessions      = 256
	defaultNTCP2MaxPending       = 64
	defaultNTCP2MaxClockSkew     = 2 * time.Minute
	ntcp2ReplayEntries           = 4096
)

var (
	ErrNTCP2ManagerConfig = errors.New("router: invalid NTCP2 manager configuration")
	ErrNTCP2Peer          = errors.New("router: invalid NTCP2 peer RouterInfo")
	ErrNTCP2Session       = errors.New("router: NTCP2 session unavailable")
)

// NTCP2ManagerConfig contains the persisted NTCP2 static key and IV that are
// advertised in the local RouterInfo. StaticPrivate and StaticIV are copied at
// construction; callers must republish matching `s`, `i`, and `v=2` address
// options before starting the manager.
type NTCP2ManagerConfig struct {
	Database         *netdb.Database
	StaticPrivate    []byte
	StaticIV         []byte
	NetworkID        uint8
	HandshakeTimeout time.Duration
	MaxClockSkew     time.Duration
	MaxSessions      int
	MaxPending       int
	PanicReporter    ingress.Reporter
	Metrics          *observability.Registry
	Logger           *slog.Logger
}

type ntcp2SessionRequestReader func(io.Reader, []byte, []byte, []byte, uint8, bool) (*ntcp2.Responder, ntcp2.SessionRequestOptions, error)
type ntcp2InitiatorFactory func([]byte) (*ntcp2.Initiator, error)

// NTCP2Manager is the concrete TCP NTCP2 transport manager. It authenticates
// SessionRequest/Created/Confirmed, validates the peer RouterInfo/static-key
// binding, derives data-phase directions, and routes authenticated I2NP blocks
// through Router's TransportBindings callback.
type ntcp2DialAttempt struct {
	done chan struct{}
	err  error
}

type NTCP2Manager struct {
	database           *netdb.Database
	staticPrivate      [32]byte
	staticIV           [aes.BlockSize]byte
	networkID          uint8
	timeout            time.Duration
	maxClockSkew       time.Duration
	maxSessions        int
	mu                 sync.RWMutex
	started            bool
	listener           net.Listener
	bindings           TransportBindings
	ctx                context.Context
	cancel             context.CancelFunc
	err                error
	done               chan struct{}
	close              sync.Once
	wg                 sync.WaitGroup
	pending            chan struct{}
	sessions           map[foundation.Hash]*ntcp2.Session
	dialing            map[foundation.Hash]*ntcp2DialAttempt
	replayMu           sync.Mutex
	replay             [ntcp2ReplayEntries][32]byte
	replaySeen         map[[32]byte]struct{}
	replayCount        uint16
	next               uint16
	reporter           ingress.Reporter
	metrics            *observability.Registry
	logger             *slog.Logger
	readSessionRequest ntcp2SessionRequestReader
	newInitiator       ntcp2InitiatorFactory
}

func (m *NTCP2Manager) releaseSensitive() {
	clear(m.staticPrivate[:])
	clear(m.staticIV[:])
	m.replayMu.Lock()
	clear(m.replay[:])
	clear(m.replaySeen)
	m.replayCount, m.next = 0, 0
	m.replayMu.Unlock()
}

// NewNTCP2Manager constructs a transport manager without opening sockets.
func NewNTCP2Manager(config NTCP2ManagerConfig) (*NTCP2Manager, error) {
	if len(config.StaticPrivate) != 32 || len(config.StaticIV) != aes.BlockSize {
		return nil, ErrNTCP2ManagerConfig
	}
	if _, err := ecdh.X25519().NewPrivateKey(config.StaticPrivate); err != nil {
		return nil, ErrNTCP2ManagerConfig
	}
	if config.NetworkID == 0 {
		config.NetworkID = defaultNTCP2NetworkID
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = defaultNTCP2HandshakeTimeout
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = defaultNTCP2MaxClockSkew
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultNTCP2MaxSessions
	}
	if config.MaxPending <= 0 {
		config.MaxPending = defaultNTCP2MaxPending
	}
	manager := &NTCP2Manager{
		database:           config.Database,
		networkID:          config.NetworkID,
		timeout:            config.HandshakeTimeout,
		maxClockSkew:       config.MaxClockSkew,
		maxSessions:        config.MaxSessions,
		done:               make(chan struct{}),
		pending:            make(chan struct{}, config.MaxPending),
		sessions:           make(map[foundation.Hash]*ntcp2.Session),
		dialing:            make(map[foundation.Hash]*ntcp2DialAttempt),
		replaySeen:         make(map[[32]byte]struct{}, ntcp2ReplayEntries),
		reporter:           config.PanicReporter,
		metrics:            config.Metrics,
		logger:             config.Logger,
		readSessionRequest: ntcp2.ReadSessionRequest,
		newInitiator:       ntcp2.NewInitiator,
	}
	copy(manager.staticPrivate[:], config.StaticPrivate)
	copy(manager.staticIV[:], config.StaticIV)
	return manager, nil
}

// Start accepts inbound NTCP2 connections from bindings.NTCP2. A nil listener
// is valid for an outbound-only router.
func (m *NTCP2Manager) Start(parent context.Context, bindings TransportBindings) error {
	if bindings.LocalInfo == nil || bindings.HandleI2NP == nil || bindings.Clock == nil {
		return ErrNTCP2ManagerConfig
	}
	if _, err := m.localHandshakePayload(bindings.LocalInfo); err != nil {
		return err
	}
	staticPublic, err := ecdhPublic(m.staticPrivate[:])
	if err != nil {
		return ErrNTCP2ManagerConfig
	}
	if bindings.NTCP2 != nil && !hasNTCP2LocalAddress(bindings.LocalInfo.Snapshot(), staticPublic, m.staticIV[:]) {
		return ErrNTCP2ManagerConfig
	}
	if parent ==
		nil {
		parent = context.Background()
	}

	if err := parent.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ErrStarted
	}
	m.started = true
	m.listener = bindings.NTCP2
	m.bindings = bindings
	m.ctx, m.cancel = context.WithCancel(parent)
	m.mu.Unlock()

	m.wg.Go(func() {
		<-m.ctx.Done()
		_ = m.Close()
	})
	if bindings.NTCP2 != nil {
		m.wg.Add(1)
		go m.acceptLoop()
	}
	go func() {
		m.wg.Wait()
		close(m.done)
	}()
	return nil
}

// Close stops accepting, closes established sessions, and unblocks Wait.
func (m *NTCP2Manager) Close() error {
	var closeErr error
	m.close.Do(func() {
		m.mu.Lock()
		listener := m.listener
		cancel := m.cancel
		sessions := make([]*ntcp2.Session, 0, len(m.sessions))
		for _, session := range m.sessions {
			sessions = append(sessions, session)
		}
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if listener != nil {
			closeErr = listener.Close()
		}
		for _, session := range sessions {
			if err := session.Close(); closeErr == nil && err != nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

// Wait blocks until all handshake and data workers have stopped. It is the
// manager-owned secret-clear barrier after Close.
func (m *NTCP2Manager) Wait() error {
	m.mu.RLock()
	started := m.started
	done := m.done
	m.mu.RUnlock()
	if !started {
		m.releaseSensitive()
		return nil
	}
	<-done
	m.releaseSensitive()
	m.mu.RLock()
	err := m.err
	m.mu.RUnlock()
	return err
}

// Status reports whether the manager remains active and its first terminal
// listener error, if any.
func (m *NTCP2Manager) Status() TransportStatus {
	m.mu.RLock()
	status := TransportStatus{Running: m.started && m.ctx != nil && m.ctx.Err() == nil, Error: m.err}
	m.mu.RUnlock()
	return status
}

// EnsureSession authenticates a bidirectional NTCP2 session without emitting
// an I2NP message.
func (m *NTCP2Manager) EnsureSession(ctx context.Context, peer foundation.Hash) error {

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.sessions[peer] != nil {
		m.mu.Unlock()
		return nil
	}
	if pending := m.dialing[peer]; pending != nil {
		done := pending.done
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			if m.session(peer) != nil {
				return nil
			}
			return pending.err
		}
	}
	pending := &ntcp2DialAttempt{done: make(chan struct{})}
	m.dialing[peer] = pending
	m.mu.Unlock()

	err := m.openOutbound(ctx, peer)
	if m.session(peer) != nil {
		err = nil
	}
	result := err
	if err != nil {
		result = errors.Join(ErrNTCP2Peer, err)
	}
	m.mu.Lock()
	delete(m.dialing, peer)
	pending.err = result
	close(pending.done)
	m.mu.Unlock()
	if err != nil {
		if m.metrics != nil {
			m.metrics.IncTransportHandshakeFailures()
		}
		if m.logger != nil {
			m.logger.Warn("public transport handshake failed", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "phase", ntcp2FailurePhase(err), "error", err)
		}
		return result
	}
	return nil
}

func (m *NTCP2Manager) HasSession(peer foundation.Hash) bool {
	return m != nil && m.session(peer) != nil
}

func (m *NTCP2Manager) DropSession(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	session := m.session(peer)
	if session == nil {
		return false
	}
	_ = session.Close()
	return true
}

// Send delivers one standard I2NP message over an established session, dialing
// and authenticating an NTCP2 peer from the verified netdb when necessary.
func (m *NTCP2Manager) Send(ctx context.Context, peer foundation.Hash, message i2np.Message) error {

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.EnsureSession(ctx, peer); err != nil {
		return err
	}
	if session := m.session(peer); session != nil {
		return m.writeI2NP(session, message)
	}
	return ErrNTCP2Session
}

func (m *NTCP2Manager) writeI2NP(session *ntcp2.Session, message i2np.Message) error {
	err := writeNTCP2I2NP(session, message)
	if err == nil && m.metrics != nil {
		m.metrics.AddTransportSentBytes(uint64(ntcp2.BlockHeaderLen + i2np.TransportHeaderLen + len(message.Payload)))
	}
	return err
}

func (m *NTCP2Manager) acceptLoop() {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if m.contextErr() == nil && !errors.Is(err, net.ErrClosed) {
				m.recordError(err)
				_ = m.Close()
			}
			return
		}
		select {
		case m.pending <- struct{}{}:
			m.wg.Go(func() {
				defer func() { <-m.pending }()
				m.acceptOne(conn)
			})
		default:
			_ = conn.Close()
		}
	}
}

func (m *NTCP2Manager) acceptOne(conn net.Conn) {
	peerAddress := conn.RemoteAddr()
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = ingress.Report(recovered, m.reporter, ingress.BoundaryNTCP2Handshake, peerAddress)
		}
	}()
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(m.timeout)); err != nil {
		return
	}
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return
	}
	localHash := bindings.LocalInfo.Hash()
	var requestWire bytes.Buffer
	responder, request, err := m.readSessionRequest(io.TeeReader(conn, &requestWire), m.staticPrivate[:], localHash[:], m.staticIV[:], m.networkID, false)
	if err != nil {
		return
	}
	defer responder.ReleaseSensitive()
	if !m.timestampValid(request.Timestamp) || m.replayedRequest(requestWire.Bytes()[:32]) {
		return
	}
	padding := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, padding); err != nil {
		return
	}
	created, err := responder.BuildSessionCreated(make([]byte, ntcp2.SessionRequestCiphertextLen+len(padding)), localHash[:], padding, ntcp2.SessionCreatedOptions{PaddingLength: uint16(len(padding)), Timestamp: uint32(time.Now().Unix())})
	if err != nil || writeAll(conn, created) != nil {
		return
	}
	if request.Message3Part2Length < ntcp2.FrameTagLen {
		return
	}
	confirmedLen := 48 + int(request.Message3Part2Length)
	if confirmedLen < 64 || confirmedLen > ntcp2.MaxSessionRequestLen {
		return
	}
	confirmed := make([]byte, confirmedLen)
	if _, err = io.ReadFull(conn, confirmed); err != nil {
		return
	}
	static, payload, err := responder.ParseSessionConfirmed(confirmed)
	if err != nil {
		return
	}
	peer, err := validateNTCP2HandshakePayload(payload, static)
	nowMillis := uint64(bindings.Clock.Now().UnixMilli())
	if err != nil || peer.Hash() == localHash || !m.admitInboundPeer(peer, static, nowMillis) {
		return
	}
	session, err := responder.NewDataSession(conn)
	if err != nil || conn.SetDeadline(time.Time{}) != nil || !m.install(peer.Hash(), session) {
		return
	}
	conn = nil
	if m.logger != nil {
		m.logger.Info("authenticated public transport session established", "transport", "NTCP2", "peer", routerHashDiagnostic(peer.Hash()), "direction", "inbound")
	}
}

func (m *NTCP2Manager) openOutbound(ctx context.Context, peer foundation.Hash) error {
	m.mu.RLock()
	if !m.started || m.ctx == nil || m.ctx.Err() != nil {
		m.mu.RUnlock()
		return ErrNTCP2Session
	}
	bindings := m.bindings
	m.mu.RUnlock()
	if m.database == nil {
		return ErrNTCP2Session
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return ErrNTCP2Peer
	}
	if err := netdb.ReseedRouterInfoFresh(ref.Info, uint64(bindings.Clock.Now().UnixMilli())); err != nil {
		return fmt.Errorf("%w: %v", ErrNTCP2Peer, err)
	}
	remote, err := selectNTCP2AddressForNetwork(ref.Info, ntcp2AddressSelection(bindings.NTCP2))
	if err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Info("public transport peer selected", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "endpoint", net.JoinHostPort(remote.host, strconv.Itoa(int(remote.port))), "phase", "dial")
	}
	payload, err := m.localHandshakePayload(bindings.LocalInfo)
	if err != nil {
		return err
	}
	if len(payload)+64 > ntcp2.MaxSessionRequestLen || len(payload)+ntcp2.FrameTagLen > 0xffff {
		return ErrNTCP2Peer
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(remote.host, strconv.Itoa(int(remote.port))))
	if err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Debug("public transport handshake phase", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "phase", "tcp_connected")
	}
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	if err = conn.SetDeadline(time.Now().Add(m.timeout)); err != nil {
		return err
	}
	initiator, err := m.newInitiator(remote.static[:])
	if err != nil {
		return err
	}
	defer initiator.ReleaseSensitive()
	padding := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, padding); err != nil {
		return err
	}
	request, err := initiator.BuildSessionRequest(make([]byte, ntcp2.SessionRequestCiphertextLen+len(padding)), peer[:], remote.iv[:], padding, ntcp2.SessionRequestOptions{
		NetworkID:           m.networkID,
		Version:             2,
		PaddingLength:       uint16(len(padding)),
		Message3Part2Length: uint16(len(payload) + ntcp2.FrameTagLen),
		Timestamp:           uint32(time.Now().Unix()),
	}, false)
	if err != nil {
		return err
	}
	if err = writeAll(conn, request); err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Debug("public transport handshake phase", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "phase", "session_request_sent")
	}
	created, err := initiator.ReadSessionCreated(conn, peer[:])
	if err != nil || !m.timestampValid(created.Timestamp) {

		if err ==
			nil {
			err = ErrNTCP2Peer
		}
		return err
	}
	if m.logger != nil {
		m.logger.Debug("public transport handshake phase", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "phase", "session_created_authenticated")
	}
	confirmed, err := initiator.BuildSessionConfirmed(make([]byte, 64+len(payload)), m.staticPrivate[:], payload)
	if err != nil {
		return err
	}
	if err = writeAll(conn, confirmed); err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Debug("public transport handshake phase", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "phase", "session_confirmed_sent")
	}
	session, err := initiator.NewDataSession(conn)
	if err != nil || conn.SetDeadline(time.Time{}) != nil {
		return err
	}
	if !m.install(peer, session) {
		return ErrNTCP2Session
	}
	keep = true
	if m.logger != nil {
		m.logger.Info("authenticated public transport session established", "transport", "NTCP2", "peer", routerHashDiagnostic(peer), "direction", "outbound")
	}
	return nil
}

func (m *NTCP2Manager) install(peer foundation.Hash, session *ntcp2.Session) bool {
	m.mu.Lock()
	if m.ctx == nil || m.ctx.Err() != nil || len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		_ = session.Close()
		return false
	}
	if _, exists := m.sessions[peer]; exists {
		m.mu.Unlock()
		_ = session.Close()
		return false
	}
	m.sessions[peer] = session
	if m.metrics != nil {
		m.metrics.IncTransportConnections()
		m.metrics.SetTransportNTCP2Sessions(uint64(len(m.sessions)))
	}
	m.mu.Unlock()
	m.wg.Add(1)
	go m.readSession(peer, session)
	return true
}

func (m *NTCP2Manager) readSession(peer foundation.Hash, session *ntcp2.Session) {
	defer m.wg.Done()
	defer func() {
		if recovered := recover(); recovered != nil {
			err := ingress.Report(recovered, m.reporter, ingress.BoundaryNTCP2Frame, nil)
			if m.logger != nil {
				m.logger.Warn("closed NTCP2 session after recovered frame panic", "peer", routerHashDiagnostic(peer), "error", err)
			}
			// The session cleanup below removes only this peer. A frame-local
			// panic must never close unrelated authenticated sessions.
		}
	}()
	defer func() {
		m.mu.Lock()
		if m.sessions[peer] == session {
			delete(m.sessions, peer)
			if m.metrics != nil {
				m.metrics.IncTransportDisconnections()
				m.metrics.SetTransportNTCP2Sessions(uint64(len(m.sessions)))
			}
		}
		m.mu.Unlock()
		_ = session.Close()
	}()
	plaintext := make([]byte, ntcp2.MaxPlaintextFrame)
	for {
		frame, err := session.Read(plaintext)
		if err != nil {
			return
		}
		if m.metrics != nil {
			m.metrics.AddTransportReceivedBytes(uint64(len(frame)))
		}
		if !m.handleNTCP2Frame(peer, frame) {
			return
		}
	}
}

func (m *NTCP2Manager) handleNTCP2Frame(peer foundation.Hash, frame []byte) bool {
	iterator := ntcp2.NewBlockIterator(frame)
	terminated := false
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return false
		}
		if !ok {
			return !terminated
		}
		switch block.Type {
		case ntcp2.BlockDateTime:
			if len(block.Data) != 4 {
				return false
			}
		case ntcp2.BlockI2NP:
			if !m.handleNTCP2I2NPBlock(peer, block.Data) {
				return false
			}
		case ntcp2.BlockRouterInfo:
			if !m.handleNTCP2RouterInfoBlock(peer, block.Data) {
				return false
			}
		case ntcp2.BlockTermination:
			terminated = true
		}
	}
}

func (m *NTCP2Manager) handleNTCP2I2NPBlock(peer foundation.Hash, data []byte) bool {
	message, err := decodeNTCP2I2NP(data)
	if err != nil {
		return false
	}
	bindings := m.currentBindings()
	nowMillis := uint64(bindings.Clock.Now().UnixMilli())
	var handleErr error
	switch {
	case bindings.HandleI2NPFrom != nil:
		handleErr = bindings.HandleI2NPFrom(peer, message, nowMillis, false)
	case bindings.HandleI2NP == nil:
		handleErr = ErrNTCP2Session
	default:
		handleErr = bindings.HandleI2NP(message, nowMillis, false)
	}
	if handleErr != nil && m.logger != nil {
		m.logger.Debug("authenticated I2NP handler rejected NTCP2 frame",
			"peer", routerHashDiagnostic(peer), "message_type", message.Header.Type, "message_id", message.Header.ID, "error", handleErr)
	}
	return true
}

func (m *NTCP2Manager) handleNTCP2RouterInfoBlock(peer foundation.Hash, data []byte) bool {
	if len(data) < 2 || data[0]&^byte(1) != 0 {
		return false
	}
	info, err := netdb.ParseRouterInfo(data[1:])
	if err != nil || info.Hash() != peer {
		return false
	}
	valid, err := info.Verify()
	if err != nil || !valid {
		return false
	}
	if m.database == nil {
		return true
	}
	bindings := m.currentBindings()
	now := bindings.Clock.Now()
	return m.database.AdmitRouterInfo(info, false, uint64(now.UnixMilli())) == nil
}

func (m *NTCP2Manager) localHandshakePayload(local LocalInfo) ([]byte, error) {
	if local == nil {
		return nil, ErrNTCP2ManagerConfig
	}
	info := local.Snapshot()
	if len(info.Bytes()) == 0 {
		return nil, ErrNTCP2ManagerConfig
	}
	valid, err := info.Verify()
	if err != nil || !valid {
		return nil, ErrNTCP2ManagerConfig
	}
	staticPublic, err := ecdhPublic(m.staticPrivate[:])
	if err != nil || !hasNTCP2Static(info, staticPublic) {
		return nil, ErrNTCP2ManagerConfig
	}
	if len(info.Bytes())+1 > ntcp2.MaxBlockData {
		return nil, ErrNTCP2Peer
	}
	payload := make([]byte, ntcp2.BlockHeaderLen+1+len(info.Bytes()))
	payload[0] = ntcp2.BlockRouterInfo
	binary.BigEndian.PutUint16(payload[1:3], uint16(1+len(info.Bytes())))
	payload[3] = 0 // local-store RouterInfo
	copy(payload[4:], info.Bytes())
	return payload, nil
}

func validateNTCP2HandshakePayload(payload, static []byte) (netdb.RouterInfo, error) {
	iterator := ntcp2.NewBlockIterator(payload)
	first, ok, err := iterator.Next()
	if err != nil || !ok || first.Type != ntcp2.BlockRouterInfo || len(first.Data) < 2 || first.Data[0]&^byte(1) != 0 {
		return netdb.RouterInfo{}, ErrNTCP2Peer
	}
	info, err := netdb.ParseRouterInfo(first.Data[1:])
	if err != nil {
		return netdb.RouterInfo{}, err
	}
	valid, err := info.Verify()
	if err != nil || !valid || !hasNTCP2Static(info, static) {
		return netdb.RouterInfo{}, ErrNTCP2Peer
	}
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return netdb.RouterInfo{}, err
		}
		if !ok {
			return info, nil
		}
		if block.Type == ntcp2.BlockOptions && len(block.Data) >= 12 {
			continue
		}
		if block.Type == ntcp2.BlockPadding {
			continue
		}
		return netdb.RouterInfo{}, ErrNTCP2Peer
	}
}

func (m *NTCP2Manager) admitInboundPeer(peer netdb.RouterInfo, static []byte, nowMillis uint64) bool {
	if !validNTCP2RouterInfoTime(peer, nowMillis) {
		return false
	}
	if m.database == nil {
		return true
	}
	if current, ok := m.database.Routers().Get(peer.Hash()); ok && current.Info.Published > peer.Published {
		// The current, newer RouterInfo owns the live static key. An archived
		// RouterInfo can authenticate only if its handshake key still matches,
		// and Database admission below retains the newer wire record.
		if !hasNTCP2Static(current.Info, static) {
			return false
		}
	}
	return m.database.AdmitRouterInfo(peer, false, nowMillis) == nil
}

func validNTCP2RouterInfoTime(info netdb.RouterInfo, nowMillis uint64) bool {
	return netdb.RouterInfoFresh(info, nowMillis) == nil
}

func hasNTCP2Static(info netdb.RouterInfo, static []byte) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		if !bytes.Equal(address.TransportStyle, []byte("NTCP")) && !bytes.Equal(address.TransportStyle, []byte("NTCP2")) {
			continue
		}
		options := address.Options.Iterator()
		var key []byte
		version := ""
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "s":
				key = value
			case "v":
				version = string(value)
			}
		}
		decoded, err := foundation.DecodeI2PBase64(key)
		if err == nil && len(decoded) == 32 && bytes.Equal(decoded, static) && supportsNTCP2Version(version) {
			return true
		}
	}
}

func hasNTCP2LocalAddress(info netdb.RouterInfo, static, iv []byte) bool {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return false
		}
		if !bytes.Equal(address.TransportStyle, []byte("NTCP")) && !bytes.Equal(address.TransportStyle, []byte("NTCP2")) {
			continue
		}
		var host, port, key, advertisedIV, version []byte
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "host":
				host = value
			case "port":
				port = value
			case "s":
				key = value
			case "i":
				advertisedIV = value
			case "v":
				version = value
			}
		}
		if !supportsNTCP2Version(string(version)) || len(host) == 0 != (len(port) == 0) {
			continue
		}
		if len(port) != 0 {
			portNumber, err := strconv.ParseUint(string(port), 10, 16)
			if err != nil || portNumber == 0 {
				continue
			}
		}
		decodedKey, keyErr := foundation.DecodeI2PBase64(key)
		decodedIV, ivErr := foundation.DecodeI2PBase64(advertisedIV)
		if keyErr == nil && ivErr == nil && bytes.Equal(decodedKey, static) && bytes.Equal(decodedIV, iv) {
			return true
		}
	}
}

type ntcp2Address struct {
	host   string
	port   uint16
	static [32]byte
	iv     [aes.BlockSize]byte
}

type ntcp2AddressMode uint8

const (
	ntcp2AddressAny ntcp2AddressMode = iota
	ntcp2AddressPreferIPv4
	ntcp2AddressRequireIPv4
)

func selectNTCP2Address(info netdb.RouterInfo) (ntcp2Address, error) {
	return selectNTCP2AddressForNetwork(info, ntcp2AddressAny)
}

func selectNTCP2AddressForNetwork(info netdb.RouterInfo, mode ntcp2AddressMode) (ntcp2Address, error) {
	var fallback ntcp2Address
	found := false
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil {
			return ntcp2Address{}, err
		}
		if !ok {
			if found && mode != ntcp2AddressRequireIPv4 {
				return fallback, nil
			}
			return ntcp2Address{}, ErrNTCP2Peer
		}
		if !bytes.Equal(address.TransportStyle, []byte("NTCP")) && !bytes.Equal(address.TransportStyle, []byte("NTCP2")) {
			continue
		}
		var host, port, static, iv, version string
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "host":
				host = string(value)
			case "port":
				port = string(value)
			case "s":
				static = string(value)
			case "i":
				iv = string(value)
			case "v":
				version = string(value)
			}
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portNumber == 0 || !supportsNTCP2Version(version) {
			continue
		}
		staticKey, staticErr := foundation.DecodeI2PBase64([]byte(static))
		ivBytes, ivErr := foundation.DecodeI2PBase64([]byte(iv))
		if staticErr != nil || ivErr != nil || len(staticKey) != 32 || len(ivBytes) != aes.BlockSize {
			continue
		}
		var selected ntcp2Address
		selected.host, selected.port = host, uint16(portNumber)
		copy(selected.static[:], staticKey)
		copy(selected.iv[:], ivBytes)
		if !found {
			fallback, found = selected, true
		}
		if mode == ntcp2AddressAny || net.ParseIP(host).To4() != nil {
			return selected, nil
		}
	}
}

func ntcp2AddressSelection(listener net.Listener) ntcp2AddressMode {
	if listener == nil {
		return ntcp2AddressPreferIPv4
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return ntcp2AddressAny
	}
	if address.IP.To4() != nil {
		return ntcp2AddressRequireIPv4
	}
	if address.IP.IsUnspecified() {
		return ntcp2AddressPreferIPv4
	}
	return ntcp2AddressAny
}

func supportsNTCP2Version(version string) bool {
	for part := range strings.SplitSeq(version, ",") {
		if part == "2" {
			return true
		}
	}
	return false
}

func ecdhPublic(private []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func marshalNTCP2I2NP(message i2np.Message) ([]byte, error) {
	encoded := make([]byte, i2np.TransportHeaderLen+len(message.Payload))
	if err := marshalNTCP2I2NPTo(encoded, message); err != nil {
		return nil, err
	}
	return encoded, nil
}

func marshalNTCP2I2NPTo(dst []byte, message i2np.Message) error {
	if len(message.Payload) > i2np.I2PDMaxPayload {
		return i2np.ErrPayloadTooLarge
	}
	expiration, ok := i2np.EncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		return i2np.ErrPayloadTooLarge
	}
	encodedLen := i2np.TransportHeaderLen + len(message.Payload)
	if len(dst) < encodedLen {
		return io.ErrShortBuffer
	}
	dst[0] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(dst[1:5], message.Header.ID)
	binary.BigEndian.PutUint32(dst[5:9], expiration)
	copy(dst[i2np.TransportHeaderLen:encodedLen], message.Payload)
	return nil
}

func decodeNTCP2I2NP(data []byte) (i2np.Message, error) {
	header, err := i2np.ParseTransportHeader(data)
	if err != nil {
		return i2np.Message{}, err
	}
	return i2np.Message{
		Header:  i2np.Header{Type: header.Type, ID: header.ID, Expiration: header.Expiration},
		Payload: append([]byte(nil), data[i2np.TransportHeaderLen:]...),
	}, nil
}

func writeNTCP2I2NP(session *ntcp2.Session, message i2np.Message) error {
	if len(message.Payload) > i2np.I2PDMaxPayload {
		return i2np.ErrPayloadTooLarge
	}
	plaintext := make([]byte, ntcp2.BlockHeaderLen+i2np.TransportHeaderLen+len(message.Payload))
	plaintext[0] = ntcp2.BlockI2NP
	binary.BigEndian.PutUint16(plaintext[1:3], uint16(len(plaintext)-ntcp2.BlockHeaderLen))
	if err := marshalNTCP2I2NPTo(plaintext[ntcp2.BlockHeaderLen:], message); err != nil {
		return err
	}
	return session.Write(plaintext)
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) != 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (m *NTCP2Manager) session(peer foundation.Hash) *ntcp2.Session {
	m.mu.RLock()
	session := m.sessions[peer]
	m.mu.RUnlock()
	return session
}

func (m *NTCP2Manager) currentBindings() TransportBindings {
	m.mu.RLock()
	bindings := m.bindings
	m.mu.RUnlock()
	return bindings
}

func (m *NTCP2Manager) contextErr() error {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return ErrNTCP2Session
	}
	return ctx.Err()
}

func (m *NTCP2Manager) timestampValid(timestamp uint32) bool {
	bindings := m.currentBindings()
	clock := bindings.Clock
	current := clock.Now()
	now := current.Unix()
	delta := now - int64(timestamp)
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(m.maxClockSkew/time.Second)
}

func (m *NTCP2Manager) replayedRequest(obfuscatedEphemeral []byte) bool {
	if len(obfuscatedEphemeral) != 32 {
		return true
	}
	key := foundation.Sum(obfuscatedEphemeral)
	m.replayMu.Lock()
	defer m.replayMu.Unlock()
	if m.replaySeen == nil {
		m.replaySeen = make(map[[32]byte]struct{}, ntcp2ReplayEntries)
	}
	if _, seen := m.replaySeen[key]; seen {
		return true
	}
	if m.replayCount == ntcp2ReplayEntries {
		delete(m.replaySeen, m.replay[m.next])
	} else {
		m.replayCount++
	}
	m.replay[m.next] = key
	m.replaySeen[key] = struct{}{}
	m.next = (m.next + 1) % ntcp2ReplayEntries
	return false
}

func (m *NTCP2Manager) recordError(err error) {
	m.mu.Lock()
	if m.err == nil {
		m.err = err
	}
	m.mu.Unlock()
}

func ntcp2FailurePhase(err error) string {
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Op == "dial" {
		return "dial"
	}
	if errors.Is(err, ErrNTCP2Peer) {
		return "router_info_or_created_validation"
	}
	if errors.Is(err, ErrNTCP2Session) {
		return "session_install"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "session_created_read"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "session_created_reset"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "session_created_timeout"
	}
	return "handshake"
}
