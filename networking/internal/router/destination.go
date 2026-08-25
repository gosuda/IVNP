package router

import (
	"context"
	"errors"
	"net"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	streamingtunnel "gosuda.org/ivnp/networking/internal/streaming/tunnel"
)

var (
	ErrDestinationExists       = errors.New("router: destination session already exists")
	ErrDestinationNotFound     = errors.New("router: destination session not found")
	ErrDefaultDestination      = errors.New("router: default destination session is not configured")
	ErrDestinationRoute        = errors.New("router: destination route overlaps an existing subscription")
	ErrDestinationBackpressure = errors.New("router: destination message queue is full")
)

// DestinationManager owns local Destination sessions independently of router
// transport sockets. Each session owns exactly one streaming endpoint and its
// key material stays scoped to that endpoint until Destroy or Close.
type DestinationManager struct {
	mu        sync.RWMutex
	sessions  map[foundation.Hash]*DestinationSession
	defaultID foundation.Hash
	closed    bool
}

// DestinationSessionConfig configures one locally-owned I2P Destination. The
// sender receives protocol-6 packets after Streaming has authenticated them;
// it must wrap them in Garlic and deliver them through the selected I2P tunnel.
type DestinationSessionConfig struct {
	Streaming streamingtunnel.TunnelNetworkConfig
	Default   bool
	// Release tears down resources owned by this destination after its
	// streaming endpoint has cancelled and joined.
	Release func()
}

// DestinationSession is a running local Destination. It implements the public
// StreamBackend shape through DialI2P and ListenI2P; it never exposes a peer
// transport socket as an I2P connection.
type DestinationSession struct {
	manager *DestinationManager
	hash    foundation.Hash
	stream  *streamingtunnel.TunnelNetwork
	sender  streamingtunnel.TunnelSender
	release func()
	once    sync.Once

	routeMu sync.RWMutex
	routes  map[destination.DestinationRoute]*destinationSubscription
}

// NewDestinationManager constructs an empty session registry without network
// I/O. Sessions are added explicitly so an embedded router can own several
// isolated Destinations.
func NewDestinationManager() *DestinationManager {
	return &DestinationManager{sessions: make(map[foundation.Hash]*DestinationSession)}
}

// Create starts a local Destination streaming endpoint and atomically inserts
// it into the registry. The endpoint is closed if insertion cannot complete.
func (m *DestinationManager) Create(config DestinationSessionConfig) (*DestinationSession, error) {
	if m == nil {
		return nil, ErrDestinationNotFound
	}
	stream, err := streamingtunnel.NewTunnelNetwork(config.Streaming)
	if err != nil {
		return nil, err
	}
	hash := config.Streaming.Destination.Hash()
	session := &DestinationSession{manager: m, hash: hash, stream: stream, sender: config.Streaming.Sender, release: config.Release, routes: make(map[destination.DestinationRoute]*destinationSubscription)}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = stream.Close()
		return nil, net.ErrClosed
	}
	if _, exists := m.sessions[hash]; exists {
		m.mu.Unlock()
		_ = stream.Close()
		return nil, ErrDestinationExists
	}
	m.sessions[hash] = session
	if config.Default || m.defaultID == (foundation.Hash{}) {
		m.defaultID = hash
	}
	m.mu.Unlock()
	return session, nil
}

// Session returns the running Destination with hash.
func (m *DestinationManager) Session(hash foundation.Hash) (*DestinationSession, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	session, ok := m.sessions[hash]
	m.mu.RUnlock()
	return session, ok
}

// SetDefault chooses the session used when the manager is supplied directly as
// Router.StreamBackend or ivnp.StreamNetwork.
func (m *DestinationManager) SetDefault(hash foundation.Hash) error {
	if m == nil {
		return ErrDestinationNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	if _, exists := m.sessions[hash]; !exists {
		return ErrDestinationNotFound
	}
	m.defaultID = hash
	return nil
}

// Destroy removes a Destination before closing its streaming endpoint. New
// inbound delivery cannot acquire it after removal, and blocked stream callers
// are released by endpoint Close.
func (m *DestinationManager) Destroy(hash foundation.Hash) error {
	if m == nil {
		return ErrDestinationNotFound
	}
	m.mu.Lock()
	session, exists := m.sessions[hash]
	if !exists {
		m.mu.Unlock()
		return ErrDestinationNotFound
	}
	delete(m.sessions, hash)
	if m.defaultID == hash {
		m.defaultID = foundation.Hash{}
		for candidate := range m.sessions {
			m.defaultID = candidate
			break
		}
	}
	m.mu.Unlock()
	session.shutdown()
	return nil
}

// HandleMessage delivers one authenticated destination payload. Streaming is
// dispatched directly; message protocols use exact-port then wildcard routes.
func (m *DestinationManager) HandleMessage(ctx context.Context, delivery streamingtunnel.Delivery) error {
	if m == nil {
		return ErrDestinationNotFound
	}
	m.mu.RLock()
	session := m.sessions[delivery.To]
	m.mu.RUnlock()
	if session == nil {
		return ErrDestinationNotFound
	}
	if delivery.Protocol == streamingtunnel.ProtocolStreaming {
		return session.stream.HandleDelivery(ctx, delivery)
	}
	return session.deliver(delivery)
}

// deliverLocalMessage accepts loopback only from the currently registered
// session instance. A stale session may retain the same Destination hash after
// Destroy and recreation, but it must never deliver into its replacement.
func (m *DestinationManager) deliverLocalMessage(session *DestinationSession, delivery streamingtunnel.Delivery) error {
	if m == nil || session == nil {
		return net.ErrClosed
	}
	m.mu.RLock()
	registered := m.sessions[delivery.To]
	m.mu.RUnlock()
	if registered != session {
		return net.ErrClosed
	}
	return session.deliver(delivery)
}

// HandleStreaming is retained as the authenticated ingress entry point while
// dispatching all supported destination protocols.
func (m *DestinationManager) HandleStreaming(ctx context.Context, delivery streamingtunnel.Delivery) error {
	return m.HandleMessage(ctx, delivery)
}

// Close tears down every owned Destination session. It is idempotent.
func (m *DestinationManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*DestinationSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	clear(m.sessions)
	m.defaultID = foundation.Hash{}
	m.mu.Unlock()
	for _, session := range sessions {
		session.shutdown()
	}
	return nil
}

// Hash returns this session's local Destination hash.
func (s *DestinationSession) Hash() foundation.Hash { return s.hash }

// B32 returns this session's local b32 hostname.
func (s *DestinationSession) B32() string { return s.stream.B32() }

// Destination returns an owned canonical public Destination encoding.
func (s *DestinationSession) Destination() []byte {
	if s == nil || s.stream == nil {
		return nil
	}
	return s.stream.Destination()
}

// StreamingStats returns the session's non-sensitive streaming congestion
// snapshot. A destroyed session reports the state retained by its closed
// endpoint, which has no live connections.
func (s *DestinationSession) StreamingStats() streamingtunnel.NetworkStats {
	if s == nil {
		return streamingtunnel.NetworkStats{}
	}
	return s.stream.Stats()
}

// DialI2P and ListenI2P make a session directly usable with ivnp.Dialer and
// ivnp.ListenerConfig.
func (s *DestinationSession) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	if s == nil || s.stream == nil {
		return nil, net.ErrClosed
	}
	return s.stream.DialI2P(ctx, address)
}

func (s *DestinationSession) DialI2PFromPort(ctx context.Context, address string, localPort uint16) (net.Conn, error) {
	if s == nil || s.stream == nil {
		return nil, net.ErrClosed
	}
	return s.stream.DialI2PFromPort(ctx, address, localPort)
}

func (s *DestinationSession) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	if s == nil || s.stream == nil {
		return nil, net.ErrClosed
	}
	return s.stream.ListenI2P(ctx, address)
}

// SendMessage routes a non-streaming destination payload. A payload addressed
// to this session is delivered through the authenticated local ingress path;
// remote payloads use this Destination's isolated sender and pool. Local
// delivery avoids creating initiator and responder ratchets under the same
// Destination hash, which cannot share one directional session slot.
func (s *DestinationSession) SendMessage(ctx context.Context, delivery streamingtunnel.Delivery) error {
	if s == nil || s.sender == nil {
		return net.ErrClosed
	}
	if delivery.From == (foundation.Hash{}) {
		delivery.From = s.hash
	}
	if delivery.From != s.hash || delivery.To == (foundation.Hash{}) {
		return streamingtunnel.ErrTunnelDestination
	}
	if delivery.To == s.hash && delivery.Protocol != streamingtunnel.ProtocolStreaming {
		return s.manager.deliverLocalMessage(s, delivery)
	}
	return s.sender.SendTunnel(ctx, delivery)
}

func (s *DestinationSession) Subscribe(route destination.DestinationRoute, capacity int) (destination.MessageSubscription, error) {
	return s.SubscribeBounded(route, capacity, 0, nil)
}

// SubscribeBounded installs a count- and byte-bounded authenticated message
// route. maxBytes zero retains count-only behavior for non-SAM callers.
func (s *DestinationSession) SubscribeBounded(route destination.DestinationRoute, capacity int, maxBytes int64, shared destination.ByteBudget) (destination.MessageSubscription, error) {
	if s == nil || route.Protocol == streamingtunnel.ProtocolStreaming || capacity < 1 || maxBytes < 0 {
		return nil, ErrDestinationRoute
	}
	subscription := &destinationSubscription{owner: s, route: route, messages: make(chan *destination.ReceivedMessage, capacity), done: make(chan struct{}), maxBytes: maxBytes, shared: shared}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	for existing := range s.routes {
		subscribeBoundedRejected := existing.Protocol == route.Protocol
		if subscribeBoundedRejected {
			subscribeBoundedRejected = (existing.ToPort == 0 || route.ToPort == 0 || existing.ToPort == route.ToPort)
		}
		if subscribeBoundedRejected {
			return nil, ErrDestinationRoute
		}
	}
	s.routes[route] = subscription
	return subscription, nil
}

func (s *DestinationSession) deliver(delivery streamingtunnel.Delivery) error {
	s.routeMu.RLock()
	subscription := s.routes[destination.DestinationRoute{Protocol: delivery.Protocol, ToPort: delivery.ToPort}]
	if subscription ==
		nil {
		subscription = s.routes[destination.DestinationRoute{Protocol: delivery.Protocol}]
	}

	s.routeMu.RUnlock()
	if subscription == nil {
		return ErrDestinationRoute
	}
	return subscription.enqueue(delivery)
}

func (s *DestinationSession) shutdown() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.routeMu.Lock()
		subscriptions := make([]*destinationSubscription, 0, len(s.routes))
		for _, subscription := range s.routes {
			subscriptions = append(subscriptions, subscription)
		}
		clear(s.routes)
		s.routeMu.Unlock()
		for _, subscription := range subscriptions {
			subscription.close(false)
		}
		if s.stream != nil {
			_ = s.stream.Close()
		}
		if s.release != nil {
			s.release()
		}
	})
}

// Close removes the session from its owner before closing it. Directly closing
// a session is therefore equivalent to DestinationManager.Destroy.
func (s *DestinationSession) Close() error {
	if s == nil || s.manager == nil {
		return nil
	}
	return s.manager.Destroy(s.hash)
}

type destinationSubscription struct {
	owner       *DestinationSession
	route       destination.DestinationRoute
	messages    chan *destination.ReceivedMessage
	done        chan struct{}
	maxBytes    int64
	queuedBytes int64
	shared      destination.ByteBudget
	mu          sync.Mutex
	closed      bool
	once        sync.Once
}

func (s *destinationSubscription) enqueue(delivery streamingtunnel.Delivery) error {
	size := len(delivery.Payload)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.maxBytes > 0 && (int64(size) > s.maxBytes || s.queuedBytes > s.maxBytes-int64(size)) {
		s.mu.Unlock()
		return ErrDestinationBackpressure
	}
	if s.shared != nil && !s.shared.TryReserve(size) {
		s.mu.Unlock()
		return ErrDestinationBackpressure
	}
	payload := append([]byte(nil), delivery.Payload...)
	message := destination.NewReceivedMessage(delivery, s.release)
	message.Delivery.Payload = payload
	// Charge the route before publishing the message. A receiver may release it
	// immediately after the channel send becomes visible.
	s.queuedBytes += int64(size)
	select {
	case s.messages <- message:
		s.mu.Unlock()
		return nil
	default:
		s.queuedBytes -= int64(size)
		s.mu.Unlock()
		if s.shared != nil {
			s.shared.Release(size)
		}
		clear(payload)
		return ErrDestinationBackpressure
	}
}

func (s *destinationSubscription) release(size int) {
	if size < 0 {
		return
	}
	s.mu.Lock()
	if int64(size) > s.queuedBytes {
		// Release callbacks are once-guarded, but contain accounting faults
		// instead of terminating the router if an alternate implementation
		// violates that ownership contract.
		s.mu.Unlock()
		return
	}
	s.queuedBytes -= int64(size)
	s.mu.Unlock()
	if s.shared != nil {
		s.shared.Release(size)
	}
}

func (s *destinationSubscription) Receive(ctx context.Context) (*destination.ReceivedMessage, error) {
	if s == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case message := <-s.messages:
		if message == nil {
			return nil, net.ErrClosed
		}
		return message, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *destinationSubscription) Close() error {
	if s == nil {
		return nil
	}
	s.close(true)
	return nil
}

func (s *destinationSubscription) close(detach bool) {
	s.once.Do(func() {
		if detach && s.owner != nil {
			s.owner.routeMu.Lock()
			if s.owner.routes[s.route] == s {
				delete(s.owner.routes, s.route)
			}
			s.owner.routeMu.Unlock()
		}
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.done)
		for {
			select {
			case message := <-s.messages:
				if message != nil {
					message.Release()
				}
			default:
				return
			}
		}
	})
}

// DialI2P and ListenI2P implement router.StreamBackend using the selected
// default Destination. They intentionally fail when callers have not chosen a
// default rather than routing an arbitrary identity's traffic.
func (m *DestinationManager) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	session, err := m.defaultSession()
	if err != nil {
		return nil, err
	}
	return session.DialI2P(ctx, address)
}

func (m *DestinationManager) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	session, err := m.defaultSession()
	if err != nil {
		return nil, err
	}
	return session.ListenI2P(ctx, address)
}

func (m *DestinationManager) defaultSession() (*DestinationSession, error) {
	if m == nil {
		return nil, ErrDefaultDestination
	}
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, net.ErrClosed
	}
	session := m.sessions[m.defaultID]
	m.mu.RUnlock()
	if session == nil {
		return nil, ErrDefaultDestination
	}
	return session, nil
}
