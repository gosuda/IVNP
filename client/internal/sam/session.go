package sam

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"gosuda.org/ivnp/interfaces/destination"
)

type sessionStyle string

const (
	styleStream   sessionStyle = "STREAM"
	styleDatagram sessionStyle = "DATAGRAM"
	styleRaw      sessionStyle = "RAW"
	stylePrimary  sessionStyle = "PRIMARY"
)

type samSession struct {
	server         *Server
	root           *samSession
	id             string
	style          sessionStyle
	endpoint       destination.DestinationEndpoint
	control        *serverConnection
	ctx            context.Context
	cancel         context.CancelFunc
	sourceIP       netip.Addr
	fromPort       uint16
	toPort         uint16
	listenPort     uint16
	protocol       uint8
	listenProtocol uint8
	rawHeader      bool
	udpTarget      *net.UDPAddr

	forward             bool
	mu                  sync.Mutex
	listener            net.Listener
	subscription        destination.MessageSubscription
	children            map[string]*samSession
	attachments         map[net.Conn]struct{}
	queueBytes          *byteBudget
	acceptOnce          sync.Once
	acceptRequests      chan acceptRequest
	acceptIncoming      chan acceptResult
	acceptAdmissions    atomic.Uint64
	acceptCancellations atomic.Uint64
	once                sync.Once
	closeErr            error
	wg                  sync.WaitGroup
}

func newRootSession(server *Server, id string, style sessionStyle, endpoint destination.DestinationEndpoint, control *serverConnection, fromPort, toPort, listenPort uint16, protocol, listenProtocol uint8, rawHeader bool, udpTarget *net.UDPAddr) *samSession {
	ctx, cancel := context.WithCancel(server.ctx)
	s := &samSession{server: server, id: id, style: style, endpoint: endpoint, control: control, ctx: ctx, cancel: cancel, sourceIP: connectionIP(control.Conn), fromPort: fromPort, toPort: toPort, listenPort: listenPort, protocol: protocol, listenProtocol: listenProtocol, rawHeader: rawHeader, udpTarget: udpTarget, children: make(map[string]*samSession), attachments: make(map[net.Conn]struct{}), queueBytes: newByteBudget(server.config.MaxSessionQueueBytes), acceptRequests: make(chan acceptRequest, server.config.SessionQueue)}
	s.root = s
	return s
}

func (s *samSession) attach(connection net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.ctx.Done():
		return net.ErrClosed
	default:
	}
	s.attachments[connection] = struct{}{}
	return nil
}
func (s *samSession) detach(connection net.Conn) {
	s.mu.Lock()
	delete(s.attachments, connection)
	s.mu.Unlock()
}

func (s *samSession) close() error {
	if s == nil {
		return nil
	}
	r := s.root
	if r != s {
		s.closeChild()
		return nil
	}
	r.once.Do(func() {
		r.server.removeRoot(r)
		r.cancel()
		r.mu.Lock()
		children := make([]*samSession, 0, len(r.children))
		for _, child := range r.children {
			children = append(children, child)
		}
		clear(r.children)
		listener := r.listener
		r.listener = nil
		attachments := make([]net.Conn, 0, len(r.attachments))
		for connection := range r.attachments {
			attachments = append(attachments, connection)
		}
		clear(r.attachments)
		subscription := r.subscription
		r.subscription = nil
		r.mu.Unlock()
		for _, child := range children {
			child.closeChild()
		}
		if subscription != nil {
			_ = subscription.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		for _, connection := range attachments {
			_ = connection.Close()
		}
		r.wg.Wait()
		r.closeErr = r.server.destroyDestination(r.endpoint)
	})
	return r.closeErr
}

func (s *samSession) closeChild() {
	if s == nil || s.root == s {
		return
	}
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		subscription := s.subscription
		s.subscription = nil
		listener := s.listener
		s.listener = nil
		attachments := make([]net.Conn, 0, len(s.attachments))
		for connection := range s.attachments {
			attachments = append(attachments, connection)
		}
		clear(s.attachments)
		s.mu.Unlock()
		if subscription != nil {
			_ = subscription.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		for _, connection := range attachments {
			_ = connection.Close()
		}
		s.wg.Wait()
	})
}

func (s *samSession) ensureListener() (net.Listener, error) {
	if s.style != styleStream {
		return nil, ErrProtocol
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener, nil
	}
	listener, err := s.endpoint.ListenI2P(s.ctx, net.JoinHostPort("", itoa16(s.listenPort)))
	if err != nil {
		return nil, err
	}
	s.listener = listener
	return listener, nil
}

func (s *samSession) startReceiver(route destination.DestinationRoute, capacity int) error {
	var subscription destination.MessageSubscription
	var err error
	if bounded, ok := s.endpoint.(destination.BoundedDestinationEndpoint); ok {
		subscription, err = bounded.SubscribeBounded(route, capacity, s.server.config.MaxSessionQueueBytes, s.server.queueBytes)
	} else {
		subscription, err = s.endpoint.Subscribe(route, capacity)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	select {
	case <-s.ctx.Done():
		s.mu.Unlock()
		_ = subscription.Close()
		return net.ErrClosed
	default:
	}
	s.subscription = subscription
	s.mu.Unlock()
	s.wg.Go(func() { ; s.receiveLoop(subscription) })
	return nil
}

func (s *samSession) removeChild(id string) error {
	r := s.root
	r.mu.Lock()
	child := r.children[id]
	if child != nil {
		delete(r.children, id)
	}
	r.mu.Unlock()
	if child == nil {
		return errors.New("sam: unknown subsession")
	}
	r.server.removeSession(child)
	child.closeChild()
	return nil
}

func (s *samSession) beginForward() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forward {
		return false
	}
	s.forward = true
	return true
}

func (s *samSession) endForward() {
	s.mu.Lock()
	s.forward = false
	s.mu.Unlock()
}

func connectionIP(connection net.Conn) netip.Addr {
	if connection == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func (s *samSession) reserve(size int64) bool {
	if !s.queueBytes.acquire(size) {
		return false
	}
	if !s.server.queueBytes.acquire(size) {
		s.queueBytes.release(size)
		return false
	}
	return true
}

func (s *samSession) release(size int64) {
	s.server.queueBytes.release(size)
	s.queueBytes.release(size)
}
