package overlay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ListenPolicy constrains which inbound channels a service accepts.
type ListenPolicy struct {
	// Protocols are the accepted endpoint protocols.
	Protocols []EndpointProtocol
	// Classes are the accepted route classes.
	Classes []RouteClass
	// Privacy is the minimum exposure constraint for accepted paths.
	Privacy PrivacyClass
	// Queue bounds pending inbound channels; zero selects 16. A full queue
	// applies backpressure to the provider: it is not asked for the next
	// channel until the application consumes one.
	Queue int
}

// InboundProvider delivers authenticated inbound channels for a service. The
// returned ChannelScope must describe the channel's authenticated binding —
// Fabric and NetworkID of the context that carried it, svc.RealmID(),
// svc.Endpoint().ID, svc.Port(), and the negotiated Protocol, Class, and
// Exposure — with PolicyGen stamped from svc.PolicyGen() at delivery time so
// a channel authenticated under a superseded policy is not admitted. The
// channel's own Binding must return the same scope. The core re-verifies
// every field before exposing a Connection to the application.
type InboundProvider interface {
	Accept(ctx context.Context, svc *Service) (Channel, ChannelScope, error)
}

// inboundItem is one buffered provider delivery: a channel and its claimed
// scope, or a provider error.
type inboundItem struct {
	channel Channel
	scope   ChannelScope
	err     error
}

// inboundErrorBackoff bounds churn when a provider fails persistently.
const inboundErrorBackoff = 50 * time.Millisecond

// Listener is a service's bounded inbound accept queue. privacy, protocols,
// and classes hold only the immutable service/listener side of the
// intersection; the realm side is re-evaluated under the current policy
// generation for every delivered channel.
type Listener struct {
	svc       *Service
	sources   []InboundProvider
	privacy   PrivacyClass
	protocols map[EndpointProtocol]struct{}
	classes   map[RouteClass]struct{}
	queue     chan inboundItem
	done      chan struct{}
	pumpDone  chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
}

// Listen registers the service's accepted protocol/path policy. The accepted
// sets are intersected with the service and realm declarations; an impossible
// intersection fails rather than silently relaxing the policy. The realm side
// of that intersection is feasibility-checked here but re-evaluated per
// inbound channel — a policy replacement must not escape through a
// listen-time snapshot. Inbound channels arrive through a registered
// InboundProvider into a queue bounded by policy.Queue plus one channel in
// provider handoff.
func (s *Service) Listen(policy ListenPolicy) (*Listener, error) {
	s.realm.mu.Lock()
	realmClosed := s.realm.closed
	s.realm.mu.Unlock()
	if realmClosed {
		return nil, CodeClosed.Wrap("realm closed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, CodeClosed.Wrap("service closed")
	}
	if s.endpoint.ID == (EndpointID{}) {
		return nil, CodeUnsupportedCapability.Wrap("service has no endpoint identity to listen under")
	}
	if !policy.Privacy.valid() {
		return nil, CodeInvalidConfig.Wrap("listen policy privacy")
	}
	if len(policy.Protocols) == 0 || len(policy.Classes) == 0 {
		return nil, CodeInvalidConfig.Wrap("listen policy requires protocols and route classes")
	}
	if !validProtocols(policy.Protocols) || !classSetValid(policy.Classes) {
		return nil, CodeInvalidConfig.Wrap("listen policy carries an unknown enum value")
	}
	if _, err := mergePrivacy(s.realm.privacyClass(), s.spec.Privacy, policy.Privacy); err != nil {
		return nil, err
	}
	// The stored sets exclude the realm side: cfg.Routing and cfg.Privacy are
	// reapplied from a fresh policy snapshot in admitScope, so a replacement
	// takes effect on the next delivered channel rather than on re-listen.
	privacy, err := mergePrivacy(s.spec.Privacy, policy.Privacy)
	if err != nil {
		return nil, err
	}
	protocols := setOfProtocols(s.spec.Protocols)
	intersectProtocols(protocols, setOfProtocols(policy.Protocols))
	if len(protocols) == 0 {
		return nil, CodeMinimumSecurityUnsatisfied.Wrap("no endpoint protocol satisfies every participant")
	}
	classes := routingClasses(s.realm.routingMode())
	intersectRouteClasses(classes, routingClasses(s.spec.Routing))
	intersectRouteClasses(classes, setOfRouteClasses(policy.Classes))
	if len(classes) == 0 {
		return nil, CodeMinimumSecurityUnsatisfied.Wrap("no route class satisfies every participant")
	}
	classes = routingClasses(s.spec.Routing)
	intersectRouteClasses(classes, setOfRouteClasses(policy.Classes))
	sources := s.realm.host.inboundProviders()
	if len(sources) == 0 {
		return nil, CodeUnsupportedCapability.Wrap("no inbound transport provider")
	}
	if policy.Queue <= 0 {
		policy.Queue = 16
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		svc: s, sources: sources, privacy: privacy,
		protocols: protocols, classes: classes,
		queue: make(chan inboundItem, policy.Queue),
		done:  make(chan struct{}), pumpDone: make(chan struct{}),
		ctx: ctx, cancel: cancel,
	}
	if s.listeners == nil {
		s.listeners = make(map[*Listener]struct{})
	}
	s.listeners[l] = struct{}{}
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(p InboundProvider) {
			defer wg.Done()
			l.pump(p)
		}(src)
	}
	go func() {
		wg.Wait()
		close(l.pumpDone)
	}()
	return l, nil
}

// pump pulls inbound channels into the bounded queue from one inbound provider.
// At most Queue channels buffer, plus one channel in provider handoff; a full
// queue applies backpressure to the provider. Close stops the pump and rejects
// every buffered channel.
func (l *Listener) pump(source InboundProvider) {
	for {
		channel, scope, err := source.Accept(l.ctx, l.svc)
		if channel == nil && err == nil {
			err = CodeEndpointBindingInvalid.Wrap("inbound provider returned no channel")
		}
		if err != nil && channel != nil {
			_ = channel.Close()
			channel = nil
		}
		if errors.Is(err, CodeUnsupportedCapability) {
			return
		}
		select {
		case l.queue <- inboundItem{channel: channel, scope: scope, err: err}:
		case <-l.done:
			if channel != nil {
				_ = channel.Close()
			}
			return
		}
		if err != nil {
			select {
			case <-time.After(inboundErrorBackoff):
			case <-l.done:
				return
			}
		}
	}
}

// Accept waits for an inbound channel whose verified scope satisfies the
// listen policy and whose session binds to the claimed protocol. Rejected
// channels are closed and never exposed; provider errors and a missing
// session provider propagate to the caller.
func (l *Listener) Accept(ctx context.Context) (*Connection, error) {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("listener closed")
	}
	for {
		var item inboundItem
		select {
		case item = <-l.queue:
		case <-l.done:
			return nil, CodeClosed.Wrap("listener closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		l.mu.Lock()
		closed = l.closed
		l.mu.Unlock()
		if closed {
			if item.channel != nil {
				_ = item.channel.Close()
			}
			return nil, CodeClosed.Wrap("listener closed")
		}
		if item.err != nil {
			return nil, item.err
		}
		conn, err := l.admitInbound(ctx, item)
		if err != nil {
			if errors.Is(err, CodeUnsupportedCapability) {
				return nil, err
			}
			continue
		}
		return conn, nil
	}
}

// admitInbound verifies one buffered channel: scope admission, binding
// equality, peer membership, and session protocol. Every failure path closes
// the channel; a missing session provider fails visibly.
func (l *Listener) admitInbound(ctx context.Context, item inboundItem) (*Connection, error) {
	channel, scope := item.channel, item.scope
	nctx := l.admitScope(scope)
	if nctx == nil {
		_ = channel.Close()
		return nil, CodeMembershipDenied.Wrap("inbound scope outside listen policy")
	}
	// The channel's authenticated binding must equal the scope the
	// provider claims it delivered.
	got, key := channel.Binding()
	if got != scope {
		_ = channel.Close()
		return nil, CodeEndpointBindingInvalid.Wrap("channel binding does not match the claimed scope")
	}
	// Credential admission: the peer's presented membership evidence is
	// verified locally before the channel may carry application data.
	// Any denial fails closed and rejects the channel.
	if err := l.svc.realm.verifyPeerMembership(ctx, channel, scope, key, nil, nil); err != nil {
		_ = channel.Close()
		return nil, err
	}
	session, err := l.bindInbound(ctx, channel, scope)
	if err != nil {
		_ = channel.Close()
		return nil, err
	}
	fsm := newConnFSM()
	if err := fsm.Begin(); err != nil {
		_ = channel.Close()
		_ = session.Close()
		return nil, err
	}
	if err := fsm.ContactFound(); err != nil {
		_ = channel.Close()
		_ = session.Close()
		return nil, err
	}
	if _, err := fsm.Commit(scope.Class); err != nil {
		_ = channel.Close()
		_ = session.Close()
		return nil, err
	}
	contextID := nctx.id
	conn := &Connection{
		Channel: channel, Session: session, owner: l.svc, fsm: fsm,
		policyGen: scope.PolicyGen,
		route: RouteInfo{
			Endpoint: scope.Endpoint, Fabric: scope.Fabric, Context: contextID,
			NetworkID: scope.NetworkID, Class: scope.Class,
			Port: scope.Port, Protocol: scope.Protocol, Exposure: scope.Exposure,
		},
	}
	if err := l.svc.registerConn(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// bindInbound opens the endpoint protocol session the authenticated channel
// declares. The negotiated protocol must equal the bound scope's protocol; a
// missing session provider fails rather than fabricating one.
func (l *Listener) bindInbound(ctx context.Context, channel Channel, scope ChannelScope) (Session, error) {
	sessions := l.svc.realm.host.sessionProvider()
	if sessions == nil {
		return nil, CodeUnsupportedCapability.Wrap("no session provider for endpoint protocol")
	}
	session, err := sessions.Open(ctx, channel, ServiceTarget{
		Endpoint: l.svc.endpoint,
		Port:     scope.Port,
		Protocol: scope.Selector,
	})
	if err != nil {
		return nil, err
	}
	if session.Protocol() != scope.Protocol {
		_ = session.Close()
		return nil, CodeEndpointBindingInvalid.Wrap("negotiated protocol outside the bound scope")
	}
	return session, nil
}

// admitScope verifies one delivered scope under a single realm policy
// snapshot — generation, bound fabrics, routing mode, and privacy class are
// read together so a channel can never be admitted by a mix of generations.
// The stored service/listener sets are immutable; only the realm side is
// refreshed here. On success it returns the bound context that carried the
// channel.
func (l *Listener) admitScope(scope ChannelScope) *NetworkContext {
	if scope.Endpoint == (EndpointID{}) || scope.Endpoint != l.svc.endpoint.ID {
		return nil
	}
	if scope.Port != l.svc.spec.Port {
		return nil
	}
	cfg, bound, gen := l.svc.realm.policySnapshot()
	if scope.Realm != cfg.ID || scope.PolicyGen != gen {
		return nil
	}
	var nctx *NetworkContext
	for _, b := range bound {
		if b.fabric.ID == scope.Fabric {
			nctx = b
			break
		}
	}
	// The claimed fabric must be a context the realm currently binds, and its
	// wire network number must equal the bound descriptor's — the same check
	// the outbound path applies.
	if nctx == nil || nctx.fabric.NetworkID != scope.NetworkID {
		return nil
	}
	if _, ok := routingClasses(cfg.Routing)[scope.Class]; !ok {
		return nil
	}
	if _, ok := l.protocols[scope.Protocol]; !ok {
		return nil
	}
	if _, ok := l.classes[scope.Class]; !ok {
		return nil
	}
	// private_confined and i2p_compatible are disjoint requirements; if the
	// replacement made the realm's class incompatible with the stored
	// service/listener merge, the impossible intersection admits nothing.
	confined := cfg.Privacy == PrivacyPrivateConfined || l.privacy == PrivacyPrivateConfined
	i2p := cfg.Privacy == PrivacyI2PCompatible || l.privacy == PrivacyI2PCompatible
	if confined && i2p {
		return nil
	}
	privacy := PrivacyExplicitDirect
	switch {
	case confined:
		privacy = PrivacyPrivateConfined
	case i2p:
		privacy = PrivacyI2PCompatible
	}
	if !privacyAdmits(privacy, RouteCandidate{Class: scope.Class, Fabric: scope.Fabric}, publicFabricSet(bound)) {
		return nil
	}
	return nctx
}

// Close stops the listener: the pump is canceled, and every buffered or
// in-handoff channel is closed.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		l.cancel()
		close(l.done)
		<-l.pumpDone
		for {
			select {
			case item := <-l.queue:
				if item.channel != nil {
					_ = item.channel.Close()
				}
			default:
				l.svc.mu.Lock()
				delete(l.svc.listeners, l)
				l.svc.mu.Unlock()
				return
			}
		}
	})
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	if l.svc != nil {
		return Addr{Endpoint: l.svc.Endpoint().ID, Port: l.svc.Port()}
	}
	return Addr{}
}

// NetListener returns a Go standard net.Listener adapter for this Listener.
func (l *Listener) NetListener() net.Listener {
	return &netListenerAdapter{l: l}
}

type netListenerAdapter struct {
	l *Listener
}

var _ net.Listener = (*netListenerAdapter)(nil)

func (n *netListenerAdapter) Accept() (net.Conn, error) {
	return n.l.Accept(context.Background())
}

func (n *netListenerAdapter) Close() error {
	return n.l.Close()
}

func (n *netListenerAdapter) Addr() net.Addr {
	return n.l.Addr()
}

func (h *Host) inboundProviders() []InboundProvider {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []InboundProvider
	for _, p := range h.providers.transports {
		if in, ok := p.(InboundProvider); ok {
			out = append(out, in)
		}
	}
	return out
}

func (h *Host) inboundProvider() (InboundProvider, bool) {
	providers := h.inboundProviders()
	if len(providers) == 0 {
		return nil, false
	}
	return providers[0], true
}
