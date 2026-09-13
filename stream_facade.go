package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/interfaces/destination"
)

// dialHedgeDelay staggers each subsequent network leg of an unqualified dial.
// The first bound network starts immediately; every further leg starts only
// after the previous one had this much head start, so a fast dedicated network
// wins without delaying a slow public fallback beyond one hedge interval.
const dialHedgeDelay = 250 * time.Millisecond

// namedEndpoint pairs a bound network name with its destination endpoint.
type namedEndpoint struct {
	name string
	ep   destination.DestinationEndpoint
}

// dialResult is one raced leg's outcome; a non-nil conn must be either the
// winner or closed by the caller.
type dialResult struct {
	conn net.Conn
	err  error
}

type Dialer struct {
	Destination *Destination
	Timeout     time.Duration
	Deadline    time.Time
	LocalPort   uint16
}

type ListenConfig struct {
	Destination *Destination
}

// streamEndpoints resolves a stream network name to the bound endpoints it
// addresses. "tcp"/"stream" and "ivnp" select every bound network in
// preference order — the dial is a happy-eyeballs race. A configured network
// name (with an optional "-stream" suffix) selects exactly that network.
func (d *Destination) streamEndpoints(network string) ([]namedEndpoint, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6", "stream", "ivnp", "ivnp-stream":
		return d.allEndpoints(), nil
	default:
		name := strings.TrimSuffix(network, "-stream")
		if ep := d.endpoints[name]; ep != nil {
			return []namedEndpoint{{name: name, ep: ep}}, nil
		}
		return nil, ErrUnsupportedNetwork
	}
}

func (d *Destination) allEndpoints() []namedEndpoint {
	eps := make([]namedEndpoint, 0, len(d.nets))
	for _, name := range d.nets {
		eps = append(eps, namedEndpoint{name: name, ep: d.endpoints[name]})
	}
	return eps
}

func (d *Destination) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Destination) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&Dialer{Destination: d}).DialContext(ctx, network, address)
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	if d.Destination == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: ErrDestinationRequired}
	}
	owner := d.Destination
	if err := owner.beginOperation(); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	defer owner.endOperation()
	if d.Timeout < 0 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: invalidConfig("Dialer.Timeout")}
	}
	eps, err := owner.streamEndpoints(network)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	deadline := d.Deadline
	if d.Timeout > 0 {
		limit := time.Now().Add(d.Timeout)
		if deadline.IsZero() || limit.Before(deadline) {
			deadline = limit
		}
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(owner.ctx, cancel)
	defer func() { stop(); cancel() }()
	if parent, ok := setup.Deadline(); !deadline.IsZero() && (!ok || deadline.Before(parent)) {
		limited, expire := context.WithDeadlineCause(setup, deadline, os.ErrDeadlineExceeded)
		defer expire()
		setup = limited
	}
	target, err := resolveAddr(setup, owner.owner.resolver, address)
	if err == nil && (target.Hash == (Hash{}) || target.Port == 0) {
		err = ErrAddressInvalid
	}
	if err == nil {
		err = setup.Err()
	}
	var connection net.Conn
	if err == nil {
		connection, err = dialEndpoints(setup, eps, target.String(), d.LocalPort)
	}
	if err == nil {
		err = setup.Err()
	}
	if err != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		if errors.Is(err, context.DeadlineExceeded) && errors.Is(context.Cause(setup), os.ErrDeadlineExceeded) {
			err = os.ErrDeadlineExceeded
		}
		if owner.ctx.Err() != nil {
			err = errors.Join(net.ErrClosed, err)
		}
		return nil, &net.OpError{Op: "dial", Net: network, Addr: target, Err: err}
	}
	wrapped, err := owner.wrapStream(connection, network)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: target, Err: err}
	}
	return wrapped, nil
}

// dialEndpoints dials the target on every given endpoint in order, staggering
// each leg by dialHedgeDelay. The first successful leg wins; losing legs are
// canceled and any late-arriving connection they produced is closed.
func dialEndpoints(setup context.Context, eps []namedEndpoint, target string, localPort uint16) (net.Conn, error) {
	if len(eps) == 1 {
		backend, ok := eps[0].ep.(destination.StreamDestinationEndpoint)
		if !ok {
			return nil, ErrUnsupportedIdentity
		}
		return backend.DialStream(setup, target, localPort)
	}
	results := make(chan dialResult, len(eps))
	race, cancel := context.WithCancel(setup)
	defer cancel()
	var won atomic.Bool
	for i := range eps {
		go func(i int) {
			if i > 0 {
				timer := time.NewTimer(dialHedgeDelay * time.Duration(i))
				select {
				case <-timer.C:
				case <-race.Done():
					timer.Stop()
					results <- dialResult{err: race.Err()}
					return
				}
			}
			backend, ok := eps[i].ep.(destination.StreamDestinationEndpoint)
			var conn net.Conn
			var err error
			if !ok {
				err = ErrUnsupportedIdentity
			} else {
				conn, err = backend.DialStream(race, target, localPort)
			}
			if err == nil && won.Load() {
				err = conn.Close()
				conn = nil
			}
			results <- dialResult{conn: conn, err: err}
		}(i)
	}
	pending := len(eps)
	var errs []error
	for pending > 0 {
		r := <-results
		pending--
		if r.err == nil && !won.Swap(true) {
			cancel()
			go drainDialResults(results, pending)
			return r.conn, nil
		}
		if r.conn != nil {
			_ = r.conn.Close()
		}
		errs = append(errs, r.err)
	}
	return nil, errors.Join(errs...)
}

// drainDialResults closes connections produced by legs that lost the race.
func drainDialResults(results <-chan dialResult, n int) {
	for i := 0; i < n; i++ {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

func (d *Destination) Listen(network, address string) (net.Listener, error) {
	return d.ListenContext(context.Background(), network, address)
}

func (d *Destination) ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	return (&ListenConfig{Destination: d}).Listen(ctx, network, address)
}

func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	if lc.Destination == nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: ErrDestinationRequired}
	}
	d := lc.Destination
	if err := d.beginOperation(); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	defer d.endOperation()
	eps, err := d.streamEndpoints(network)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	local, err := parseBindAddress(d.hash, address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	subs := make([]*streamListener, 0, len(eps))
	for _, ne := range eps {
		backend, ok := ne.ep.(destination.StreamDestinationEndpoint)
		if !ok {
			err = ErrUnsupportedIdentity
			break
		}
		var listener net.Listener
		listener, err = backend.ListenStream(setup, local.String())
		if err == nil {
			err = setup.Err()
		}
		if err != nil {
			break
		}
		bound, parseErr := ParseAddr(listener.Addr().String())
		if parseErr != nil {
			err = errors.Join(parseErr, listener.Close())
			break
		}
		subs = append(subs, &streamListener{Listener: listener, owner: d, addr: bound, network: ne.name})
	}
	if err != nil {
		for _, sub := range subs {
			err = errors.Join(err, sub.Listener.Close())
		}
		if d.ctx.Err() != nil {
			err = errors.Join(net.ErrClosed, err)
		}
		return nil, &net.OpError{Op: "listen", Net: network, Addr: local, Err: err}
	}
	if len(subs) == 1 {
		wrapped := subs[0]
		wrapped.network = network
		if err = d.registerResource(wrapped); err != nil {
			return nil, errors.Join(err, wrapped.Close())
		}
		return wrapped, nil
	}
	merged := newMergedListener(d, subs)
	if err = d.registerResource(merged); err != nil {
		return nil, errors.Join(err, merged.Close())
	}
	return merged, nil
}

func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (*PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	if lc.Destination == nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: ErrDestinationRequired}
	}
	return lc.Destination.ListenPacketContext(ctx, network, address)
}

func (lc *ListenConfig) ListenUnauthPacket(ctx context.Context, network, address string) (*UnauthPacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	if lc.Destination == nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: ErrDestinationRequired}
	}
	return lc.Destination.ListenUnauthPacketContext(ctx, network, address)
}

type streamConn struct {
	net.Conn
	owner   *Destination
	local   Addr
	remote  Addr
	network string
	once    sync.Once
	err     error
}

func (d *Destination) wrapStream(connection net.Conn, network string) (net.Conn, error) {
	local, err := ParseAddr(connection.LocalAddr().String())
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	remote, err := ParseAddr(connection.RemoteAddr().String())
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	wrapped := &streamConn{Conn: connection, owner: d, local: local, remote: remote, network: network}
	if err = d.registerResource(wrapped); err != nil {
		return nil, errors.Join(err, wrapped.Close())
	}
	return wrapped, nil
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && err != io.EOF {
		return n, &net.OpError{Op: "read", Net: c.network, Source: c.local, Addr: c.remote, Err: err}
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		return n, &net.OpError{Op: "write", Net: c.network, Source: c.local, Addr: c.remote, Err: err}
	}
	return n, nil
}

func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.unregisterResource(c)
	})
	return c.err
}

type streamListener struct {
	net.Listener
	owner   *Destination
	addr    Addr
	network string
	once    sync.Once
	err     error
}

func (l *streamListener) Addr() net.Addr { return l.addr }

func (l *streamListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.owner.wrapStream(connection, l.network)
}

func (l *streamListener) Close() error {
	l.once.Do(func() {
		l.err = l.Listener.Close()
		l.owner.unregisterResource(l)
	})
	return l.err
}

// mergedListener multiplexes Accept across one listener per bound network so
// an unqualified Listen serves every network the destination is bound to.
type mergedListener struct {
	owner *Destination
	subs  []*streamListener
	addr  Addr
	ch    chan acceptResult
	done  chan struct{}
	alive atomic.Int32
	once  sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newMergedListener(owner *Destination, subs []*streamListener) *mergedListener {
	l := &mergedListener{
		owner: owner, subs: subs, addr: subs[0].addr,
		ch:   make(chan acceptResult, len(subs)),
		done: make(chan struct{}),
	}
	l.alive.Store(int32(len(subs)))
	for _, sub := range subs {
		go l.feed(sub)
	}
	return l
}

func (l *mergedListener) feed(sub *streamListener) {
	defer func() {
		if l.alive.Add(-1) == 0 {
			close(l.ch)
		}
	}()
	for {
		conn, err := sub.Accept()
		if err != nil {
			select {
			case l.ch <- acceptResult{err: err}:
			case <-l.done:
			}
			return
		}
		select {
		case l.ch <- acceptResult{conn: conn}:
		case <-l.done:
			_ = conn.Close()
			return
		}
	}
}

func (l *mergedListener) Accept() (net.Conn, error) {
	r, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return r.conn, r.err
}

func (l *mergedListener) Addr() net.Addr { return l.addr }

func (l *mergedListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		for _, sub := range l.subs {
			_ = sub.Listener.Close()
		}
		l.owner.unregisterResource(l)
	})
	return nil
}
