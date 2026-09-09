package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"gosuda.org/ivnp/interfaces/destination"
)

type Dialer struct {
	Destination *Destination
	Timeout     time.Duration
	Deadline    time.Time
	LocalPort   uint16
}

type ListenConfig struct {
	Destination *Destination
}

func streamNetwork(network string) error {
	switch network {
	case "i2p", "i2p-stream", "tcp":
		return nil
	default:
		return ErrUnsupportedNetwork
	}
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
	if err := streamNetwork(network); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	if d.Timeout < 0 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: invalidConfig("Dialer.Timeout")}
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
		backend, ok := owner.endpoint.(destination.StreamDestinationEndpoint)
		if !ok {
			err = ErrUnsupportedIdentity
		} else {
			connection, err = backend.DialStream(setup, target.String(), d.LocalPort)
		}
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
	if err := streamNetwork(network); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	local, err := parseBindAddress(d.hash, address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	backend, ok := d.endpoint.(destination.StreamDestinationEndpoint)
	if !ok {
		return nil, &net.OpError{Op: "listen", Net: network, Addr: local, Err: ErrUnsupportedIdentity}
	}
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	listener, err := backend.ListenStream(setup, local.String())
	if err == nil {
		err = setup.Err()
	}
	if err != nil {
		if listener != nil {
			err = errors.Join(err, listener.Close())
		}
		if d.ctx.Err() != nil {
			err = errors.Join(net.ErrClosed, err)
		}
		return nil, &net.OpError{Op: "listen", Net: network, Addr: local, Err: err}
	}
	bound, err := ParseAddr(listener.Addr().String())
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	wrapped := &streamListener{Listener: listener, owner: d, addr: bound, network: network}
	if err = d.registerResource(wrapped); err != nil {
		return nil, errors.Join(err, wrapped.Close())
	}
	return wrapped, nil
}

func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (*PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lc.Destination == nil {
		return nil, ErrDestinationRequired
	}
	return lc.Destination.ListenPacketContext(ctx, network, address)
}

func (lc *ListenConfig) ListenUnauthPacket(ctx context.Context, network, address string) (*UnauthPacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lc.Destination == nil {
		return nil, ErrDestinationRequired
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
