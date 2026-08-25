package ivnp

import (
	"context"
	"net"
	"sync"
)

type localStreamNetwork struct {
	mu        sync.Mutex
	listeners map[string]*localListener
}

func (n *localStreamNetwork) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	n.mu.Lock()
	l := n.listeners[address]
	n.mu.Unlock()
	if l == nil {
		return nil, ErrAddressUnavailable
	}
	if !l.beginDial() {
		return nil, net.ErrClosed
	}
	defer l.dials.Done()

	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	case <-l.closed:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	}
}

// NewLocalStreamNetwork creates an in-process zero-hop StreamNetwork. It is
// useful for embedded services and tests; it does not claim remote I2P routing.
func NewLocalStreamNetwork() StreamNetwork {
	return &localStreamNetwork{listeners: make(map[string]*localListener)}
}
func (n *localStreamNetwork) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	if address == "" {
		return nil, ErrAddressInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := n.listeners[address]; ok {
		return nil, ErrAddressInUse
	}
	l := &localListener{network: n, address: address, incoming: make(chan net.Conn, 64), closed: make(chan struct{})}
	n.listeners[address] = l
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-l.closed:
		}
	}()
	return l, nil
}

type localListener struct {
	network  *localStreamNetwork
	address  string
	incoming chan net.Conn
	closed   chan struct{}

	mu      sync.Mutex
	closing bool
	dials   sync.WaitGroup
	once    sync.Once
}

func (l *localListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		l.mu.Lock()
		if l.closing {
			l.mu.Unlock()
			_ = c.Close()
			return nil, net.ErrClosed
		}
		l.mu.Unlock()
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *localListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closing = true
		l.mu.Unlock()

		l.network.mu.Lock()
		if l.network.listeners[l.address] == l {
			delete(l.network.listeners, l.address)
		}
		l.network.mu.Unlock()
		close(l.closed)
		l.dials.Wait()
		for {
			select {
			case c := <-l.incoming:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}
func (l *localListener) beginDial() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	l.dials.Add(1)
	return true
}

func (l *localListener) Addr() net.Addr { return localAddr(l.address) }

type localAddr string

func (a localAddr) Network() string { return "i2p" }
func (a localAddr) String() string  { return string(a) }
