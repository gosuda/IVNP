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
	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	case <-l.closed:
		client.Close()
		server.Close()
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
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.listeners[address]; ok {
		return nil, ErrAddressInUse
	}
	l := &localListener{network: n, address: address, incoming: make(chan net.Conn, 64), closed: make(chan struct{})}
	n.listeners[address] = l
	go func() { <-ctx.Done(); _ = l.Close() }()
	return l, nil
}

type localListener struct {
	network  *localStreamNetwork
	address  string
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func (l *localListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *localListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.network.mu.Lock()
		delete(l.network.listeners, l.address)
		l.network.mu.Unlock()
		for {
			select {
			case c := <-l.incoming:
				c.Close()
			default:
				return
			}
		}
	})
	return nil
}
func (l *localListener) Addr() net.Addr { return localAddr(l.address) }

type localAddr string

func (a localAddr) Network() string { return "i2p" }
func (a localAddr) String() string  { return string(a) }
