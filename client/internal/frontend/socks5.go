package frontend

import (
	"bufio"
	"context"
	"io"
	"net"
	"time"

	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/internal/ingress"
)

const defaultSOCKS5Address = "127.0.0.1:4447"

// SOCKS5Config configures a local SOCKS5 CONNECT proxy. Only no-authentication
// domain-name CONNECT requests to I2P destinations are accepted.
type SOCKS5Config struct {
	Network           stream.StreamNetwork
	ListenAddress     string
	AllowRemote       bool
	MaxConnections    int
	MaxHandshakeBytes int
	HandshakeTimeout  time.Duration
	DialTimeout       time.Duration
	Listen            func(context.Context, string, string) (net.Listener, error)
	PanicReporter     ingress.Reporter
}

// SOCKS5Proxy forwards SOCKS5 domain CONNECT requests to I2P.
type SOCKS5Proxy struct {
	config SOCKS5Config
	server server
}

func NewSOCKS5Proxy(config SOCKS5Config) (*SOCKS5Proxy, error) {
	if config.Network == nil {
		return nil, ErrInvalidConfig
	}
	if config.ListenAddress == "" {
		config.ListenAddress = defaultSOCKS5Address
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxHandshakeBytes == 0 {
		config.MaxHandshakeBytes = 1024
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 30 * time.Second
	}
	if config.MaxConnections < 1 || config.MaxHandshakeBytes < minSOCKS5HandshakeBytes || config.HandshakeTimeout < 1 || config.DialTimeout < 1 {
		return nil, ErrInvalidConfig
	}
	return &SOCKS5Proxy{config: config}, nil
}

func (p *SOCKS5Proxy) Start(ctx context.Context) error {
	if p == nil {
		return net.ErrClosed
	}
	return p.server.start(ctx, p.config.ListenAddress, p.config.AllowRemote, p.config.MaxConnections, p.config.Listen, p.serve)
}

func (p *SOCKS5Proxy) Close() error {
	if p == nil {
		return nil
	}
	return p.server.close()
}

func (p *SOCKS5Proxy) Wait() error {
	if p == nil {
		return net.ErrClosed
	}
	return p.server.wait()
}

func (p *SOCKS5Proxy) Addr() net.Addr {
	if p == nil {
		return nil
	}
	return p.server.addr()
}

func (p *SOCKS5Proxy) serve(listener net.Listener) {
	var delay time.Duration
	for {
		connection, err := listener.Accept()
		if err != nil {
			if temporary, ok := err.(interface{ Temporary() bool }); !ok || !temporary.Temporary() {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
				if delay > time.Second {
					delay = time.Second
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-p.server.runningContext().Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			continue
		}
		delay = 0
		p.server.goServeActivity(func() {
			p.serveConnection(connection)
		})
	}
}
func (p *SOCKS5Proxy) serveConnection(connection net.Conn) {
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = ingress.Report(recovered, p.config.PanicReporter, ingress.BoundaryClientConnection, connection.RemoteAddr())
		}
	}()
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(p.config.HandshakeTimeout)); err != nil {
		return
	}
	reader := bufio.NewReader(connection)
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 || int(greeting[1])+2 > p.config.MaxHandshakeBytes {
		return
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		p.reply(connection, 0xff)
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return
	}

	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	if request[1] != 1 {
		p.reply(connection, 7)
		return
	}
	if request[3] != 3 {
		p.reply(connection, 8)
		return
	}
	var length [1]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil || int(length[0])+7 > p.config.MaxHandshakeBytes || length[0] == 0 {
		return
	}
	host := make([]byte, length[0])
	if _, err := io.ReadFull(reader, host); err != nil {
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	address, err := targetAddress(string(host), port)
	if err != nil {
		p.reply(connection, 4)
		return
	}

	ctx, cancel := context.WithTimeout(p.server.runningContext(), p.config.DialTimeout)
	defer cancel()
	if err := connection.SetReadDeadline(time.Now().Add(p.config.DialTimeout)); err != nil {
		return
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		if _, err := reader.Peek(1); err != nil {
			cancel()
		}
	}()
	outbound, err := p.config.Network.DialI2P(ctx, address)
	_ = connection.SetReadDeadline(time.Now())
	<-watchDone
	if resetErr := connection.SetDeadline(time.Time{}); resetErr != nil {
		if outbound != nil {
			_ = outbound.Close()
		}
		return
	}
	if err != nil {
		p.reply(connection, 4)
		return
	}
	defer outbound.Close()
	if !p.reply(connection, 0) {
		return
	}
	relayConnections(connection, outbound, reader)
}

func (p *SOCKS5Proxy) reply(connection net.Conn, code byte) bool {
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return false
	}
	_, err := connection.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}

const minSOCKS5HandshakeBytes = len("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p") + 7
