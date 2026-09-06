package router

import (
	"context"
	"net"
)

// Endpoint identifies a socket endpoint. SocketRuntime implementations define
// how Network and Address are interpreted; NativeSocketRuntime passes both
// directly to the Go networking stack.
type Endpoint struct {
	Network string
	Address string
}

// SocketRuntime supplies the IP-facing sockets used by transport managers.
// I2P streaming sessions are provided by the streaming/tunnel package.
type SocketRuntime interface {
	ListenStream(context.Context, Endpoint) (net.Listener, error)
	DialStream(context.Context, Endpoint) (net.Conn, error)
	ListenUDP(context.Context, Endpoint) (*net.UDPConn, error)
}

// NativeSocketRuntime maps Endpoints to the standard library networking APIs.
// Its zero value uses the zero values of net.Dialer and net.ListenConfig.
type NativeSocketRuntime struct {
	Dialer       net.Dialer
	ListenConfig net.ListenConfig
}

func (n *NativeSocketRuntime) ListenStream(ctx context.Context, endpoint Endpoint) (net.Listener, error) {
	return n.ListenConfig.Listen(ctx, endpoint.Network, endpoint.Address)
}

func (n *NativeSocketRuntime) DialStream(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	return n.Dialer.DialContext(ctx, endpoint.Network, endpoint.Address)
}

func (n *NativeSocketRuntime) ListenUDP(ctx context.Context, endpoint Endpoint) (*net.UDPConn, error) {
	packet, err := n.ListenConfig.ListenPacket(ctx, endpoint.Network, endpoint.Address)
	if err != nil {
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, net.ErrClosed
	}
	return udp, nil
}

var _ SocketRuntime = (*NativeSocketRuntime)(nil)
