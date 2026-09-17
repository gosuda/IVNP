package router

import (
	"context"
	"net"

	"gosuda.org/ivnp/dataplane/internal/transport/ssu2"
)

// Endpoint identifies a socket endpoint. SocketRuntime implementations define
// how Network and Address are interpreted; NativeSocketRuntime passes both
// directly to the Go networking stack.
type Endpoint struct {
	Network string
	Address string
}

// UDPSocket is the bound-UDP-socket surface transports consume. It is the
// ssu2 package contract so the batch I/O wrapper stays usable without a
// kernel socket.
type UDPSocket = ssu2.UDPSocket

// SocketRuntime supplies the IP-facing sockets used by transport managers.
// I2P streaming sessions are provided by the streaming/tunnel package.
// Implementations may return virtual sockets: ListenUDP only requires the
// UDPSocket surface, and transport dials use DialStream.
type SocketRuntime interface {
	ListenStream(context.Context, Endpoint) (net.Listener, error)
	DialStream(context.Context, Endpoint) (net.Conn, error)
	ListenUDP(context.Context, Endpoint) (UDPSocket, error)
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

func (n *NativeSocketRuntime) ListenUDP(ctx context.Context, endpoint Endpoint) (UDPSocket, error) {
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
