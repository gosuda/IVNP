package ivnp

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/interfaces/destination"
)

const (
	MaxSendDatagramSize    = 32768
	MaxReceiveDatagramSize = 62690
)

type PacketConn struct{ socket *packetSocket }
type UnauthPacketConn struct{ socket *packetSocket }
type UnauthPacket struct {
	ClaimedSource    Hash
	HasClaimedSource bool
	FromPort         uint16
}

var _ net.PacketConn = (*PacketConn)(nil)

type packetSocket struct {
	owner                       *Destination
	network                     string
	protocol                    uint8
	local                       Addr
	maxPayload                  int
	subscription                destination.MessageSubscription
	mu                          sync.Mutex
	closed                      bool
	closeDone                   chan struct{}
	closeErr                    error
	readDeadline, writeDeadline time.Time
	operations                  map[*packetOperation]struct{}
	active                      sync.WaitGroup
}

func (d *Destination) ListenPacket(network, address string) (*PacketConn, error) {
	return d.ListenPacketContext(context.Background(), network, address)
}
func (d *Destination) ListenPacketContext(ctx context.Context, network, address string) (*PacketConn, error) {
	var protocol uint8
	switch network {
	case "i2p", "i2p-datagram2":
		protocol = 19
	case "i2p-datagram1":
		protocol = 17
	}
	s, err := d.listenPacket(ctx, network, address, protocol)
	if err != nil {
		return nil, err
	}
	return &PacketConn{socket: s}, nil
}
func (d *Destination) ListenUnauthPacket(network, address string) (*UnauthPacketConn, error) {
	return d.ListenUnauthPacketContext(context.Background(), network, address)
}
func (d *Destination) ListenUnauthPacketContext(ctx context.Context, network, address string) (*UnauthPacketConn, error) {
	var protocol uint8
	switch network {
	case "i2p-datagram3":
		protocol = 20
	case "i2p-raw":
		protocol = 18
	}
	s, err := d.listenPacket(ctx, network, address, protocol)
	if err != nil {
		return nil, err
	}
	return &UnauthPacketConn{socket: s}, nil
}
func (d *Destination) listenPacket(ctx context.Context, network, address string, protocol uint8) (_ *packetSocket, err error) {
	if ctx == nil {
		panic("nil context")
	}
	var local Addr
	defer func() {
		if err != nil {
			if d.ctx.Err() != nil {
				err = errors.Join(net.ErrClosed, err)
			}
			err = &net.OpError{Op: "listen", Net: network, Addr: local, Err: err}
		}
	}()
	if err = d.beginOperation(); err != nil {
		return nil, err
	}
	defer d.endOperation()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if protocol == 0 {
		return nil, ErrUnsupportedNetwork
	}
	local, err = parseBindAddress(d.hash, address)
	if err != nil {
		return nil, err
	}
	bounded, ok := d.endpoint.(destination.BoundedDestinationEndpoint)
	if !ok {
		return nil, ErrUnsupportedIdentity
	}
	maxPayload := MaxSendDatagramSize
	if protocol == 20 {
		maxPayload -= 34
	}
	if protocol == 17 || protocol == 19 {
		sizing, ok := d.endpoint.(destination.DatagramPayloadEndpoint)
		if !ok {
			return nil, ErrUnsupportedIdentity
		}
		maxPayload, err = sizing.DatagramMaxPayload(protocol)
		if err != nil {
			return nil, errors.Join(ErrUnsupportedIdentity, err)
		}
		if maxPayload < 0 || maxPayload > MaxSendDatagramSize {
			return nil, ErrUnsupportedIdentity
		}
	}
	if protocol == 19 || protocol == 20 {
		if _, ok := d.endpoint.(destination.ModernDatagramEndpoint); !ok {
			return nil, ErrUnsupportedIdentity
		}
	}
	s := &packetSocket{owner: d, network: network, protocol: protocol, local: local, maxPayload: maxPayload, closeDone: make(chan struct{}), operations: make(map[*packetOperation]struct{})}
	first, last := int(local.Port), int(local.Port)
	if first == 0 {
		first, last = 49152, 65535
	}
	for port := first; port <= last; port++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = d.checkOpen(); err != nil {
			return nil, err
		}
		s.subscription, err = bounded.SubscribeBounded(destination.DestinationRoute{Protocol: protocol, ToPort: uint16(port)}, d.packetQueue.MaxPackets, d.packetQueue.MaxBytes, d.owner.packetBudget)
		if err == nil {
			s.local.Port = uint16(port)
			break
		}
		if !errors.Is(err, dataplane.RouterErrDestinationRoute) {
			return nil, err
		}
		if local.Port != 0 {
			return nil, ErrAddressInUse
		}
	}
	if s.subscription == nil {
		return nil, ErrNoPortsAvailable
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, s.subscription.Close())
	}
	if err = d.registerResource(s); err != nil {
		return nil, errors.Join(err, s.subscription.Close())
	}
	return s, nil
}

func (c *PacketConn) LocalAddr() net.Addr       { return c.socket.local }
func (c *UnauthPacketConn) LocalAddr() Addr     { return c.socket.local }
func (c *PacketConn) MaxPayloadSize() int       { return c.socket.maxPayload }
func (c *UnauthPacketConn) MaxPayloadSize() int { return c.socket.maxPayload }
func (c *PacketConn) Close() error              { return c.socket.Close() }
func (c *UnauthPacketConn) Close() error        { return c.socket.Close() }
func (c *PacketConn) SetDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetBothDeadlines)
}
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetReadDeadline)
}
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetWriteDeadline)
}
func (c *UnauthPacketConn) SetDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetBothDeadlines)
}
func (c *UnauthPacketConn) SetReadDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetReadDeadline)
}
func (c *UnauthPacketConn) SetWriteDeadline(t time.Time) error {
	return c.socket.setDeadline(t, packetWriteDeadline)
}

func (s *packetSocket) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.closeDone
		return s.closeErr
	}
	s.closed = true
	for op := range s.operations {
		op.cancel(net.ErrClosed)
		if op.timer != nil {
			op.timer.Stop()
		}
	}
	s.mu.Unlock()
	err := s.subscription.Close()
	s.active.Wait()
	s.owner.unregisterResource(s)
	s.closeErr = err
	close(s.closeDone)
	return err
}

type packetByteBudget struct {
	mu          sync.Mutex
	used, limit int64
}

func newPacketBudget(limit int64) destination.ByteBudget { return &packetByteBudget{limit: limit} }
func (b *packetByteBudget) TryReserve(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || int64(size) > b.limit-b.used {
		return false
	}
	b.used += int64(size)
	return true
}
func (b *packetByteBudget) Release(size int) { b.mu.Lock(); b.used -= int64(size); b.mu.Unlock() }
