//go:build dst || synctest

package simnet

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type udpDelivery struct {
	from netip.AddrPort
	data []byte
}

// UDPConn is a simulated bound UDP socket. It satisfies net.PacketConn plus
// the address-aware methods the SSU2 transport's UDPSocket contract requires.
// Receives queue into a bounded channel; overflow drops are counted as
// EventQueueDrop.
type UDPConn struct {
	net  *Network
	host *Host
	addr netip.AddrPort
	in   chan udpDelivery

	closed chan struct{}
	once   sync.Once
	rd, wd simDeadline
}

// ListenUDP binds a virtual UDP socket on the host. An unspecified address
// binds the host's address; a zero port allocates the next free ephemeral
// port starting at 32768.
func (h *Host) ListenUDP(ap netip.AddrPort) (*UDPConn, error) {
	n := h.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrClosed
	}
	addr, err := h.bindLocked(ap, n.udp)
	if err != nil {
		return nil, err
	}
	c := &UDPConn{
		net: n, host: h, addr: addr,
		in: make(chan udpDelivery, n.cfg.UDPQueueLimit), closed: make(chan struct{}),
		rd: newSimDeadline(), wd: newSimDeadline(),
	}
	n.udp[addr] = c
	return c, nil
}

// bindLocked normalizes a bind address and claims the port in table. For a
// zero port it allocates from the host's ephemeral range.
func (h *Host) bindLocked[V any](ap netip.AddrPort, table map[netip.AddrPort]V) (netip.AddrPort, error) {
	addr := ap.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		addr = h.addr
	}
	if addr != h.addr {
		return netip.AddrPort{}, ErrNotLocal
	}
	port := ap.Port()
	if port == 0 {
		for range 32768 {
			candidate := h.nextPort
			h.nextPort++
			if h.nextPort < 32768 {
				h.nextPort = 32768
			}
			if _, used := table[netip.AddrPortFrom(addr, candidate)]; !used {
				port = candidate
				break
			}
		}
		if port == 0 {
			return netip.AddrPort{}, ErrBound
		}
	}
	bound := netip.AddrPortFrom(addr, port)
	if _, used := table[bound]; used {
		return netip.AddrPort{}, ErrBound
	}
	return bound, nil
}

// LocalAddr returns the socket's bound address.
func (c *UDPConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.addr)
}

// AddrPort returns the bound address as netip.AddrPort.
func (c *UDPConn) AddrPort() netip.AddrPort { return c.addr }

func (c *UDPConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// deliver enqueues one datagram, dropping when the receive queue is full or
// the socket is closed. Called by the scheduler.
func (c *UDPConn) deliver(from netip.AddrPort, data []byte, duplicate bool) {
	select {
	case <-c.closed:
		return
	default:
	}
	kind := EventDeliver
	if duplicate {
		kind = EventDuplicate
	}
	select {
	case c.in <- udpDelivery{from: from, data: data}:
		c.net.record(kind, ProtoUDP, from, c.addr, len(data))
	default:
		c.net.record(EventQueueDrop, ProtoUDP, from, c.addr, len(data))
	}
}

// ReadFromUDPAddrPort receives the next datagram into b.
func (c *UDPConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, _, _, addr, err := c.ReadMsgUDPAddrPort(b, nil)
	return n, addr, err
}

// ReadFromUDP receives the next datagram into b.
func (c *UDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(addr), nil
}

// ReadFrom receives the next datagram into b.
func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadFromUDP(b)
}

// ReadMsgUDPAddrPort receives the next datagram. Out-of-band data is not
// simulated: oob is ignored and oobn and flags are always zero. The read
// blocks until a datagram arrives, the read deadline passes, or the socket
// closes.
func (c *UDPConn) ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	for {
		if c.isClosed() {
			return 0, 0, 0, netip.AddrPort{}, ErrClosed
		}
		select {
		case d := <-c.in:
			return copy(b, d.data), 0, 0, d.from, nil
		default:
		}
		timer, gen, expired := c.rd.arm(c.net.now())
		if expired {
			return 0, 0, 0, netip.AddrPort{}, timeoutError{op: "read"}
		}
		var deadline <-chan time.Time
		if timer != nil {
			deadline = timer.C
		}
		select {
		case d := <-c.in:
			stopTimer(timer)
			return copy(b, d.data), 0, 0, d.from, nil
		case <-c.closed:
			stopTimer(timer)
			return 0, 0, 0, netip.AddrPort{}, ErrClosed
		case <-gen:
			stopTimer(timer)
			continue
		case <-deadline:
			return 0, 0, 0, netip.AddrPort{}, timeoutError{op: "read"}
		}
	}
}

// WriteToUDPAddrPort transmits one datagram through the link to addr.
// Delivery is scheduled; the sender always observes success. A passed write
// deadline still reports a timeout, mirroring net.UDPConn semantics.
func (c *UDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c.isClosed() {
		return 0, ErrClosed
	}
	timer, _, expired := c.wd.arm(c.net.now())
	stopTimer(timer)
	if expired {
		return 0, timeoutError{op: "write"}
	}
	if !addr.Addr().IsValid() {
		return 0, ErrNoRoute
	}
	c.net.sendDatagram(c.addr, addr, b)
	return len(b), nil
}

// WriteToUDP transmits one datagram to addr.
func (c *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if addr == nil {
		return 0, ErrNoRoute
	}
	return c.WriteToUDPAddrPort(b, addr.AddrPort())
}

// WriteTo transmits one datagram to addr.
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil {
		return 0, ErrNoRoute
	}
	return c.WriteToUDPAddrPort(b, udp.AddrPort())
}

// Close unblocks all operations and releases the bound port.
func (c *UDPConn) Close() error {
	c.once.Do(func() {
		c.net.mu.Lock()
		delete(c.net.udp, c.addr)
		c.net.mu.Unlock()
		close(c.closed)
	})
	return nil
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
