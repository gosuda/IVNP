//go:build dst || synctest

package simnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// TCPListener is a simulated stream listener. Pending connections occupy
// backlog slots until Accept; a full backlog refuses new dials.
type TCPListener struct {
	net  *Network
	host *Host
	addr netip.AddrPort

	pending chan *TCPConn
	closed  chan struct{}
	once    sync.Once
}

// ListenTCP binds a virtual stream listener on the host.
func (h *Host) ListenTCP(ap netip.AddrPort) (*TCPListener, error) {
	n := h.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrClosed
	}
	addr, err := h.bindLocked(ap, n.tcp)
	if err != nil {
		return nil, err
	}
	l := &TCPListener{
		net: n, host: h, addr: addr,
		pending: make(chan *TCPConn, n.cfg.TCPBacklog), closed: make(chan struct{}),
	}
	n.tcp[addr] = l
	return l, nil
}

// Addr returns the listener's bound address.
func (l *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

// Accept returns the next pending connection. It blocks until a dial
// completes or the listener closes.
func (l *TCPListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.pending:
		return c, nil
	case <-l.closed:
		return nil, ErrClosed
	}
}

// Close releases the port and resets pending connections.
func (l *TCPListener) Close() error {
	l.once.Do(func() {
		l.net.mu.Lock()
		delete(l.net.tcp, l.addr)
		var pending []*TCPConn
		for {
			select {
			case c := <-l.pending:
				pending = append(pending, c)
			default:
				l.net.mu.Unlock()
				close(l.closed)
				for _, c := range pending {
					c.reset()
				}
				return
			}
		}
	})
	return nil
}

// TCPConn is one direction of a simulated stream connection. Writes schedule
// delivery events on the peer link; reads drain the receive buffer. Flow
// control bounds in-flight plus buffered bytes; writers block at the bound.
//
// DropRate loss on a stream link discards data permanently — the sim has no
// retransmission — so stream tests should prefer Partition/ResetLink over
// DropRate for fault injection.
type TCPConn struct {
	net    *Network
	local  netip.AddrPort
	remote netip.AddrPort
	peer   *TCPConn

	mu         sync.Mutex
	recv       [][]byte
	recvBytes  int
	pending    map[uint64][]byte
	pendingLen int
	recvSeq    uint64
	inflight   int
	sendSeq    uint64 // guarded by net.mu; wire order of committed chunks
	dataReady  chan struct{}
	spaceAvail chan struct{}

	closed       chan struct{} // closed when this conn is unusable
	closedOnce   sync.Once
	peerDone     chan struct{} // closed when the peer gracefully closed
	peerDoneOnce sync.Once
	removeOnce   sync.Once
	resetFlag    atomic.Bool
	rd, wd       simDeadline
}

type dialResult struct {
	done     chan struct{}
	canceled atomic.Bool
	conn     *TCPConn
	err      error
}

// DialTCP opens a stream to remote through the link. The dial completes after
// one link traversal: a missing listener or full backlog refuses; a
// partitioned link retries the SYN until ctx ends.
func (h *Host) DialTCP(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	n := h.net
	if n.closed {
		return nil, ErrClosed
	}
	res := &dialResult{done: make(chan struct{})}
	n.scheduleSYN(h, remote, res)
	select {
	case <-res.done:
		if errors.Is(res.err, ErrConnRefused) {
			// Match the stdlib: a refused stream dial surfaces as a
			// *net.OpError dial failure, which transport callers classify.
			return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: net.TCPAddrFromAddrPort(remote), Err: res.err}
		}
		return res.conn, res.err
	case <-ctx.Done():
		res.canceled.Store(true)
		return nil, ctx.Err()
	}
}

const synRetry = 200 * time.Millisecond

func (n *Network) scheduleSYN(h *Host, remote netip.AddrPort, res *dialResult) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		res.err = ErrClosed
		close(res.done)
		return
	}
	if res.canceled.Load() {
		// The dialer gave up; stop retransmitting the SYN.
		n.mu.Unlock()
		return
	}
	link := n.linkLocked(h.addr, remote.Addr())
	if link.down {
		// The SYN is dropped; retry on a bounded interval until the dialer
		// cancels, mirroring retransmission.
		n.scheduleLocked(n.now().Add(synRetry), func() { n.scheduleSYN(h, remote, res) })
		n.mu.Unlock()
		return
	}
	if link.shouldDrop(ProtoTCP) {
		n.emitLocked(EventDrop, ProtoTCP, netip.AddrPortFrom(h.addr, 0), remote, 64)
		n.scheduleLocked(n.now().Add(synRetry), func() { n.scheduleSYN(h, remote, res) })
		n.mu.Unlock()
		return
	}
	delay := link.delayLocked(n.now(), 64)
	n.scheduleLocked(n.now().Add(delay), func() { n.completeSYN(h, remote, res) })
	n.mu.Unlock()
}

func (n *Network) completeSYN(h *Host, remote netip.AddrPort, res *dialResult) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		res.err = ErrClosed
		close(res.done)
		return
	}
	if res.canceled.Load() {
		return
	}
	link := n.linkLocked(h.addr, remote.Addr())
	if link.down {
		n.scheduleLocked(n.now().Add(synRetry), func() { n.scheduleSYN(h, remote, res) })
		return
	}
	l := n.tcp[remote]
	if l == nil {
		n.emitLocked(EventRefused, ProtoTCP, netip.AddrPortFrom(h.addr, 0), remote, 0)
		res.err = ErrConnRefused
		close(res.done)
		return
	}
	select {
	case <-l.closed:
		n.emitLocked(EventRefused, ProtoTCP, netip.AddrPortFrom(h.addr, 0), remote, 0)
		res.err = ErrConnRefused
		close(res.done)
		return
	default:
	}
	local := h.allocDialPortLocked()
	if !local.IsValid() {
		res.err = ErrBound
		close(res.done)
		return
	}
	client := newTCPConn(n, local, remote)
	server := newTCPConn(n, remote, local)
	client.peer, server.peer = server, client
	select {
	case l.pending <- server:
	default:
		n.emitLocked(EventRefused, ProtoTCP, local, remote, 0)
		res.err = ErrConnRefused
		close(res.done)
		return
	}
	n.conns[client] = struct{}{}
	n.conns[server] = struct{}{}
	n.dialUsed[local] = struct{}{}
	n.emitLocked(EventDeliver, ProtoTCP, local, remote, 0)
	if res.canceled.Load() {
		// The dialer abandoned after the SYN was admitted. Tear the pair
		// down so the accepted conn observes a reset, like a real
		// mid-handshake RST, instead of leaking a live half of the dial.
		n.mu.Unlock()
		client.reset()
		n.mu.Lock()
		return
	}
	res.conn = client
	close(res.done)
}

func newTCPConn(n *Network, local, remote netip.AddrPort) *TCPConn {
	return &TCPConn{
		net: n, local: local, remote: remote,
		dataReady: make(chan struct{}, 1), spaceAvail: make(chan struct{}, 1),
		closed: make(chan struct{}), peerDone: make(chan struct{}),
		rd: newSimDeadline(), wd: newSimDeadline(),
	}
}

// allocDialPortLocked picks an ephemeral stream port not used by listeners or
// live dialer ports. Caller holds n.mu.
func (h *Host) allocDialPortLocked() netip.AddrPort {
	n := h.net
	for range 20000 {
		port := h.nextDial
		h.nextDial--
		if h.nextDial < 40000 {
			h.nextDial = 61000
		}
		local := netip.AddrPortFrom(h.addr, port)
		if _, taken := n.tcp[local]; taken {
			continue
		}
		if _, taken := n.dialUsed[local]; taken {
			continue
		}
		return local
	}
	return netip.AddrPort{}
}

// LocalAddr returns the connection's local endpoint.
func (c *TCPConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.local) }

// RemoteAddr returns the connection's remote endpoint.
func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }

// Write schedules b for delivery to the peer, blocking under flow control
// until the peer's receive space admits the data, the write deadline passes,
// or the connection ends. Writes chunk into 64KiB segments.
func (c *TCPConn) Write(b []byte) (int, error) {
	const maxSegment = 64 << 10
	written := 0
	for written < len(b) {
		if c.resetFlag.Load() {
			return written, ErrConnReset
		}
		if c.isClosed() {
			return written, ErrClosed
		}
		if c.peer.resetFlag.Load() {
			return written, ErrConnReset
		}
		c.peer.mu.Lock()
		space := c.net.cfg.TCPReceiveBuffer - c.peer.recvBytes - c.peer.pendingLen - c.peer.inflight
		if space > 0 {
			n := min(space, len(b)-written, maxSegment)
			chunk := append([]byte(nil), b[written:written+n]...)
			c.peer.inflight += n
			peer := c.peer
			c.peer.mu.Unlock()
			c.net.sendSegment(c, peer, chunk)
			written += n
			continue
		}
		c.peer.mu.Unlock()
		timer, gen, expired := c.wd.arm(c.net.now())
		if expired {
			return written, timeoutError{op: "write"}
		}
		var deadline <-chan time.Time
		if timer != nil {
			deadline = timer.C
		}
		select {
		case <-c.peer.spaceAvail:
			stopTimer(timer)
			continue
		case <-gen:
			stopTimer(timer)
			continue
		case <-c.closed:
			stopTimer(timer)
			return written, ErrClosed
		case <-c.peerDone:
			stopTimer(timer)
			return written, io.ErrClosedPipe
		case <-deadline:
			return written, timeoutError{op: "write"}
		}
	}
	return written, nil
}

// Read drains the receive buffer, returning io.EOF once the peer has closed
// and all in-flight data has arrived, or ErrConnReset after an abort.
func (c *TCPConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.recv) != 0 {
			chunk := c.recv[0]
			n := copy(b, chunk)
			if n == len(chunk) {
				c.recv[0] = nil
				c.recv = c.recv[1:]
			} else {
				c.recv[0] = chunk[n:]
			}
			c.recvBytes -= n
			c.releaseLocked()
			c.mu.Unlock()
			return n, nil
		}
		if c.resetFlag.Load() {
			c.mu.Unlock()
			return 0, ErrConnReset
		}
		select {
		case <-c.peerDone:
			if c.inflight == 0 {
				c.mu.Unlock()
				return 0, io.EOF
			}
		default:
		}
		c.mu.Unlock()
		if c.isClosed() {
			return 0, ErrClosed
		}
		timer, gen, expired := c.rd.arm(c.net.now())
		if expired {
			return 0, timeoutError{op: "read"}
		}
		var deadline <-chan time.Time
		if timer != nil {
			deadline = timer.C
		}
		select {
		case <-c.dataReady:
			stopTimer(timer)
			continue
		case <-gen:
			stopTimer(timer)
			continue
		case <-c.closed:
			stopTimer(timer)
			return 0, ErrClosed
		case <-deadline:
			return 0, timeoutError{op: "read"}
		}
	}
}

func (c *TCPConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// sendSegment schedules one chunk's delivery on the c→peer link. Chunks carry
// a per-direction sequence number so jittered deliveries reassemble in wire
// order — a stream must never reorder bytes. A dropped chunk leaves a
// permanent hole (the sim has no retransmission): later arrivals wait in the
// reorder buffer and the reader stalls, matching documented stream loss.
func (n *Network) sendSegment(c, peer *TCPConn, chunk []byte) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		peer.mu.Lock()
		peer.inflight -= len(chunk)
		peer.releaseLocked()
		peer.nudgeReadLocked()
		peer.mu.Unlock()
		return
	}
	n.emitLocked(EventSent, ProtoTCP, c.local, c.remote, len(chunk))
	seq := c.sendSeq
	c.sendSeq++
	link := n.linkLocked(c.local.Addr(), c.remote.Addr())
	dropped := link.down
	if !dropped && link.shouldDrop(ProtoTCP) {
		dropped = true
	}

	if dropped {
		n.emitLocked(EventDrop, ProtoTCP, c.local, c.remote, len(chunk))
		n.mu.Unlock()
		peer.mu.Lock()
		peer.inflight -= len(chunk)
		peer.releaseLocked()
		peer.nudgeReadLocked()
		peer.mu.Unlock()
		return
	}
	delay := link.delayLocked(n.now(), len(chunk))
	n.scheduleLocked(n.now().Add(delay), func() { peer.deliverSegment(seq, chunk) })
	n.mu.Unlock()
}

// deliverSegment records an arrived chunk; called by the scheduler on the
// receiving side. In-order chunks join the readable stream; out-of-order
// chunks wait in the reorder buffer until their predecessors land, exactly
// like a real TCP reassembly queue. If the link went down after scheduling,
// the segment is discarded.
func (c *TCPConn) deliverSegment(seq uint64, data []byte) {
	c.net.mu.Lock()
	down := c.net.linkLocked(c.remote.Addr(), c.local.Addr()).down
	c.net.mu.Unlock()
	c.mu.Lock()
	c.inflight -= len(data)
	if c.isClosed() || c.resetFlag.Load() {
		c.releaseLocked()
		c.nudgeReadLocked()
		c.mu.Unlock()
		return
	}
	kind := EventDeliver
	switch {
	case down:
		kind = EventDrop
	case seq < c.recvSeq:
		kind = EventDuplicate
	case seq > c.recvSeq:
		if seq >= c.recvSeq+uint64(c.net.cfg.TCPReorderWindow) {
			kind = EventDrop
			break
		}
		if c.pending == nil {
			c.pending = make(map[uint64][]byte)
		}
		if _, dup := c.pending[seq]; dup {
			kind = EventDuplicate
		} else {
			c.pending[seq] = data
			c.pendingLen += len(data)
		}

	default:
		c.recv = append(c.recv, data)
		c.recvBytes += len(data)
		c.recvSeq++
		for {
			next, ok := c.pending[c.recvSeq]
			if !ok {
				break
			}
			delete(c.pending, c.recvSeq)
			c.pendingLen -= len(next)
			c.recv = append(c.recv, next)
			c.recvBytes += len(next)
			c.recvSeq++
		}
	}
	c.releaseLocked()
	c.nudgeReadLocked()
	c.mu.Unlock()
	c.net.record(kind, ProtoTCP, c.remote, c.local, len(data))
}

// nudgeReadLocked wakes a parked reader so it can re-check buffer and
// end-of-stream state. Caller holds c.mu.
func (c *TCPConn) nudgeReadLocked() {
	select {
	case c.dataReady <- struct{}{}:
	default:
	}
}

// releaseLocked wakes a writer blocked on receive space. Caller holds c.mu.
func (c *TCPConn) releaseLocked() {
	select {
	case c.spaceAvail <- struct{}{}:
	default:
	}
}

// Close performs a graceful close: scheduled and buffered data still drains
// to the peer before it observes io.EOF.
func (c *TCPConn) Close() error {
	c.closeLocal()
	c.remove()
	if p := c.peer; p != nil {
		p.peerDoneOnce.Do(func() {
			close(p.peerDone)
			select {
			case p.dataReady <- struct{}{}:
			default:
			}
		})
	}
	return nil
}

func (c *TCPConn) closeLocal() {
	c.closedOnce.Do(func() {
		close(c.closed)
		select {
		case c.dataReady <- struct{}{}:
		default:
		}
		c.releaseLocked()
	})
}

func (c *TCPConn) remove() {
	c.removeOnce.Do(func() {
		c.net.mu.Lock()
		delete(c.net.conns, c)
		delete(c.net.dialUsed, c.local)
		c.net.mu.Unlock()
	})
}

// reset aborts the connection and its peer, discarding undelivered data.
func (c *TCPConn) reset() {
	if c.resetFlag.Swap(true) {
		return
	}
	c.remove()
	c.closeLocal()
	if p := c.peer; p != nil && !p.resetFlag.Swap(true) {
		p.remove()
		p.closeLocal()
	}
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}

// ResetLink aborts every connection on the a↔b pair and drops the link both
// ways — a hard cut, as opposed to Partition's stall on new deliveries.
func (n *Network) ResetLink(a, b netip.Addr) {
	n.Partition(a, b)
	n.mu.Lock()
	var doomed []*TCPConn
	for c := range n.conns {
		pair := [2]netip.Addr{c.local.Addr(), c.remote.Addr()}
		if pair == [2]netip.Addr{a, b} || pair == [2]netip.Addr{b, a} {
			doomed = append(doomed, c)
		}
	}
	n.mu.Unlock()
	for _, c := range doomed {
		c.reset()
	}
}
