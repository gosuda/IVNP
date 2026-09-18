//go:build dst || synctest

// Package simnet is a deterministic in-process network simulator. It provides
// virtual UDP sockets and TCP streams whose addressing, latency, jitter,
// packet loss, duplication, and bandwidth are controlled by a shared Network.
// No kernel socket, file, or external process is touched: every delivery is a
// scheduled event on the caller's clock, so a simulation placed inside a
// testing/synctest bubble advances on virtual time, while the same code runs
// on the wall clock elsewhere (benchmarks, non-bubble tests).
//
// Create the Network and all Hosts inside the synctest test function (or
// entirely outside any bubble). A channel or timer created inside a bubble is
// bubble-scoped; mixing a simnet created inside a bubble with goroutines
// outside it panics the runtime, which is the desired failure mode.
package simnet

import (
	"container/heap"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrClosed reports use of a closed socket, listener, or network. It
	// satisfies errors.Is(err, net.ErrClosed) so callers share one close path.
	ErrClosed = net.ErrClosed
	// ErrConnRefused reports a stream dial that reached a node with no
	// listener or no free backlog slot.
	ErrConnRefused = errors.New("simnet: connection refused")
	// ErrConnReset reports a stream read or write on a connection reset by a
	// partition or an aborted peer.
	ErrConnReset = errors.New("simnet: connection reset")
	// ErrBound reports a bind to an address and port already in use.
	ErrBound = errors.New("simnet: address already in use")
	// ErrNoRoute reports a dial or datagram to an address with no host.
	ErrNoRoute = errors.New("simnet: no route to host")
	// ErrNotLocal reports a bind to an address the host does not own.
	ErrNotLocal = errors.New("simnet: cannot assign requested address")
)

// timeoutError is the net.Error-compatible deadline result. os.IsTimeout and
// net.Error Timeout() both recognize it.
type timeoutError struct{ op string }

func (e timeoutError) Error() string   { return "simnet: " + e.op + ": i/o timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

// Proto identifies the simulated protocol an Event describes.
type Proto uint8

const (
	ProtoUDP Proto = iota + 1
	ProtoTCP
)

// EventKind classifies a Network event for hooks and statistics.
type EventKind uint8

const (
	// EventSent is recorded when a datagram or stream segment is accepted for
	// delivery — before drop sampling.
	EventSent EventKind = iota + 1
	// EventDeliver records one delivery into a receive queue or stream buffer.
	EventDeliver
	// EventDrop records a packet discarded by link loss or a partition.
	EventDrop
	// EventQueueDrop records a datagram discarded because the destination
	// socket's receive queue was full.
	EventQueueDrop
	// EventDuplicate records delivery of an extra copy.
	EventDuplicate
	// EventRefused records a stream dial refused by missing listener or
	// backlog.
	EventRefused
)

// Event describes one simulated network occurrence. At carries the network's
// clock value — fake time inside a synctest bubble, wall time outside.
type Event struct {
	At       time.Time
	Kind     EventKind
	Proto    Proto
	From, To netip.AddrPort
	Bytes    int
	Seq      uint64
}

// Stats counts network-level outcomes. Queue drops model receive-buffer
// exhaustion; kernel-style drops are not simulated.
type Stats struct {
	Sent         uint64
	Delivered    uint64
	Dropped      uint64
	QueueDropped uint64
	Duplicated   uint64
	Refused      uint64
	Bytes        uint64
	SentUDP      uint64
	SentTCP      uint64
	DroppedUDP   uint64
	DroppedTCP   uint64
}

// BurstLossConfig parameterizes a Gilbert-Elliott two-state Markov loss model.
// State 0 (Good) models normal delivery with low or zero loss; State 1 (Bad)
// models a temporary burst outage (congestion, wireless fading, GFW disruption).
type BurstLossConfig struct {
	// PToBad is the transition probability from Good to Bad on each packet in (0, 1].
	PToBad float64
	// PToGood is the transition probability from Bad to Good on each packet in (0, 1].
	// The mean burst loss length is 1/PToGood packets.
	PToGood float64
	// LossGood is the drop rate in Good state in [0, 1]. Default is 0.
	LossGood float64
	// LossBad is the drop rate in Bad state in [0, 1]. Default is 1.0 (complete loss).
	LossBad float64
}

// LinkConfig describes one directed link's impairment profile. A zero value
// delivers packets immediately and reliably.
type LinkConfig struct {
	// Latency is the base one-way propagation+transmission delay.
	Latency time.Duration
	// Jitter is sampled uniformly in [-Jitter, +Jitter] and added to Latency;
	// the effective delay is clamped at zero. Jitter naturally reorders
	// back-to-back packets.
	Jitter time.Duration
	// DropRate is the independent loss probability per packet in [0,1].
	DropRate float64
	// DropProto scopes DropRate and BurstLoss to one protocol; zero applies
	// loss to all packets. UDP datagram loss exercises transport retransmission.
	DropProto Proto
	// BurstLoss configures a Gilbert-Elliott burst loss model when non-nil.
	// It is evaluated alongside DropRate.
	BurstLoss *BurstLossConfig
	// DuplicateRate is the independent probability of extra delivered copies
	// in [0,1].
	DuplicateRate float64
	// DuplicateDelay is the base extra delay added to duplicated packets.
	// Zero delivers the duplicate concurrently with the original.
	DuplicateDelay time.Duration
	// DuplicateJitter is jitter applied to the duplicate delay.
	DuplicateJitter time.Duration
	// DuplicateCount is the number of extra copies generated when duplication occurs.
	// Zero or 1 selects 1 duplicate copy.
	DuplicateCount int
	// RateBps serializes transmission: packet N departs no earlier than
	// packet N-1's departure plus its wire time (bits/RateBps). Zero means
	// unlimited bandwidth.
	RateBps int64
}

// Config tunes a Network. All fields are optional.
type Config struct {
	// Seed feeds every link's loss/jitter/duplication sampler. Each directed
	// link gets its own derived stream, so sampling on one link is independent
	// of scheduling order on another.
	Seed uint64
	// Prefix is the address block Hosts are allocated from sequentially.
	// Default: 192.0.2.0/24 (TEST-NET-1).
	Prefix netip.Prefix
	// DefaultLink applies to directed pairs with no SetLink entry.
	DefaultLink LinkConfig
	// Now supplies the clock. Nil selects time.Now — which is the fake bubble
	// clock inside testing/synctest and the wall clock outside.
	Now func() time.Time
	// Hook observes every Event when non-nil. It runs on the scheduler or
	// sender goroutine and must be fast and non-blocking.
	Hook func(Event)
	// UDPQueueLimit bounds each UDP socket's inbound queue in packets;
	// overflow is dropped and counted. Zero selects 256.
	UDPQueueLimit int
	// TCPBacklog bounds each listener's pending connection queue; excess
	// dials are refused. Zero selects 64.
	TCPBacklog int
	// TCPReceiveBuffer bounds unacked+undelivered bytes per direction of a
	// stream; writers block past the bound. Zero selects 256KiB.
	TCPReceiveBuffer int
	// TCPReorderWindow bounds the sliding window of out-of-order segments
	// buffered per stream during jitter reordering. Segments arriving at
	// or beyond recvSeq + TCPReorderWindow are dropped as outside the receive
	// window. Zero selects 256 segments.
	TCPReorderWindow int
}

type event struct {
	due time.Time
	seq uint64
	run func()
}

type eventHeap []event

func (h eventHeap) Len() int           { return len(h) }
func (h eventHeap) Less(i, j int) bool { return lessEvent(h[i], h[j]) }
func (h eventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)        { *h = append(*h, x.(event)) }
func (h *eventHeap) Pop() any          { old := *h; n := len(old); e := old[n-1]; *h = old[:n-1]; return e }

func lessEvent(a, b event) bool {
	if a.due.Equal(b.due) {
		return a.seq < b.seq
	}
	return a.due.Before(b.due)
}

// linkState is one directed edge plus its own randomness and wire clock.
type linkState struct {
	cfg      LinkConfig
	rng      *rand.Rand
	txFree   time.Time
	down     bool
	burstBad bool
}

// Host is one node with a single address. Sockets and listeners created on a
// host share its address; ports are scoped per protocol.
type Host struct {
	net      *Network
	name     string
	addr     netip.Addr
	nextPort uint16
	nextDial uint16
}

// Addr returns the host's assigned address.
func (h *Host) Addr() netip.Addr { return h.addr }

// Name returns the host's label.
func (h *Host) Name() string { return h.name }

// Network owns the topology, the event scheduler, and simulation statistics.
// Methods are safe for concurrent use; event ordering is deterministic for a
// given schedule of calls, and per-link randomness is seeded from Config.Seed.
type Network struct {
	now  func() time.Time
	seed uint64
	hook func(Event)
	cfg  Config

	mu        sync.Mutex
	hosts     map[netip.Addr]*Host
	udp       map[netip.AddrPort]*UDPConn
	tcp       map[netip.AddrPort]*TCPListener
	conns     map[*TCPConn]struct{}
	dialUsed  map[netip.AddrPort]struct{}
	links     map[[2]netip.Addr]*linkState
	linkSeq   uint64
	events    eventHeap
	seq       uint64
	closed    bool
	stats     Stats
	nextAddr  uint32
	wake      chan struct{}
	done      chan struct{}
	schedDone chan struct{}
}

// NewNetwork creates a simulator and starts its scheduler goroutine. The
// goroutine must be created inside the eventual synctest bubble: constructing
// the Network inside the test function passed to synctest.Test satisfies this.
func NewNetwork(cfg Config) *Network {
	if cfg.Prefix == (netip.Prefix{}) {
		cfg.Prefix = netip.MustParsePrefix("192.0.2.0/24")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.UDPQueueLimit <= 0 {
		cfg.UDPQueueLimit = 256
	}
	if cfg.TCPBacklog <= 0 {
		cfg.TCPBacklog = 64
	}
	if cfg.TCPReceiveBuffer <= 0 {
		cfg.TCPReceiveBuffer = 256 << 10
	}
	if cfg.TCPReorderWindow <= 0 {
		cfg.TCPReorderWindow = 256
	}

	n := &Network{
		now:       cfg.Now,
		seed:      cfg.Seed,
		hook:      cfg.Hook,
		cfg:       cfg,
		hosts:     make(map[netip.Addr]*Host),
		udp:       make(map[netip.AddrPort]*UDPConn),
		tcp:       make(map[netip.AddrPort]*TCPListener),
		conns:     make(map[*TCPConn]struct{}),
		dialUsed:  make(map[netip.AddrPort]struct{}),
		links:     make(map[[2]netip.Addr]*linkState),
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		schedDone: make(chan struct{}),
	}
	n.nextAddr = 1
	go n.run()
	return n
}

// SetHook replaces the event observer configured at construction. Pass nil to
// disable observation.
func (n *Network) SetHook(hook func(Event)) {
	n.mu.Lock()
	n.hook = hook
	n.mu.Unlock()
}

// Host allocates and registers a node with the next sequential prefix
// address. Names are diagnostic labels and need not be unique.
func (n *Network) Host(name string) *Host {
	n.mu.Lock()
	defer n.mu.Unlock()
	addr, ok := n.allocAddrLocked()
	if !ok {
		return nil
	}
	h := &Host{net: n, name: name, addr: addr, nextPort: 32768, nextDial: 61000}
	n.hosts[addr] = h
	return h
}

// HostAt registers a node on a specific prefix-contained address.
func (n *Network) HostAt(name string, addr netip.Addr) *Host {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, used := n.hosts[addr]; used {
		return nil
	}
	h := &Host{net: n, name: name, addr: addr, nextPort: 32768, nextDial: 61000}
	n.hosts[addr] = h
	return h
}

func (n *Network) allocAddrLocked() (netip.Addr, bool) {
	base := n.cfg.Prefix.Masked().Addr()
	for i := 0; i < 65536; i++ {
		addr := addAddr(base, n.nextAddr)
		n.nextAddr++
		if _, used := n.hosts[addr]; !used {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func addAddr(base netip.Addr, offset uint32) netip.Addr {
	if base.Is4() {
		a := base.As4()
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		v += offset
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	a := base.As16()
	carry := uint64(offset)
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(a[i]) + carry
		a[i] = byte(sum)
		carry = sum >> 8
	}
	return netip.AddrFrom16(a)
}

// Close stops the scheduler and closes every socket, listener, and stream
// created on the network. Blocked operations return ErrClosed.
func (n *Network) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.events = nil
	udp := make([]*UDPConn, 0, len(n.udp))
	for _, c := range n.udp {
		udp = append(udp, c)
	}
	tcp := make([]*TCPListener, 0, len(n.tcp))
	for _, l := range n.tcp {
		tcp = append(tcp, l)
	}
	conns := n.connsLocked()
	n.mu.Unlock()
	close(n.done)
	for _, c := range udp {
		_ = c.Close()
	}
	for _, l := range tcp {
		_ = l.Close()
	}
	for _, c := range conns {
		c.reset()
	}
	<-n.schedDone
	return nil
}

// Stats returns a consistent snapshot of network counters.
func (n *Network) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stats
}

// connsLocked snapshots live connections; caller holds n.mu.
func (n *Network) connsLocked() []*TCPConn {
	out := make([]*TCPConn, 0, len(n.conns))
	for c := range n.conns {
		out = append(out, c)
	}
	return out
}

// PendingEvents returns the number of scheduled-but-undelivered events.
func (n *Network) PendingEvents() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.events)
}

// SetLink configures the directed link from → to, replacing any previous
// entry. The link's random stream derives from the network seed and the
// link's creation order, so a link's samples are independent of traffic on
// other links.
func (n *Network) SetLink(from, to netip.Addr, cfg LinkConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := [2]netip.Addr{from, to}
	l, ok := n.links[key]
	if !ok {
		n.linkSeq++
		l = &linkState{rng: rand.New(rand.NewPCG(n.seed, n.linkSeq))}
		n.links[key] = l
	}
	l.cfg = cfg
	l.down = false
}

// SetBidirectional configures both directions of a link pair identically.
func (n *Network) SetBidirectional(a, b netip.Addr, cfg LinkConfig) {
	n.SetLink(a, b, cfg)
	n.SetLink(b, a, cfg)
}

// Blackhole drops all future deliveries from 'from' to 'to' without affecting
// reverse traffic from 'to' to 'from', modeling unidirectional routing failures
// or asymmetric filtering. In-flight events landing after this call are also dropped.
func (n *Network) Blackhole(from, to netip.Addr) {
	n.setDown(from, to, true)
}

// Unblackhole restores unidirectional delivery from 'from' to 'to'.
func (n *Network) Unblackhole(from, to netip.Addr) {
	n.setDown(from, to, false)
}

// Partition drops all future deliveries between the pair in both directions.
// In-flight events still landing after the call are also dropped.
func (n *Network) Partition(a, b netip.Addr) {
	n.setDown(a, b, true)
	n.setDown(b, a, true)
}

// Heal restores both directions of a partitioned pair.
func (n *Network) Heal(a, b netip.Addr) {
	n.setDown(a, b, false)
	n.setDown(b, a, false)
}

func (n *Network) setDown(from, to netip.Addr, down bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	l := n.linkLocked(from, to)
	l.down = down
}

// linkLocked returns the directed link entry, creating it with defaults.
func (n *Network) linkLocked(from, to netip.Addr) *linkState {
	key := [2]netip.Addr{from, to}
	l, ok := n.links[key]
	if !ok {
		n.linkSeq++
		l = &linkState{rng: rand.New(rand.NewPCG(n.seed, n.linkSeq)), cfg: n.cfg.DefaultLink}
		n.links[key] = l
	}
	return l
}

// emitLocked records an event; caller holds n.mu.
func (n *Network) emitLocked(kind EventKind, proto Proto, from, to netip.AddrPort, bytes int) {
	switch kind {
	case EventSent:
		n.stats.Sent++
		if proto == ProtoUDP {
			n.stats.SentUDP++
		} else if proto == ProtoTCP {
			n.stats.SentTCP++
		}
	case EventDeliver:
		n.stats.Delivered++
		n.stats.Bytes += uint64(bytes)
	case EventDrop:
		n.stats.Dropped++
		if proto == ProtoUDP {
			n.stats.DroppedUDP++
		} else if proto == ProtoTCP {
			n.stats.DroppedTCP++
		}
	case EventQueueDrop:
		n.stats.QueueDropped++
	case EventDuplicate:
		n.stats.Duplicated++
	case EventRefused:
		n.stats.Refused++
	}
	if n.hook != nil {
		n.seq++
		n.hook(Event{At: n.now(), Kind: kind, Proto: proto, From: from, To: to, Bytes: bytes, Seq: n.seq})
	}
}

// drops reports whether link loss applies to proto.
func (l *linkState) drops(proto Proto) bool {
	return (l.cfg.DropRate > 0 || l.cfg.BurstLoss != nil) && (l.cfg.DropProto == 0 || l.cfg.DropProto == proto)
}

// shouldDrop samples packet loss under both Bernoulli DropRate and the
// Gilbert-Elliott two-state Markov burst loss model. Caller holds n.mu.
func (l *linkState) shouldDrop(proto Proto) bool {
	if !l.drops(proto) {
		return false
	}
	if l.cfg.BurstLoss != nil {
		b := l.cfg.BurstLoss
		if !l.burstBad {
			if b.PToBad > 0 && l.rng.Float64() < b.PToBad {
				l.burstBad = true
			}
		} else {
			if b.PToGood > 0 && l.rng.Float64() < b.PToGood {
				l.burstBad = false
			}
		}
		rate := b.LossGood
		if l.burstBad {
			rate = b.LossBad
			if rate <= 0 {
				rate = 1.0
			}
		}
		if rate > 0 && l.rng.Float64() < rate {
			return true
		}
	}
	if l.cfg.DropRate > 0 && l.rng.Float64() < l.cfg.DropRate {
		return true
	}
	return false
}

// delayLocked computes the delivery delay for bytes on a link: wire-time
// serialization, propagation latency, and jitter. Caller holds n.mu.
func (l *linkState) delayLocked(now time.Time, bytes int) time.Duration {
	delay := l.cfg.Latency
	if l.cfg.Jitter > 0 {
		j := int64(l.cfg.Jitter)
		delay += time.Duration(l.rng.Int64N(2*j+1) - j)
	}
	if l.cfg.RateBps > 0 {
		wire := time.Duration(int64(bytes) * 8 * int64(time.Second) / l.cfg.RateBps)
		start := now
		if l.txFree.After(now) {
			start = l.txFree
		}
		l.txFree = start.Add(wire)
		delay += l.txFree.Sub(now)
	}
	if delay < 0 {
		delay = 0
	}
	return delay
}

// scheduleLocked pushes one event; caller holds n.mu.
func (n *Network) scheduleLocked(due time.Time, run func()) {
	n.seq++
	heap.Push(&n.events, event{due: due, seq: n.seq, run: run})
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// run is the event scheduler. It sleeps until the next event's due time on
// the caller clock — inside a synctest bubble that sleep is a fake timer, so
// virtual time advances exactly to each delivery.
func (n *Network) run() {
	defer close(n.schedDone)
	for n.step() {
	}
}

// step runs one scheduler iteration: false means the network is closing.
func (n *Network) step() bool {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return false
	}
	if len(n.events) == 0 {
		n.mu.Unlock()
		select {
		case <-n.wake:
			return true
		case <-n.done:
			return false
		}
	}
	delay := n.events[0].due.Sub(n.now())
	if delay > 0 {
		n.mu.Unlock()
		return n.waitDelay(delay)
	}
	now := n.now()
	var ready []event
	for len(n.events) > 0 && !n.events[0].due.After(now) {
		ready = append(ready, heap.Pop(&n.events).(event))
	}
	n.mu.Unlock()
	for _, ev := range ready {
		ev.run()
	}
	return true
}

// Advance parks the caller for d on the ambient clock. Inside a
// testing/synctest bubble this is the fake clock: virtual time jumps to the
// next pending timer, running scheduled deliveries without wall-clock waits.
func (n *Network) Advance(d time.Duration) {
	time.Sleep(d)
}

// waitDelay parks until the timer fires, a new event wakes the scheduler, or
// the network closes; false means close.
func (n *Network) waitDelay(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-n.wake:
		return true
	case <-n.done:
		return false
	}
}

// sendDatagram implements UDP send: sample loss/duplication on the directed
// link, then schedule delivery. A send always reports success — like real
// UDP, failures are invisible to the sender.
func (n *Network) sendDatagram(from, to netip.AddrPort, payload []byte) {
	n.mu.Lock()
	n.emitLocked(EventSent, ProtoUDP, from, to, len(payload))
	link := n.linkLocked(from.Addr(), to.Addr())
	if link.down {
		n.emitLocked(EventDrop, ProtoUDP, from, to, len(payload))
		n.mu.Unlock()
		return
	}
	delay := link.delayLocked(n.now(), len(payload))
	if link.shouldDrop(ProtoUDP) {
		n.emitLocked(EventDrop, ProtoUDP, from, to, len(payload))
		n.mu.Unlock()
		return
	}
	data := append([]byte(nil), payload...)
	now := n.now()
	n.scheduleLocked(now.Add(delay), func() { n.deliverDatagram(from, to, data, false) })
	if link.cfg.DuplicateRate > 0 && link.rng.Float64() < link.cfg.DuplicateRate {
		copies := max(link.cfg.DuplicateCount, 1)
		for range copies {
			dupDelay := delay + link.cfg.DuplicateDelay
			if link.cfg.DuplicateJitter > 0 {
				j := int64(link.cfg.DuplicateJitter)
				dupDelay += time.Duration(link.rng.Int64N(2*j+1) - j)
			}
			if dupDelay < 0 {
				dupDelay = 0
			}
			n.scheduleLocked(now.Add(dupDelay), func() { n.deliverDatagram(from, to, data, true) })
		}
	}
	n.mu.Unlock()
}

func (n *Network) deliverDatagram(from, to netip.AddrPort, data []byte, duplicate bool) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	link := n.linkLocked(from.Addr(), to.Addr())
	if link.down {
		n.emitLocked(EventDrop, ProtoUDP, from, to, len(data))
		n.mu.Unlock()
		return
	}
	sock := n.udp[to]
	n.mu.Unlock()
	if sock == nil {
		return
	}
	sock.deliver(from, data, duplicate)
}

// record emits one Event with its own lock acquisition — for code paths that
// do not already hold n.mu.
func (n *Network) record(kind EventKind, proto Proto, from, to netip.AddrPort, bytes int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.emitLocked(kind, proto, from, to, bytes)
}

// simDeadline tracks a read or write deadline. Every Set broadcasts on a
// fresh generation channel so in-flight waiters re-arm against the new value.
// Inside a synctest bubble the arming timer is a fake-clock timer.
type simDeadline struct {
	mu  sync.Mutex
	t   time.Time
	gen chan struct{}
}

func newSimDeadline() simDeadline {
	return simDeadline{gen: make(chan struct{})}
}

func (d *simDeadline) set(t time.Time) {
	d.mu.Lock()
	d.t = t
	close(d.gen)
	d.gen = make(chan struct{})
	d.mu.Unlock()
}

// arm returns a timer for the current deadline, the generation channel, and
// whether the deadline has already passed at now.
func (d *simDeadline) arm(now time.Time) (*time.Timer, <-chan struct{}, bool) {
	d.mu.Lock()
	t, gen := d.t, d.gen
	d.mu.Unlock()
	if t.IsZero() {
		return nil, gen, false
	}
	if !now.Before(t) {
		return nil, gen, true
	}
	return time.NewTimer(t.Sub(now)), gen, false
}
