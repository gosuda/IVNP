package streamingtunnel

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/interfaces/stream"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/networking/internal/streaming"
)

type Packet = streaming.Packet

const (
	HeaderLen       = streaming.HeaderLen
	MaxPacketSize   = streaming.MaxPacketSize
	InitialWindow   = streaming.InitialWindow
	MaxWindow       = streaming.MaxWindow
	FlagSynchronize = streaming.FlagSynchronize
	FlagClose       = streaming.FlagClose
	FlagReset       = streaming.FlagReset
	FlagNoACK       = streaming.FlagNoACK
)
const (
	// ProtocolStreaming is the I2CP protocol number for streaming packets (6).
	ProtocolStreaming uint8 = 6

	DefaultTunnelAcceptQueue  = 64
	DefaultTunnelReadQueue    = 64
	DefaultTunnelSendQueue    = 128
	DefaultRetransmitAfter    = streaming.InitialRTO
	DefaultTunnelRetries      = 8
	gracefulDisconnectTimeout = 5 * time.Minute
	localMaxPayloadSize       = MaxPacketSize - HeaderLen
	defaultPeerMaxPayloadSize = 1730
	minPeerMaxPayloadSize     = 512
	tunnelRetryUpdateIdle     = false
	tunnelRetryUpdatePending  = true
)

const (
	FlagSignatureIncluded  = 0x0008
	FlagFromIncluded       = 0x0020
	FlagDelayRequested     = 0x0040
	FlagMaxPacketSize      = 0x0080
	FlagOfflineSignature   = 0x0800
	streamingKnownFlags    = FlagSynchronize | FlagClose | FlagReset | FlagSignatureIncluded | FlagFromIncluded | FlagDelayRequested | FlagMaxPacketSize | FlagNoACK | FlagOfflineSignature
	streamingSignatureSize = ed25519.SignatureSize
)

var (
	ErrTunnelSender       = errors.New("streaming: missing tunnel sender")
	ErrTunnelAddress      = errors.New("streaming: invalid I2P stream address")
	ErrTunnelProtocol     = errors.New("streaming: invalid tunnel delivery protocol")
	ErrTunnelDestination  = errors.New("streaming: delivery addressed to another destination")
	ErrTunnelIdentity     = errors.New("streaming: invalid local or peer destination")
	ErrTunnelSignature    = errors.New("streaming: invalid streaming control signature")
	ErrTunnelPacket       = errors.New("streaming: invalid tunnel streaming packet")
	ErrTunnelBackpressure = errors.New("streaming: connection receive queue is full")
	ErrTunnelReset        = errors.New("streaming: peer reset the connection")
)

type Delivery = destination.Delivery

// TunnelSender wraps and delivers Streaming payloads through outbound tunnels.
type TunnelSender interface {
	SendTunnel(context.Context, Delivery) error
}

// TunnelNetworkConfig configures a local tunnel-backed streaming network.
type TunnelNetworkConfig struct {
	Destination     *foundation.LocalDestination
	Sender          TunnelSender
	AcceptQueue     int
	ReadQueue       int
	RetransmitAfter time.Duration
	MaxRetries      int
}

// TunnelNetwork manages streaming connections routed over I2P tunnels.
type TunnelNetwork struct {
	localHash      foundation.Hash
	localIdentity  foundation.Identity
	localRaw       []byte
	localB32       string
	sign           func([]byte) ([]byte, error)
	sender         TunnelSender
	acceptCapacity int
	readCapacity   int
	retransmit     time.Duration
	maxRetries     int

	mu             sync.RWMutex
	listeners      map[uint16]*tunnelListener
	byID           map[uint32]*tunnelConn
	inbound        map[inboundKey]*tunnelConn
	closed         bool
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	outboundMu     sync.RWMutex
	outbound       chan sendRequest
	retryUpdates   chan *tunnelConn
	completionPool sync.Pool
	deliveryQueues []chan sendRequest
	closeOnce      sync.Once
	wg             sync.WaitGroup
}

// NetworkStats holds connection count and aggregate flow-control metrics.
type NetworkStats struct {
	Connections        int
	PendingPackets     int
	CongestionWindow   uint64
	SlowStartThreshold uint64
}

type inboundKey struct {
	from foundation.Hash
	id   uint32
}

// NewTunnelNetwork creates a TunnelNetwork with the given configuration.
func NewTunnelNetwork(config TunnelNetworkConfig) (*TunnelNetwork, error) {
	if config.Sender == nil {
		return nil, ErrTunnelSender
	}
	if config.Destination == nil {
		return nil, ErrTunnelIdentity
	}
	identity, err := config.Destination.Identity()
	if err != nil {
		return nil, ErrTunnelIdentity
	}
	if identity.CryptoKeyType() != foundation.CryptoElGamal {
		return nil, ErrTunnelIdentity
	}
	raw, localHash, sign := identity.Bytes(), config.Destination.Hash(), config.Destination.Sign
	if config.AcceptQueue <= 0 {
		config.AcceptQueue = DefaultTunnelAcceptQueue
	}
	if config.ReadQueue <= 0 {
		config.ReadQueue = DefaultTunnelReadQueue
	}
	if config.RetransmitAfter <= 0 {
		config.RetransmitAfter = DefaultRetransmitAfter
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = DefaultTunnelRetries
	}
	lifetime, cancel := context.WithCancel(context.Background())
	deliveryWorkers := parallelism.Workers(DefaultTunnelSendQueue)
	deliveryCapacity := max(1, (DefaultTunnelSendQueue+deliveryWorkers-1)/deliveryWorkers)
	network := &TunnelNetwork{
		localHash:      localHash,
		localIdentity:  identity,
		localRaw:       raw,
		localB32:       hashB32(localHash),
		sign:           sign,
		sender:         config.Sender,
		acceptCapacity: config.AcceptQueue,
		readCapacity:   config.ReadQueue,
		retransmit:     config.RetransmitAfter,
		maxRetries:     config.MaxRetries,
		listeners:      make(map[uint16]*tunnelListener),
		byID:           make(map[uint32]*tunnelConn),
		inbound:        make(map[inboundKey]*tunnelConn),
		ctx:            lifetime,
		cancel:         cancel,
		done:           make(chan struct{}),
		outbound:       make(chan sendRequest, DefaultTunnelSendQueue),
		retryUpdates:   make(chan *tunnelConn, DefaultTunnelSendQueue),
		deliveryQueues: make([]chan sendRequest, deliveryWorkers),
	}
	network.wg.Add(1 + deliveryWorkers)
	for index := range network.deliveryQueues {
		network.deliveryQueues[index] = make(chan sendRequest, deliveryCapacity)
		go network.deliveryWorker(network.deliveryQueues[index])
	}
	go network.maintain()
	return network, nil
}

// Stats snapshots live connection and congestion state without exposing
// connection objects or payload buffers.
func (n *TunnelNetwork) Stats() NetworkStats {
	if n == nil {
		return NetworkStats{}
	}
	n.mu.RLock()
	connections := make([]*tunnelConn, 0, len(n.byID))
	for _, connection := range n.byID {
		connections = append(connections, connection)
	}
	n.mu.RUnlock()

	stats := NetworkStats{Connections: len(connections)}
	for _, connection := range connections {
		connection.mu.Lock()
		stats.PendingPackets += len(connection.pending)
		stats.CongestionWindow += uint64(connection.congestion.Window())
		stats.SlowStartThreshold += uint64(connection.congestion.SlowStartThreshold())
		connection.mu.Unlock()
	}
	return stats
}

// B32 returns this endpoint's canonical b32.i2p host name.
func (n *TunnelNetwork) B32() string { return n.localB32 }

// Destination returns the canonical public Destination encoding.
func (n *TunnelNetwork) Destination() []byte {
	if n == nil {
		return nil
	}
	return []byte(foundation.EncodeI2PBase64(n.localRaw))
}

// DialI2P opens an authenticated Streaming connection with an ephemeral local
// virtual port. address must be a b32 hostname or an I2P-base64 Destination
// followed by a virtual I2P port.
func (n *TunnelNetwork) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	return n.DialI2PFromPort(ctx, address, 0)
}

// DialI2PFromPort opens an authenticated Streaming connection using localPort.
// A zero localPort selects a cryptographically-random ephemeral virtual port.
func (n *TunnelNetwork) DialI2PFromPort(ctx context.Context, address string, localPort uint16) (net.Conn, error) {
	target, port, err := parsePeerAddress(address)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	localPort = cmp.Or(localPort, randomPort())

	localID, err := n.allocateID()
	if err != nil {
		return nil, err
	}
	connection := n.newConn(localID, 0, target, foundation.Identity{}, localPort, port, true)
	if err = n.register(connection); err != nil {
		return nil, err
	}
	if err = connection.sendSynchronize(ctx, true); err != nil {
		connection.abort(false)
		return nil, err
	}
	select {
	case <-connection.established:
		if err = connection.sendACK(ctx); err != nil {
			connection.abort(false)
			return nil, err
		}
		return connection, nil
	case <-connection.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		connection.abort(true)
		return nil, ctx.Err()
	}
}

// ListenI2P registers one local virtual I2P port. An address host is optional;
// when supplied it must equal this network's B32 hostname.
func (n *TunnelNetwork) ListenI2P(ctx context.Context, address string) (net.Listener, error) {
	host, port, err := splitI2PAddress(address)
	if err != nil || (host != "" && !strings.EqualFold(host, n.localB32)) {
		return nil, ErrTunnelAddress
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	listener := &tunnelListener{network: n, port: port, incoming: make(chan net.Conn, n.acceptCapacity), closed: make(chan struct{})}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, net.ErrClosed
	}
	if _, exists := n.listeners[port]; exists {
		return nil, stream.ErrAddressInUse
	}
	n.listeners[port] = listener
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-listener.closed:
		case <-n.done:
		}
	}()
	return listener, nil
}

// HandleDelivery accepts one routed I2CP protocol-6 payload. The caller must
// invoke it only after Garlic authentication, destination selection, and
// tunnel reassembly; it never treats a native socket as an I2P stream.
func (n *TunnelNetwork) HandleDelivery(ctx context.Context, delivery Delivery) error {
	if delivery.Protocol != ProtocolStreaming {
		return ErrTunnelProtocol
	}
	if delivery.To != n.localHash {
		return ErrTunnelDestination
	}
	packet, err := streaming.Parse(delivery.Payload)
	if err != nil {
		return err
	}
	if packet.Flags&^streamingKnownFlags != 0 {
		return invalidTunnelPacket("unknown flags", packet)
	}
	if packet.SendStreamID == 0 && packet.Flags&FlagSynchronize != 0 {
		return n.handleSynchronize(ctx, delivery, packet)
	}
	if packet.SendStreamID == 0 || packet.ReceiveStreamID == 0 {
		return invalidTunnelPacket("missing stream ID", packet)
	}
	n.mu.RLock()
	// After SYN, the sender writes the stream ID chosen by the packet
	// recipient into SendStreamID. A pending originator has no peer-assigned
	// ID yet, so its SYN reply is the sole ReceiveStreamID lookup.
	connection := n.byID[packet.SendStreamID]
	if connection == nil && packet.Flags&FlagSynchronize != 0 {
		connection = n.byID[packet.ReceiveStreamID]
	}
	n.mu.RUnlock()
	if connection == nil {
		return invalidTunnelPacket("unknown stream", packet)
	}
	return connection.handle(ctx, delivery, packet)
}

func invalidTunnelPacket(reason string, packet Packet) error {
	return fmt.Errorf("%w: %s flags=%#x send=%d receive=%d sequence=%d ack=%d nacks=%d payload=%d options=%d",
		ErrTunnelPacket, reason, packet.Flags, packet.SendStreamID, packet.ReceiveStreamID,
		packet.Sequence, packet.AckThrough, packet.NACKCount, len(packet.Payload), len(packet.Options))
}

// Close unregisters listeners and connections, then stops the single
// retransmission worker. It is safe to call more than once.
func (n *TunnelNetwork) Close() error {
	n.closeOnce.Do(func() {
		n.cancel()
		close(n.done)
		n.mu.Lock()
		n.closed = true
		listeners := make([]*tunnelListener, 0, len(n.listeners))
		for _, listener := range n.listeners {
			listeners = append(listeners, listener)
		}
		connections := make([]*tunnelConn, 0, len(n.byID))
		for _, connection := range n.byID {
			connections = append(connections, connection)
		}
		n.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, connection := range connections {
			connection.abort(false)
		}
	})
	n.wg.Wait()
	return nil
}

func (n *TunnelNetwork) handleSynchronize(ctx context.Context, delivery Delivery, packet Packet) error {
	validNACKs := packet.NACKCount == 0 && len(packet.NACKs) == 0
	if packet.NACKCount == 8 && len(packet.NACKs) == foundation.HashLength {
		var target foundation.Hash
		copy(target[:], packet.NACKs)
		validNACKs = target == n.localHash
	}
	handleSynchronizeRejected := packet.ReceiveStreamID == 0 || packet.Sequence != 0 || packet.Flags&FlagNoACK == 0 || !validNACKs
	if handleSynchronizeRejected {
		return invalidTunnelPacket("invalid SYN", packet)
	}
	peer, peerMaxPayloadSize, err := verifyControl(packet, delivery.Payload, delivery.From, nil, true)
	if err != nil {
		return fmt.Errorf("streaming SYN control: %w", err)
	}
	key := inboundKey{from: delivery.From, id: packet.ReceiveStreamID}
	n.mu.RLock()
	existing := n.inbound[key]
	listener := n.listeners[delivery.ToPort]
	if listener == nil {
		listener = n.listeners[0]
	}

	n.mu.RUnlock()
	if existing != nil {
		existing.setPeerMaxPayloadSize(peerMaxPayloadSize)
		return existing.sendSynchronize(ctx, false)
	}
	if listener == nil {
		return ErrTunnelAddress
	}
	localID, err := n.allocateID()
	if err != nil {
		return err
	}
	connection := n.newConn(localID, packet.ReceiveStreamID, delivery.From, peer.identity, delivery.ToPort, delivery.FromPort, false)
	connection.setPeerControlLocked(peer)
	if len(packet.Payload) != 0 {
		connection.mu.Lock()
		queued := connection.enqueuePayloadLocked(packet.Payload)
		connection.mu.Unlock()
		if !queued {
			connection.abort(false)
			return ErrTunnelBackpressure
		}
	}
	connection.setPeerMaxPayloadSize(peerMaxPayloadSize)
	if err = n.registerInbound(key, connection); err != nil {
		return err
	}
	if err = connection.sendSynchronize(ctx, false); err != nil {
		connection.abort(false)
		return err
	}
	select {
	case listener.incoming <- connection:
		return nil
	case <-listener.closed:
		connection.abort(true)
		return net.ErrClosed
	default:
		connection.abort(true)
		return ErrTunnelBackpressure
	}
}

func (n *TunnelNetwork) newConn(localID, remoteID uint32, peer foundation.Hash, peerIdentity foundation.Identity, localPort, remotePort uint16, outbound bool) *tunnelConn {
	connection := &tunnelConn{
		network:            n,
		localID:            localID,
		remoteID:           remoteID,
		peer:               peer,
		peerIdentity:       peerIdentity,
		localPort:          localPort,
		remotePort:         remotePort,
		outbound:           outbound,
		nextSequence:       1,
		peerMaxPayloadSize: defaultPeerMaxPayloadSize,
		expect:             1,
		pending:            make(map[uint32]pendingPacket),
		reordered:          make(map[uint32]receivedPacket),
		reads:              make(chan []byte, n.readCapacity),
		established:        make(chan struct{}),
		peerClosed:         make(chan struct{}),
		done:               make(chan struct{}),
		wake:               make(chan struct{}, 1),
		rto:                streaming.NewRTOEstimator(n.retransmit),
		congestion:         streaming.NewCongestionWindow(streaming.MinWindow),
	}
	if remoteID != 0 {
		connection.markEstablished()
	}
	return connection
}

func (n *TunnelNetwork) register(connection *tunnelConn) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	if _, exists := n.byID[connection.localID]; exists {
		return ErrTunnelPacket
	}
	n.byID[connection.localID] = connection
	return nil
}

func (n *TunnelNetwork) registerInbound(key inboundKey, connection *tunnelConn) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	if _, exists := n.byID[connection.localID]; exists {
		return ErrTunnelPacket
	}
	if _, exists := n.inbound[key]; exists {
		return ErrTunnelPacket
	}
	n.byID[connection.localID] = connection
	n.inbound[key] = connection
	connection.inboundKey = &key
	return nil
}

func (n *TunnelNetwork) unregister(connection *tunnelConn) {
	n.mu.Lock()
	if n.byID[connection.localID] == connection {
		delete(n.byID, connection.localID)
	}
	if connection.inboundKey != nil && n.inbound[*connection.inboundKey] == connection {
		delete(n.inbound, *connection.inboundKey)
	}
	n.mu.Unlock()
}

func (n *TunnelNetwork) allocateID() (uint32, error) {
	var encoded [4]byte
	for range 128 {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, err
		}
		id := uint32(encoded[0])<<24 | uint32(encoded[1])<<16 | uint32(encoded[2])<<8 | uint32(encoded[3])
		if id == 0 {
			continue
		}
		n.mu.RLock()
		_, exists := n.byID[id]
		closed := n.closed
		n.mu.RUnlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !exists {
			return id, nil
		}
	}
	return 0, ErrTunnelBackpressure
}

func (n *TunnelNetwork) maintain() {
	defer n.wg.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	requests := sendSchedule{items: make([]scheduledSend, 0, cap(n.outbound))}
	retries := retrySchedule{indices: make(map[*tunnelConn]int)}
	for {
		now := time.Now()
		due := now.Add(time.Hour)
		if request, ok := requests.peek(); ok {
			due = request.due
		}
		if retry, ok := retries.peek(); ok && retry.due.Before(due) {
			due = retry.due
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(time.Nanosecond, time.Until(due)))
		select {
		case <-n.done:
			n.outboundMu.Lock()
			requests.finishAll(net.ErrClosed)
			for {
				select {
				case request := <-n.outbound:
					request.finish(net.ErrClosed)
				default:
					n.outboundMu.Unlock()
					return
				}
			}
		case request := <-n.outbound:
			if request.connection == nil || len(requests.items) == cap(n.outbound) {
				request.finish(ErrTunnelBackpressure)
				continue
			}
			now = time.Now()
			requests.push(request, request.connection.paceDue(now))
			retries.upsert(request.connection, request.connection.retryDue())
		case connection := <-n.retryUpdates:
			connection.retryUpdateQueued.Store(tunnelRetryUpdateIdle)
			retries.upsert(connection, connection.retryDue())
		case <-timer.C:
			now = time.Now()
			n.queueDueRetries(now, &requests, &retries)
			n.dispatchDue(now, &requests)
		}
	}
}

func (n *TunnelNetwork) dispatchDue(now time.Time, requests *sendSchedule) {
	for {
		scheduled, ok := requests.peek()
		if !ok {
			return
		}
		actualDue := scheduled.request.connection.paceDue(now)
		if actualDue.After(scheduled.due) {
			requests.updateTop(actualDue)
			continue
		}
		if now.Before(actualDue) {
			return
		}
		request := requests.pop().request
		if err := request.ctx.Err(); err != nil {
			request.finish(err)
			continue
		}
		request.connection.advancePace(now)
		n.dispatchDelivery(request)
	}
}

func (n *TunnelNetwork) queueDueRetries(now time.Time, requests *sendSchedule, retries *retrySchedule) {
	for {
		scheduled, ok := retries.peek()
		if !ok || now.Before(scheduled.due) {
			return
		}
		connection := retries.pop().connection
		resends := connection.retry(now)
		for index, resend := range resends {
			if len(requests.items) == cap(n.outbound) {
				for _, unqueued := range resends[index:] {
					unqueued.lease.release()
				}
				break
			}
			requests.push(sendRequest{connection: connection, wire: resend.wire, lease: resend.lease, ctx: n.ctx}, connection.paceDue(now))
		}
		retries.upsert(connection, connection.retryDue())
	}
}

func (n *TunnelNetwork) scheduleRetry(connection *tunnelConn) {
	if connection == nil || !connection.retryUpdateQueued.CompareAndSwap(tunnelRetryUpdateIdle, tunnelRetryUpdatePending) {
		return
	}
	select {
	case n.retryUpdates <- connection:
	case <-n.done:
		connection.retryUpdateQueued.Store(tunnelRetryUpdateIdle)
	}
}

func (n *TunnelNetwork) dispatchDelivery(request sendRequest) {
	shard := int(binary.BigEndian.Uint64(request.connection.peer[:8]) % uint64(len(n.deliveryQueues)))
	select {
	case n.deliveryQueues[shard] <- request:
	case <-n.done:
		request.finish(net.ErrClosed)
	default:
		request.finish(ErrTunnelBackpressure)
	}
}

func (n *TunnelNetwork) deliveryWorker(jobs <-chan sendRequest) {
	defer n.wg.Done()
	for {
		select {
		case request := <-jobs:
			if err := request.ctx.Err(); err != nil {
				request.finish(err)
			} else {
				request.finish(n.deliver(request.connection, request.wire))
			}
		case <-n.done:
			for {
				select {
				case request := <-jobs:
					request.finish(net.ErrClosed)
				default:
					return
				}
			}
		}
	}
}

type sendRequest struct {
	connection *tunnelConn
	wire       []byte
	lease      *wireLease
	ctx        context.Context
	result     *sendCompletion
}

func (r sendRequest) finish(err error) {
	if r.result != nil {
		r.result.value <- err
		r.result.release()
	}
	r.lease.release()
}

type sendCompletion struct {
	owner *sync.Pool
	value chan error
	refs  atomic.Int32
}

func (n *TunnelNetwork) acquireCompletion() *sendCompletion {
	completion, _ := n.completionPool.Get().(*sendCompletion)
	if completion == nil {
		completion = &sendCompletion{value: make(chan error, 1)}
	}
	select {
	case <-completion.value:
	default:
	}
	completion.owner = &n.completionPool
	completion.refs.Store(2)
	return completion
}

func (c *sendCompletion) release() {
	if c.refs.Add(-1) == 0 {
		c.owner.Put(c)
	}
}

func (n *TunnelNetwork) deliver(connection *tunnelConn, wire []byte) error {
	return n.sender.SendTunnel(n.ctx, Delivery{
		From: n.localHash, To: connection.peer, FromPort: connection.localPort, ToPort: connection.remotePort,
		Protocol: ProtocolStreaming, Payload: wire,
	})
}

type scheduledSend struct {
	request sendRequest
	due     time.Time
	order   uint64
}

type sendSchedule struct {
	items []scheduledSend
	order uint64
}

func (h *sendSchedule) less(left, right int) bool {
	if h.items[left].due.Equal(h.items[right].due) {
		return h.items[left].order < h.items[right].order
	}
	return h.items[left].due.Before(h.items[right].due)
}

func (h *sendSchedule) swap(left, right int) {
	h.items[left], h.items[right] = h.items[right], h.items[left]
}

func (h *sendSchedule) push(request sendRequest, due time.Time) {
	h.order++
	h.items = append(h.items, scheduledSend{request: request, due: due, order: h.order})
	for index := len(h.items) - 1; index > 0; {
		parent := (index - 1) / 2
		if !h.less(index, parent) {
			break
		}
		h.swap(index, parent)
		index = parent
	}
}

func (h *sendSchedule) peek() (scheduledSend, bool) {
	if len(h.items) == 0 {
		return scheduledSend{}, false
	}
	return h.items[0], true
}

func (h *sendSchedule) pop() scheduledSend {
	item := h.items[0]
	last := len(h.items) - 1
	h.items[0] = h.items[last]
	h.items[last] = scheduledSend{}
	h.items = h.items[:last]
	h.down(0)
	return item
}

func (h *sendSchedule) updateTop(due time.Time) {
	h.items[0].due = due
	h.down(0)
}

func (h *sendSchedule) down(index int) {
	for {
		left := 2*index + 1
		if left >= len(h.items) {
			return
		}
		child := left
		if right := left + 1; right < len(h.items) && h.less(right, left) {
			child = right
		}
		if !h.less(child, index) {
			return
		}
		h.swap(index, child)
		index = child
	}
}

func (h *sendSchedule) finishAll(err error) {
	for len(h.items) != 0 {
		h.pop().request.finish(err)
	}
}

type scheduledRetry struct {
	connection *tunnelConn
	due        time.Time
}

type retrySchedule struct {
	items   []scheduledRetry
	indices map[*tunnelConn]int
}

func (h *retrySchedule) less(left, right int) bool {
	return h.items[left].due.Before(h.items[right].due)
}

func (h *retrySchedule) swap(left, right int) {
	h.items[left], h.items[right] = h.items[right], h.items[left]
	h.indices[h.items[left].connection] = left
	h.indices[h.items[right].connection] = right
}

func (h *retrySchedule) upsert(connection *tunnelConn, due time.Time) {
	index, exists := h.indices[connection]
	if due.IsZero() {
		if exists {
			h.remove(index)
		}
		return
	}
	if exists {
		h.items[index].due = due
		h.fix(index)
		return
	}
	h.items = append(h.items, scheduledRetry{connection: connection, due: due})
	index = len(h.items) - 1
	h.indices[connection] = index
	for index > 0 {
		parent := (index - 1) / 2
		if !h.less(index, parent) {
			break
		}
		h.swap(index, parent)
		index = parent
	}
}

func (h *retrySchedule) peek() (scheduledRetry, bool) {
	if len(h.items) == 0 {
		return scheduledRetry{}, false
	}
	return h.items[0], true
}

func (h *retrySchedule) pop() scheduledRetry {
	return h.remove(0)
}

func (h *retrySchedule) remove(index int) scheduledRetry {
	item := h.items[index]
	delete(h.indices, item.connection)
	last := len(h.items) - 1
	if index != last {
		h.items[index] = h.items[last]
		h.indices[h.items[index].connection] = index
	}
	h.items[last] = scheduledRetry{}
	h.items = h.items[:last]
	if index < len(h.items) {
		h.fix(index)
	}
	return item
}

func (h *retrySchedule) fix(index int) {
	for index > 0 {
		parent := (index - 1) / 2
		if !h.less(index, parent) {
			break
		}
		h.swap(index, parent)
		index = parent
	}
	for {
		left := 2*index + 1
		if left >= len(h.items) {
			return
		}
		child := left
		if right := left + 1; right < len(h.items) && h.less(right, left) {
			child = right
		}
		if !h.less(child, index) {
			return
		}
		h.swap(index, child)
		index = child
	}
}

type tunnelConn struct {
	network *TunnelNetwork

	localID, remoteID uint32
	peer              foundation.Hash
	peerIdentity      foundation.Identity
	peerSigningType   foundation.SigningKeyType
	peerSigningPublic []byte
	localPort         uint16
	remotePort        uint16
	outbound          bool
	inboundKey        *inboundKey

	mu                 sync.Mutex
	nextSequence       uint32
	expect             uint32
	pending            map[uint32]pendingPacket
	reordered          map[uint32]receivedPacket
	preSynchronize     []deferredDelivery
	synchronize        []byte
	synchronizeLease   *wireLease
	syncSent           time.Time
	syncRetries        int
	rto                streaming.RTOEstimator
	congestion         streaming.CongestionWindow
	lastAck            uint32
	haveAck            bool
	duplicateACK       uint8
	peerMaxPayloadSize int
	retryUpdateQueued  atomic.Bool
	nextPaced          time.Time
	peerClosedOK       bool
	localWriteClosed   bool
	localCloseSequence uint32
	reset              bool

	reads          chan []byte
	readCurrent    []byte
	readMu         sync.Mutex
	peerClosed     chan struct{}
	peerOnce       sync.Once
	established    chan struct{}
	establishOnce  sync.Once
	done           chan struct{}
	closeOnce      sync.Once
	gracefulOnce   sync.Once
	closeTimerOnce sync.Once
	wake           chan struct{}

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

type pendingPacket struct {
	wire          []byte
	lease         *wireLease
	sent          time.Time
	retries       int
	retransmitted bool
}

func (p pendingPacket) release() {
	p.lease.release()
}

type receivedPacket struct {
	payload []byte
	close   bool
}

func (c *tunnelConn) paceDue(now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextPaced.IsZero() {
		return now
	}
	return c.nextPaced
}

func (c *tunnelConn) advancePace(now time.Time) {
	c.mu.Lock()
	window := time.Duration(c.congestion.Window())
	interval := c.rto.RTO() / (window * 8)
	if interval < time.Millisecond {
		interval = time.Millisecond
	} else if interval > 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	c.nextPaced = now.Add(interval)
	c.mu.Unlock()
}

func (c *tunnelConn) retryDue() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isDoneLocked() {
		return time.Time{}
	}
	var due time.Time
	rto := c.rto.RTO()
	if c.remoteID == 0 && len(c.synchronize) != 0 {
		due = c.syncSent.Add(rto)
	}
	for _, pending := range c.pending {
		if pending.sent.IsZero() {
			continue
		}
		candidate := pending.sent.Add(rto)
		if due.IsZero() || candidate.Before(due) {
			due = candidate
		}
	}
	return due
}

func (c *tunnelConn) handle(ctx context.Context, delivery Delivery, packet Packet) error {
	handleRejected := delivery.From != c.peer || (delivery.FromPort != 0 && delivery.FromPort != c.remotePort)
	if !handleRejected {
		handleRejected = (delivery.ToPort != 0 && delivery.ToPort != c.localPort)
	}
	if handleRejected {
		return ErrTunnelDestination
	}

	var sendACK, sendReset, finishClose, startCloseTimer bool
	var fastRetransmit []leasedSend
	var deferred []deferredDelivery
	c.mu.Lock()
	if c.isDoneLocked() {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if c.remoteID == 0 && packet.Flags&FlagSynchronize == 0 {
		err := c.queuePreSynchronizeLocked(delivery, packet)
		c.mu.Unlock()
		return err
	}
	if err := c.preparePeerLocked(delivery, packet); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.remoteID != 0 && len(c.preSynchronize) != 0 {
		deferred, c.preSynchronize = c.preSynchronize, nil
	}
	retryChanged := packet.Flags&FlagNoACK == 0
	if retryChanged {
		fastRetransmit = c.acknowledgeLocked(packet.AckThrough, packet.NACKs, time.Now())
	}
	if packet.Flags&FlagReset != 0 {
		c.reset = true
		c.peerClosedOK = true
		c.signalPeerClosedLocked()
		c.mu.Unlock()
		return ErrTunnelReset
	}
	if packet.Sequence != 0 {
		sendACK, sendReset = c.handleSequenceLocked(packet)
	}
	if c.localWriteClosed {
		_, closePending := c.pending[c.localCloseSequence]
		if !closePending {
			finishClose = c.peerClosedOK
			startCloseTimer = !finishClose
		}
	}
	c.mu.Unlock()
	if retryChanged {
		c.network.scheduleRetry(c)
	}
	if sendReset {
		c.abort(true)
		for _, unsent := range fastRetransmit {
			unsent.lease.release()
		}
		return ErrTunnelBackpressure
	}
	for index, resend := range fastRetransmit {
		if err := c.sendWireOwned(ctx, resend.wire, resend.lease); err != nil {
			for _, unsent := range fastRetransmit[index+1:] {
				unsent.lease.release()
			}
			return err
		}
	}
	if sendACK {
		if err := c.sendACK(ctx); err != nil {
			return err
		}
	}
	if finishClose {
		c.abort(false)
	} else if startCloseTimer {
		c.scheduleGracefulCleanup()
	}
	for _, pending := range deferred {
		if err := c.network.HandleDelivery(ctx, pending.delivery); err != nil {
			return err
		}
	}
	return nil
}

func (c *tunnelConn) preparePeerLocked(delivery Delivery, packet Packet) error {
	if c.remoteID != 0 {
		if packet.SendStreamID != c.localID || packet.ReceiveStreamID != c.remoteID {
			return invalidTunnelPacket("stream ID mismatch", packet)
		}
		if packet.Flags&FlagNoACK == 0 {
			c.releaseSynchronizeLocked()
		}
		if packet.Flags&(FlagSynchronize|FlagClose|FlagReset) == 0 {
			return nil
		}
		known := controlPeer{
			identity: c.peerIdentity, signingType: c.peerSigningType,
			signingPublic: c.peerSigningPublic,
		}
		_, peerMaxPayloadSize, err := verifyControl(packet, delivery.Payload, delivery.From, &known, packet.Flags&FlagSynchronize != 0)
		if err != nil {
			return err
		}
		c.updatePeerMaxPayloadSizeLocked(peerMaxPayloadSize)
		return nil
	}
	if packet.Flags&FlagSynchronize == 0 {
		return invalidTunnelPacket("invalid packet before SYN reply", packet)
	}
	invalidSynchronize := packet.Flags&FlagNoACK != 0 ||
		packet.SendStreamID != c.localID || packet.ReceiveStreamID == 0 ||
		packet.Sequence != 0 || packet.NACKCount != 0
	if invalidSynchronize {
		return invalidTunnelPacket("invalid SYN reply", packet)
	}
	peer, peerMaxPayloadSize, err := verifyControl(packet, delivery.Payload, delivery.From, nil, true)
	if err != nil {
		return fmt.Errorf("streaming SYN reply control: %w", err)
	}
	if !c.enqueuePayloadLocked(packet.Payload) {
		return ErrTunnelBackpressure
	}
	c.setPeerControlLocked(peer)
	c.updatePeerMaxPayloadSizeLocked(peerMaxPayloadSize)
	c.remoteID = packet.ReceiveStreamID
	c.releaseSynchronizeLocked()
	c.markEstablished()
	return nil
}

type deferredDelivery struct {
	sequence uint32
	flags    uint16
	delivery Delivery
}

func (c *tunnelConn) queuePreSynchronizeLocked(delivery Delivery, packet Packet) error {
	if packet.SendStreamID != c.localID || packet.ReceiveStreamID == 0 || packet.Sequence >= uint32(InitialWindow) {
		return invalidTunnelPacket("invalid packet before SYN reply", packet)
	}
	retained := deferredDelivery{sequence: packet.Sequence, flags: packet.Flags, delivery: delivery}
	retained.delivery.Payload = append([]byte(nil), delivery.Payload...)
	for index := range c.preSynchronize {
		existing := &c.preSynchronize[index]
		if existing.sequence == retained.sequence && existing.flags == retained.flags {
			*existing = retained
			return nil
		}
	}
	if len(c.preSynchronize) >= InitialWindow {
		return ErrTunnelBackpressure
	}
	c.preSynchronize = append(c.preSynchronize, retained)
	return nil
}

func (c *tunnelConn) handleSequenceLocked(packet Packet) (bool, bool) {
	received := receivedPacket{payload: packet.Payload, close: packet.Flags&FlagClose != 0}
	if packet.Sequence == c.expect {
		sendReset := !c.enqueueExpectedLocked(received)
		return !sendReset, sendReset
	}
	if !sequenceAfter(packet.Sequence, c.expect) {
		return true, false
	}
	if len(c.reordered) >= MaxWindow {
		return false, true
	}
	if _, exists := c.reordered[packet.Sequence]; !exists {
		received.payload = append([]byte(nil), received.payload...)
		c.reordered[packet.Sequence] = received
	}
	return true, false
}

func (c *tunnelConn) enqueueExpectedLocked(received receivedPacket) bool {
	if !c.enqueueReceivedLocked(received) {
		return false
	}
	c.expect++
	for {
		reordered, exists := c.reordered[c.expect]
		if !exists {
			return true
		}
		if !c.enqueueReceivedLocked(reordered) {
			return false
		}
		delete(c.reordered, c.expect)
		c.expect++
	}
}

func (c *tunnelConn) acknowledgeLocked(through uint32, nacks []byte, now time.Time) []leasedSend {
	if len(nacks)%4 != 0 || len(nacks) > 4*MaxWindow {
		return nil
	}
	var acknowledged uint16
	for sequence, pending := range c.pending {
		if sequenceBeforeOrEqual(sequence, through) && !containsNACK(nacks, sequence) {
			if !pending.retransmitted && !pending.sent.IsZero() {
				c.rto.Observe(now.Sub(pending.sent))
			}
			pending.release()
			delete(c.pending, sequence)
			acknowledged++
		}
	}
	if acknowledged != 0 {
		c.congestion.Acknowledge(acknowledged)
		c.duplicateACK = 0
		c.lastAck, c.haveAck = through, true
		c.signalWakeLocked()
		return nil
	}
	if (c.haveAck && c.lastAck == through) || len(nacks) != 0 {
		c.duplicateACK++
	} else {
		c.lastAck, c.haveAck, c.duplicateACK = through, true, 0
	}
	if c.duplicateACK < 3 {
		return nil
	}
	c.duplicateACK = 0
	c.congestion.Loss()
	var selected uint32
	var pending pendingPacket
	found := false
	for sequence, candidate := range c.pending {
		if containsNACK(nacks, sequence) && candidate.retries < c.network.maxRetries {
			selected, pending, found = sequence, candidate, true
			break
		}
	}
	if !found {
		for sequence, candidate := range c.pending {
			acknowledgeLockedSelected := sequenceAfter(sequence, through) && candidate.retries < c.network.maxRetries
			if acknowledgeLockedSelected {
				acknowledgeLockedSelected = (!found || sequenceBeforeOrEqual(sequence, selected))
			}
			if acknowledgeLockedSelected {
				selected, pending, found = sequence, candidate, true
			}
		}
	}
	if !found {
		return nil
	}
	pending.retries++
	pending.retransmitted = true
	pending.sent = now
	c.pending[selected] = pending
	pending.lease.retain()
	return []leasedSend{{wire: pending.wire, lease: pending.lease}}
}

func (c *tunnelConn) enqueueReceivedLocked(packet receivedPacket) bool {
	if !c.enqueuePayloadLocked(packet.payload) {
		return false
	}
	if packet.close {
		c.peerClosedOK = true
		c.signalPeerClosedLocked()
	}
	return true
}

func (c *tunnelConn) enqueuePayloadLocked(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	copyPayload := append([]byte(nil), payload...)
	select {
	case c.reads <- copyPayload:
		return true
	default:
		return false
	}
}

func (c *tunnelConn) sendSynchronize(ctx context.Context, originator bool) error {
	c.mu.Lock()
	var packet Packet
	if originator {
		packet = Packet{ReceiveStreamID: c.localID, Sequence: 0, NACKCount: 8, NACKs: c.peer[:], Flags: FlagSynchronize | FlagSignatureIncluded | FlagFromIncluded | FlagMaxPacketSize | FlagNoACK}
	} else {
		packet = Packet{SendStreamID: c.remoteID, ReceiveStreamID: c.localID, Sequence: 0, Flags: FlagSynchronize | FlagSignatureIncluded | FlagFromIncluded | FlagMaxPacketSize}
	}
	wire, err := c.network.signedControl(packet, controlOptions{includeFrom: true, includeMax: true})
	var lease *wireLease
	if err == nil {
		wire, lease = leaseWire(wire)
		c.releaseSynchronizeLocked()
		c.synchronize = wire
		c.synchronizeLease = lease
		c.syncSent = time.Now()
		c.syncRetries++
		lease.retain()
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err = c.sendWireOwned(ctx, wire, lease); err != nil {
		c.mu.Lock()
		if len(c.synchronize) != 0 && &c.synchronize[0] == &wire[0] {
			c.releaseSynchronizeLocked()
		}
		c.mu.Unlock()
	}
	return err
}

func (c *tunnelConn) releaseSynchronizeLocked() {
	c.synchronizeLease.release()
	c.synchronize = nil
	c.synchronizeLease = nil
}

func (c *tunnelConn) sendACK(ctx context.Context) error {
	c.mu.Lock()
	if c.remoteID == 0 || c.isDoneLocked() {
		c.mu.Unlock()
		return net.ErrClosed
	}
	packet := Packet{SendStreamID: c.remoteID, ReceiveStreamID: c.localID, AckThrough: c.expect - 1, NACKs: c.nacksLocked()}

	wire, err := marshalPacket(packet)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.sendWire(ctx, wire)
}
func (c *tunnelConn) nacksLocked() []byte {
	var highest uint32
	haveHighest := false
	for sequence := range c.reordered {
		if !haveHighest || sequenceAfter(sequence, highest) {
			highest, haveHighest = sequence, true
		}
	}
	if !haveHighest {
		return nil
	}
	nacks := make([]byte, 0, min(int(MaxWindow), int(highest-c.expect))*4)
	for sequence := c.expect; sequenceBeforeOrEqual(sequence, highest) && len(nacks) < 4*MaxWindow; sequence++ {
		if _, received := c.reordered[sequence]; !received {
			nacks = append(nacks, byte(sequence>>24), byte(sequence>>16), byte(sequence>>8), byte(sequence))
		}
	}
	return nacks
}

func (c *tunnelConn) sendWire(ctx context.Context, wire []byte) error {
	return c.sendWireOwned(ctx, wire, nil)
}

func (c *tunnelConn) sendWireOwned(ctx context.Context, wire []byte, lease *wireLease) error {
	completion := c.network.acquireCompletion()
	request := sendRequest{connection: c, wire: wire, lease: lease, ctx: ctx, result: completion}
	c.network.outboundMu.RLock()
	select {
	case <-c.network.done:
		c.network.outboundMu.RUnlock()
		completion.release()
		completion.release()
		lease.release()
		return net.ErrClosed
	default:
	}
	select {
	case c.network.outbound <- request:
		c.network.outboundMu.RUnlock()
	case <-c.network.done:
		c.network.outboundMu.RUnlock()
		completion.release()
		completion.release()
		lease.release()
		return net.ErrClosed
	case <-ctx.Done():
		c.network.outboundMu.RUnlock()
		completion.release()
		completion.release()
		lease.release()
		return ctx.Err()
	}
	defer completion.release()
	select {
	case err := <-completion.value:
		return err
	case <-c.network.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *tunnelConn) retry(now time.Time) []leasedSend {
	var resend []leasedSend
	closeConnection := false
	c.mu.Lock()
	if c.isDoneLocked() {
		c.mu.Unlock()
		return nil
	}
	rto := c.rto.RTO()
	if c.remoteID == 0 && len(c.synchronize) != 0 && now.Sub(c.syncSent) >= rto {
		if c.syncRetries >= c.network.maxRetries {
			closeConnection = true
		} else {
			c.syncRetries++
			c.syncSent = now
			c.rto.Backoff()
			c.synchronizeLease.retain()
			resend = append(resend, leasedSend{wire: c.synchronize, lease: c.synchronizeLease})
		}
	}
	lost := false
	for sequence, pending := range c.pending {
		if pending.sent.IsZero() || now.Sub(pending.sent) < rto {
			continue
		}
		if pending.retries >= c.network.maxRetries {
			pending.release()
			delete(c.pending, sequence)
			closeConnection = true
			continue
		}
		pending.retries++
		pending.retransmitted = true
		pending.sent = now
		c.pending[sequence] = pending
		pending.lease.retain()
		resend = append(resend, leasedSend{wire: pending.wire, lease: pending.lease})
		lost = true
	}
	if lost {
		c.congestion.Loss()
		c.rto.Backoff()
	}
	c.mu.Unlock()
	if closeConnection {
		c.abort(true)
	}
	return resend
}

func (c *tunnelConn) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.readCurrent) != 0 {
			n := copy(dst, c.readCurrent)
			c.readCurrent = c.readCurrent[n:]
			return n, nil
		}
		select {
		case payload := <-c.reads:
			c.readCurrent = payload
			continue
		default:
		}
		if c.isDone() {
			return 0, net.ErrClosed
		}
		if c.isPeerClosed() {
			c.mu.Lock()
			reset := c.reset
			c.mu.Unlock()
			if reset {
				return 0, ErrTunnelReset
			}
			return 0, io.EOF
		}
		timer, timeout := deadlineTimer(c.currentReadDeadline())
		if timer != nil {
			defer timer.Stop()
		}
		select {
		case payload := <-c.reads:
			c.readCurrent = payload
		case <-c.done:
			return 0, net.ErrClosed
		case <-c.peerClosed:
			continue
		case <-timeout:
			return 0, timeoutError{}
		}
	}
}

func (c *tunnelConn) Write(src []byte) (int, error) {
	if len(src) == 0 {
		if c.isDone() {
			return 0, net.ErrClosed
		}
		return 0, nil
	}
	written := 0
	for len(src) != 0 {
		if err := c.waitForWindow(); err != nil {
			return written, err
		}
		chunkLen := len(src)
		c.mu.Lock()
		if c.remoteID == 0 || c.isDoneLocked() || c.peerClosedOK || c.localWriteClosed {
			c.mu.Unlock()
			return written, net.ErrClosed
		}
		if chunkLen > c.peerMaxPayloadSize {
			chunkLen = c.peerMaxPayloadSize
		}
		chunk := src[:chunkLen]
		sequence := c.nextSequence
		c.nextSequence++
		packet := Packet{SendStreamID: c.remoteID, ReceiveStreamID: c.localID, Sequence: sequence, AckThrough: c.expect - 1, Payload: chunk}
		wire, lease, err := marshalPacketLeased(packet)
		if err == nil {
			c.pending[sequence] = pendingPacket{wire: wire, lease: lease, sent: time.Now()}
			lease.retain()
		}
		c.mu.Unlock()
		if err != nil {
			return written, err
		}
		if err = c.sendWireOwned(context.Background(), wire, lease); err != nil {
			c.mu.Lock()
			pending := c.pending[sequence]
			delete(c.pending, sequence)
			pending.release()
			c.signalWakeLocked()
			c.mu.Unlock()
			return written, err
		}
		written += chunkLen
		src = src[chunkLen:]
	}
	return written, nil
}

func (c *tunnelConn) waitForWindow() error {
	for {
		c.mu.Lock()
		if c.isDoneLocked() || c.localWriteClosed {
			c.mu.Unlock()
			return net.ErrClosed
		}
		if c.remoteID == 0 {
			c.mu.Unlock()
			return ErrTunnelPacket
		}
		if len(c.pending) < int(c.congestion.Window()) {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		timer, timeout := deadlineTimer(c.currentWriteDeadline())
		if timer != nil {
			defer timer.Stop()
		}
		select {
		case <-c.wake:
		case <-c.done:
			return net.ErrClosed
		case <-timeout:
			return timeoutError{}
		}
	}
}

func (c *tunnelConn) Close() error {
	if err := c.initiateClose(); err != nil {
		c.abort(false)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	for {
		c.mu.Lock()
		_, pending := c.pending[c.localCloseSequence]
		acknowledged := c.localWriteClosed && !pending
		peerClosed := c.peerClosedOK
		done := c.isDoneLocked()
		c.mu.Unlock()
		if acknowledged {
			if peerClosed {
				c.abort(false)
			} else {
				c.scheduleGracefulCleanup()
			}
			return nil
		}
		if done {
			return nil
		}
		timer, timeout := deadlineTimer(c.currentWriteDeadline())
		select {
		case <-c.wake:
		case <-c.done:
		case <-timeout:
			if timer != nil {
				timer.Stop()
			}
			c.abort(false)
			return timeoutError{}
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *tunnelConn) scheduleGracefulCleanup() {
	c.closeTimerOnce.Do(func() {
		time.AfterFunc(gracefulDisconnectTimeout, func() {
			c.abort(false)
		})
	})
}

func (c *tunnelConn) abort(sendReset bool) {
	if sendReset {
		c.mu.Lock()
		var wire []byte
		if c.remoteID != 0 && !c.isDoneLocked() {
			packet := Packet{SendStreamID: c.remoteID, ReceiveStreamID: c.localID, Flags: FlagReset | FlagSignatureIncluded}
			wire, _ = c.network.signedControl(packet, controlOptions{})
		}
		c.mu.Unlock()
		if len(wire) != 0 {
			_ = c.sendWire(c.network.ctx, wire)
		}
	}
	c.closeOnce.Do(func() {
		close(c.done)
		c.mu.Lock()
		for sequence, pending := range c.pending {
			pending.release()
			delete(c.pending, sequence)
		}
		c.releaseSynchronizeLocked()
		c.mu.Unlock()
		c.network.unregister(c)
		c.signalWake()
	})
}

func (c *tunnelConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *tunnelConn) markEstablished() {
	c.establishOnce.Do(func() { close(c.established) })
}

// LocalDestination and RemoteDestination expose authenticated public metadata
// to local protocol adapters such as SAM.
func (c *tunnelConn) LocalDestination() []byte {
	return c.network.Destination()
}

func (c *tunnelConn) RemoteDestination() []byte {
	if c == nil {
		return nil
	}
	return []byte(foundation.EncodeI2PBase64(c.peerIdentity.Bytes()))
}

func (c *tunnelConn) LocalI2PPort() uint16  { return c.localPort }
func (c *tunnelConn) RemoteI2PPort() uint16 { return c.remotePort }

// CloseWrite sends a sequenced, retransmittable Streaming CLOSE without
// discarding the readable half. Close waits until that CLOSE and all preceding
// data are acknowledged (or the connection's retry/deadline policy expires)
// before releasing the connection.
func (c *tunnelConn) CloseWrite() error {
	return c.initiateClose()
}

func (c *tunnelConn) initiateClose() error {
	var result error
	c.gracefulOnce.Do(func() {
		c.mu.Lock()
		if c.remoteID == 0 || c.isDoneLocked() {
			result = net.ErrClosed
			c.mu.Unlock()
			return
		}
		sequence := c.nextSequence
		packet := Packet{SendStreamID: c.remoteID, ReceiveStreamID: c.localID, Sequence: sequence, AckThrough: c.expect - 1, Flags: FlagClose | FlagSignatureIncluded}
		wire, err := c.network.signedControl(packet, controlOptions{})
		var lease *wireLease
		if err == nil {
			wire, lease = leaseWire(wire)
			c.nextSequence++
			c.localWriteClosed = true
			c.localCloseSequence = sequence
			c.pending[sequence] = pendingPacket{wire: wire, lease: lease, sent: time.Now()}
			lease.retain()
		}
		c.mu.Unlock()
		if err != nil {
			result = err
			return
		}
		if result = c.sendWireOwned(c.network.ctx, wire, lease); result != nil {
			c.mu.Lock()
			pending := c.pending[sequence]
			delete(c.pending, sequence)
			pending.release()
			c.signalWakeLocked()
			c.mu.Unlock()
		}
	})
	return result
}
func (c *tunnelConn) LocalAddr() net.Addr {
	return tunnelAddr{host: c.network.localB32, port: c.localPort}
}

func (c *tunnelConn) RemoteAddr() net.Addr {
	return tunnelAddr{host: hashB32(c.peer), port: c.remotePort}
}

func (c *tunnelConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *tunnelConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *tunnelConn) currentReadDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}

func (c *tunnelConn) currentWriteDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func (c *tunnelConn) signalPeerClosedLocked() {
	c.peerOnce.Do(func() { close(c.peerClosed) })
}

func (c *tunnelConn) signalWakeLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *tunnelConn) signalWake() {
	c.mu.Lock()
	c.signalWakeLocked()
	c.mu.Unlock()
}

func (c *tunnelConn) isDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *tunnelConn) isDoneLocked() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *tunnelConn) isPeerClosed() bool {
	select {
	case <-c.peerClosed:
		return true
	default:
		return false
	}
}

type tunnelListener struct {
	network  *TunnelNetwork
	port     uint16
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.incoming:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.network.done:
		return nil, net.ErrClosed
	}
}

func (l *tunnelListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.network.mu.Lock()
		if l.network.listeners[l.port] == l {
			delete(l.network.listeners, l.port)
		}
		l.network.mu.Unlock()
		for {
			select {
			case connection := <-l.incoming:
				_ = connection.Close()
			default:
				return
			}
		}
	})
	return nil
}

func (l *tunnelListener) Addr() net.Addr { return tunnelAddr{host: l.network.localB32, port: l.port} }

type tunnelAddr struct {
	host string
	port uint16
}

func (a tunnelAddr) Network() string { return "i2p" }
func (a tunnelAddr) String() string  { return net.JoinHostPort(a.host, strconv.Itoa(int(a.port))) }

type controlOptions struct {
	includeFrom bool
	includeMax  bool
}

func (n *TunnelNetwork) signedControl(packet Packet, options controlOptions) ([]byte, error) {
	if n.sign == nil {
		return nil, ErrTunnelIdentity
	}
	if options.includeFrom {
		packet.Flags |= FlagFromIncluded
		packet.Options = append(packet.Options, n.localRaw...)
	}
	if options.includeMax {
		packet.Flags |= FlagMaxPacketSize
		packet.Options = append(packet.Options, byte(localMaxPayloadSize>>8), byte(localMaxPayloadSize&0xff))
	}
	packet.Flags |= FlagSignatureIncluded
	packet.Options = append(packet.Options, make([]byte, streamingSignatureSize)...)
	wire, err := marshalPacket(packet)
	if err != nil {
		return nil, err
	}
	signature, err := n.sign(wire)
	if err != nil || len(signature) != streamingSignatureSize {
		return nil, ErrTunnelIdentity
	}
	signatureOffset := 17 + len(packet.NACKs) + 5 + len(packet.Options) - len(signature)
	if signatureOffset < 0 || signatureOffset+len(signature) > len(wire) {
		return nil, ErrTunnelPacket
	}
	copy(wire[signatureOffset:signatureOffset+len(signature)], signature)
	return wire, nil
}

type controlPeer struct {
	identity      foundation.Identity
	signingType   foundation.SigningKeyType
	signingPublic []byte
}

func (c *tunnelConn) setPeerControlLocked(peer controlPeer) {
	c.peerIdentity = peer.identity
	c.peerSigningType = peer.signingType
	c.peerSigningPublic = peer.signingPublic
}

func verifyControl(packet Packet, wire []byte, claimed foundation.Hash, known *controlPeer, requireFrom bool) (controlPeer, int, error) {
	if packet.Flags&FlagSignatureIncluded == 0 || packet.Flags&^streamingKnownFlags != 0 {
		return controlPeer{}, 0, ErrTunnelPacket
	}
	peer := controlPeer{}
	offset := 0
	if packet.Flags&FlagDelayRequested != 0 {
		if len(packet.Options) < 2 {
			return controlPeer{}, 0, ErrTunnelPacket
		}
		offset += 2
	}
	if packet.Flags&FlagFromIncluded != 0 {
		_, consumed, err := foundation.ParseIdentity(packet.Options[offset:])
		if err != nil {
			return controlPeer{}, 0, ErrTunnelIdentity
		}
		raw := append([]byte(nil), packet.Options[offset:offset+consumed]...)
		identity, parsed, err := foundation.ParseIdentity(raw)
		if err != nil || parsed != len(raw) || identity.Hash() != claimed {
			return controlPeer{}, 0, ErrTunnelIdentity
		}
		peer.identity = identity
		offset += len(raw)
	} else {
		if requireFrom || known == nil {
			return controlPeer{}, 0, ErrTunnelIdentity
		}
		peer = *known
	}
	peerMaxPayloadSize := -1
	if packet.Flags&FlagMaxPacketSize != 0 {
		if len(packet.Options)-offset < 2 {
			return controlPeer{}, 0, ErrTunnelPacket
		}
		peerMaxPayloadSize = int(binary.BigEndian.Uint16(packet.Options[offset : offset+2]))
		offset += 2
	}
	signingType := peer.identity.SigningKeyType()
	signingPublic := peer.signingPublic
	if len(signingPublic) != 0 {
		signingType = peer.signingType
	}
	if packet.Flags&FlagOfflineSignature != 0 {
		if packet.Flags&FlagFromIncluded == 0 || len(packet.Options)-offset < 6 {
			return controlPeer{}, 0, ErrTunnelPacket
		}
		offlineStart := offset
		expires := binary.BigEndian.Uint32(packet.Options[offset : offset+4])
		transientType := foundation.SigningKeyType(binary.BigEndian.Uint16(packet.Options[offset+4 : offset+6]))
		transientKeyLen, keyOK := transientType.PublicKeyLen()
		offlineSignatureLen, signatureOK := peer.identity.SigningKeyType().SignatureLen()
		offset += 6
		if !keyOK || !signatureOK || len(packet.Options)-offset < transientKeyLen+offlineSignatureLen {
			return controlPeer{}, 0, ErrTunnelPacket
		}
		transientPublic := packet.Options[offset : offset+transientKeyLen]
		offset += transientKeyLen
		offlineSignature := packet.Options[offset : offset+offlineSignatureLen]
		offset += offlineSignatureLen
		if uint64(expires) <= uint64(time.Now().Unix()) {
			return controlPeer{}, 0, ErrTunnelSignature
		}
		valid, err := peer.identity.Verify(packet.Options[offlineStart:offlineStart+6+transientKeyLen], offlineSignature)
		if err != nil || !valid {
			return controlPeer{}, 0, ErrTunnelSignature
		}
		signingType = transientType
		signingPublic = transientPublic
	}
	signatureLen, ok := signingType.SignatureLen()
	if !ok || len(packet.Options)-offset != signatureLen {
		return controlPeer{}, 0, ErrTunnelPacket
	}
	optionStart := 17 + len(packet.NACKs) + 5
	signatureOffset := optionStart + offset
	if signatureOffset < 0 || signatureOffset+signatureLen > len(wire) {
		return controlPeer{}, 0, ErrTunnelPacket
	}
	signed := append([]byte(nil), wire...)
	signature := append([]byte(nil), signed[signatureOffset:signatureOffset+signatureLen]...)
	clear(signed[signatureOffset : signatureOffset+signatureLen])
	var valid bool
	var err error
	if len(signingPublic) != 0 {
		valid, err = foundation.VerifySignature(signingType, signingPublic, nil, signed, signature)
	} else {
		valid, err = peer.identity.Verify(signed, signature)
	}
	clear(signed)
	clear(signature)
	if err != nil || !valid {
		return controlPeer{}, 0, ErrTunnelSignature
	}
	if packet.Flags&FlagOfflineSignature != 0 {
		peer.signingType = signingType
		peer.signingPublic = append([]byte(nil), signingPublic...)
	}
	return peer, peerMaxPayloadSize, nil
}

func (c *tunnelConn) setPeerMaxPayloadSize(advertised int) {
	c.mu.Lock()
	c.updatePeerMaxPayloadSizeLocked(advertised)
	c.mu.Unlock()
}

func (c *tunnelConn) updatePeerMaxPayloadSizeLocked(advertised int) {
	if advertised < 0 {
		return
	}
	if advertised < minPeerMaxPayloadSize {
		advertised = minPeerMaxPayloadSize
	} else if advertised > localMaxPayloadSize {
		advertised = localMaxPayloadSize
	}
	c.peerMaxPayloadSize = advertised
}

func marshalPacket(packet Packet) ([]byte, error) {
	encodedLen := packet.EncodedLen()
	if encodedLen < HeaderLen {
		return nil, ErrTunnelPacket
	}
	wire := make([]byte, encodedLen)
	if _, err := packet.MarshalTo(wire); err != nil {
		return nil, err
	}
	return wire, nil
}

type leasedSend struct {
	wire  []byte
	lease *wireLease
}

type wireLease struct {
	slab *pool.Lease
	refs atomic.Int32
}

var wireLeasePool sync.Pool

func acquireWireLease(size int) ([]byte, *wireLease, bool) {
	slab, ok := pool.AcquireLease(size)
	if !ok {
		return nil, nil, false
	}
	wire, ok := slab.Bytes(size)
	if !ok {
		slab.Release()
		return nil, nil, false
	}
	lease, _ := wireLeasePool.Get().(*wireLease)
	if lease == nil {
		lease = &wireLease{}
	}
	lease.slab = slab
	lease.refs.Store(1)
	return wire, lease, true
}

func (l *wireLease) retain() {
	if l != nil {
		l.refs.Add(1)
	}
}

func (l *wireLease) release() {
	if l == nil || l.refs.Add(-1) != 0 {
		return
	}
	l.slab.Release()
	l.slab = nil
	wireLeasePool.Put(l)
}

func marshalPacketLeased(packet Packet) ([]byte, *wireLease, error) {
	encodedLen := packet.EncodedLen()
	if encodedLen < HeaderLen {
		return nil, nil, ErrTunnelPacket
	}
	wire, lease, ok := acquireWireLease(encodedLen)
	if !ok {
		return nil, nil, ErrTunnelBackpressure
	}
	if _, err := packet.MarshalTo(wire); err != nil {
		lease.release()
		return nil, nil, err
	}
	return wire, lease, nil
}

func leaseWire(src []byte) ([]byte, *wireLease) {
	dst, lease, _ := acquireWireLease(len(src))
	copy(dst, src)
	return dst, lease
}

func splitI2PAddress(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, ErrTunnelAddress
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, ErrTunnelAddress
	}
	return host, uint16(value), nil
}

func parsePeerAddress(address string) (foundation.Hash, uint16, error) {
	host, port, err := splitI2PAddress(address)
	if err != nil || host == "" {
		return foundation.Hash{}, 0, ErrTunnelAddress
	}
	hash, err := parseDestinationHost(host)
	if err != nil {
		return foundation.Hash{}, 0, err
	}
	return hash, port, nil
}

func parseDestinationHost(host string) (foundation.Hash, error) {
	var hash foundation.Hash
	if before, ok := strings.CutSuffix(strings.ToLower(host), ".b32.i2p"); ok {
		encoded := before
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
		if err != nil || len(decoded) != len(hash) {
			return hash, ErrTunnelAddress
		}
		copy(hash[:], decoded)
		return hash, nil
	}
	identity, _, err := decodeDestination([]byte(host))
	if err != nil {
		return hash, ErrTunnelAddress
	}
	return identity.Hash(), nil
}

func decodeDestination(encoded []byte) (foundation.Identity, []byte, error) {
	identity, err := foundation.ParseDestination(encoded)
	if err != nil {
		return foundation.Identity{}, nil, ErrTunnelIdentity
	}
	return identity, append([]byte(nil), identity.Bytes()...), nil
}

func hashB32(hash foundation.Hash) string { return foundation.B32(hash) }

func sequenceAfter(left, right uint32) bool         { return int32(left-right) > 0 }
func sequenceBeforeOrEqual(left, right uint32) bool { return int32(left-right) <= 0 }

func containsNACK(nacks []byte, sequence uint32) bool {
	for len(nacks) >= 4 {
		if uint32(nacks[0])<<24|uint32(nacks[1])<<16|uint32(nacks[2])<<8|uint32(nacks[3]) == sequence {
			return true
		}
		nacks = nacks[4:]
	}
	return false
}

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func randomPort() uint16 {
	var encoded [2]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0
	}
	return uint16(encoded[0])<<8 | uint16(encoded[1])
}

func (c *tunnelConn) String() string {
	return fmt.Sprintf("%s -> %s", c.LocalAddr(), c.RemoteAddr())
}
