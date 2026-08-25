package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/packet"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/observability"
)

const (
	defaultTunnelTTL      = time.Minute
	defaultDeliveryBlocks = TunnelPayloadLen / 3
	circuitShards         = 64
)

var (
	ErrCircuitID        = errors.New("tunnel: invalid circuit ID")
	ErrCircuitExists    = errors.New("tunnel: circuit already exists")
	ErrCircuitNotFound  = errors.New("tunnel: circuit not found")
	ErrCircuitExpired   = errors.New("tunnel: circuit expired")
	ErrCircuitDirection = errors.New("tunnel: invalid circuit direction")
	ErrTunnelSender     = errors.New("tunnel: sender unavailable")
	ErrDeliveryHandler  = errors.New("tunnel: local delivery handler unavailable")
)

// Sender sends a standard I2NP message to a directly connected router. The
// message payload is borrowed and is valid only until Send returns. Senders
// that queue or otherwise retain a message must copy its payload before return.
// This permits the tunnel hot path to return packet slabs to its pool after a
// synchronous transport hand-off rather than allocate one heap object per hop.
type Sender interface {
	Send(context.Context, foundation.Hash, i2np.Message) error
}

// SessionEnsurer authenticates a bidirectional peer session without sending an
// application message. Inbound tunnel builders use it for the terminal hop so
// firewalled creators can receive the build reply over an existing session.
type SessionEnsurer interface {
	EnsureSession(context.Context, foundation.Hash) error
}

// Forward identifies the next participant for a transit tunnel. The next
// tunnel ID replaces the receive ID after the configured layer transform.
type Forward struct {
	Peer     foundation.Hash
	TunnelID uint32
}

// OutboundCircuit describes an already established local tunnel gateway.
// Transforms are applied in order to its 1,024-byte payload region. A tunnel
// builder installs the exact negotiated transform sequence. ExpiresAt is a
// Unix-millisecond deadline; zero retains manual-circuit behavior indefinitely.
type OutboundCircuit struct {
	ID uint32
	// Owner is the creator-pool identity. Zero denotes the router's own
	// exploratory circuits; transit circuits use no creator owner.
	Owner        foundation.Hash
	FirstHop     foundation.Hash
	NextTunnelID uint32
	Transforms   []LayerCipher
	ExpiresAt    uint64
}

// InboundCircuit describes either a transit participant or a tunnel endpoint.
// Exactly one of Forward and Endpoint must be set. Local sees a borrowed I2NP
// message and must not retain it after returning. ExpiresAt is a
// Unix-millisecond deadline; zero retains manual-circuit behavior indefinitely.
type InboundCircuit struct {
	ID uint32
	// Owner is the creator-pool identity for local endpoint circuits. It is
	// zero for transit forwarding circuits.
	Owner      foundation.Hash
	Transforms []LayerCipher
	Forward    *Forward
	Endpoint   *Endpoint
	Local      func(i2np.Message) error
	ExpiresAt  uint64
}

type inboundCircuit struct {
	owner      foundation.Hash
	transforms []LayerCipher
	forward    *Forward
	endpoint   *Endpoint
	local      func(i2np.Message) error
	expiresAt  uint64
	activity   *atomic.Uint64
}

type outboundCircuit struct {
	owner        foundation.Hash
	firstHop     foundation.Hash
	nextTunnelID uint32
	transforms   []LayerCipher
	expiresAt    uint64
	activity     *atomic.Uint64
}

type circuitShard struct {
	mu       sync.RWMutex
	inbound  map[uint32]inboundCircuit
	outbound map[uint32]outboundCircuit
}

type senderBox struct{ sender Sender }

// RuntimeConfig controls a tunnel Runtime. Now returns Unix milliseconds and
// is injectable so message expiration is deterministic in tests. Gateway is
// optional; a random-padded gateway is constructed when omitted.
type RuntimeConfig struct {
	Sender  Sender
	Gateway *Gateway
	Now     func() uint64
	Metrics *observability.Registry
}

// Runtime owns bounded, explicitly registered circuit state. Its circuit
// registry is sharded by tunnel ID, so unrelated high-throughput circuits do
// not serialize behind a global lock. Packet buffers and delivery slices are
// pooled, AES schedules are precomputed in LayerCipher, and the steady-state
// forwarding path allocates neither packet storage nor goroutines.
//
// Runtime deliberately does not negotiate build records. A build manager
// installs negotiated circuits with RegisterInbound/RegisterOutbound.
type Runtime struct {
	gateway   *Gateway
	now       func() uint64
	nextID    atomic.Uint32
	sender    atomic.Pointer[senderBox]
	shards    [circuitShards]circuitShard
	blocks    sync.Pool // *[]Block with defaultDeliveryBlocks capacity
	metricsMu sync.Mutex
	metrics   *observability.Registry
}

// NewRuntime constructs a tunnel runtime without network I/O.
func NewRuntime(cfg RuntimeConfig) *Runtime {
	now := cfg.Now
	if now == nil {
		now = func() uint64 { return uint64(time.Now().UnixMilli()) }
	}

	gateway := cfg.Gateway
	if gateway ==
		nil {
		gateway = NewGateway(nil)
	}

	runtime := &Runtime{gateway: gateway, now: now, metrics: cfg.Metrics}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err == nil {
		runtime.nextID.Store(binary.BigEndian.Uint32(seed[:]))
	}
	for index := range runtime.shards {
		runtime.shards[index].inbound = make(map[uint32]inboundCircuit)
		runtime.shards[index].outbound = make(map[uint32]outboundCircuit)
	}
	runtime.sender.Store(&senderBox{sender: cfg.Sender})
	runtime.blocks.New = func() any {
		blocks := make([]Block, defaultDeliveryBlocks)
		return &blocks
	}
	return runtime
}

// SetSender atomically changes the direct transport hand-off. Existing packet
// processing observes either the old or new sender without blocking on a
// registry mutation.
func (r *Runtime) SetSender(sender Sender) {
	if r != nil {
		r.sender.Store(&senderBox{sender: sender})
	}
}

// RegisterOutbound installs one local gateway circuit. It replaces an older
// circuit with the same local ID during tunnel rotation.
func (r *Runtime) RegisterOutbound(circuit OutboundCircuit) error {
	if r == nil || circuit.ID == 0 || circuit.NextTunnelID == 0 {
		return ErrCircuitID
	}
	if r.expired(circuit.ExpiresAt) {
		return ErrCircuitExpired
	}
	shard := r.shard(circuit.ID)
	shard.mu.Lock()
	if _, exists := shard.inbound[circuit.ID]; exists {
		shard.mu.Unlock()
		return ErrCircuitExists
	}
	shard.outbound[circuit.ID] = outboundCircuit{
		owner:        circuit.Owner,
		firstHop:     circuit.FirstHop,
		nextTunnelID: circuit.NextTunnelID,
		transforms:   append([]LayerCipher(nil), circuit.Transforms...),
		expiresAt:    circuit.ExpiresAt,
		activity:     new(atomic.Uint64),
	}
	shard.mu.Unlock()
	r.publishActiveTunnelCounts()
	return nil
}

// RegisterInbound installs either a transit participant or endpoint circuit.
// Endpoint is caller-owned but concurrency-safe; transforms and forwarding
// metadata are copied before publication to prevent caller mutation.
func (r *Runtime) RegisterInbound(circuit InboundCircuit) error {
	if r == nil || circuit.ID == 0 {
		return ErrCircuitID
	}
	if r.expired(circuit.ExpiresAt) {
		return ErrCircuitExpired
	}
	if (circuit.Forward == nil) == (circuit.Endpoint == nil) {
		return ErrCircuitDirection
	}
	var forward *Forward
	if circuit.Forward != nil {
		if circuit.Forward.TunnelID == 0 {
			return ErrCircuitID
		}
		copy := *circuit.Forward
		forward = &copy
	}
	shard := r.shard(circuit.ID)
	shard.mu.Lock()
	if _, exists := shard.inbound[circuit.ID]; exists {
		shard.mu.Unlock()
		return ErrCircuitExists
	}
	if _, exists := shard.outbound[circuit.ID]; exists {
		shard.mu.Unlock()
		return ErrCircuitExists
	}
	shard.inbound[circuit.ID] = inboundCircuit{
		owner:      circuit.Owner,
		transforms: append([]LayerCipher(nil), circuit.Transforms...),
		forward:    forward,
		endpoint:   circuit.Endpoint,
		local:      circuit.Local,
		expiresAt:  circuit.ExpiresAt,
		activity:   new(atomic.Uint64),
	}
	shard.mu.Unlock()
	r.publishActiveTunnelCounts()
	return nil
}

func (r *Runtime) hasCircuit(id uint32) bool {
	if r == nil || id == 0 {
		return true
	}
	shard := r.shard(id)
	shard.mu.RLock()
	_, inbound := shard.inbound[id]
	_, outbound := shard.outbound[id]
	shard.mu.RUnlock()
	return inbound || outbound
}

// CircuitOwner reports the immutable creator owner for a currently installed
// circuit. It is intentionally an inspection API; installation and removal
// remain controlled by build/runtime owners.
func (r *Runtime) CircuitOwner(id uint32) (foundation.Hash, bool) {
	if r == nil || id == 0 {
		return foundation.Hash{}, false
	}
	shard := r.shard(id)
	shard.mu.RLock()
	if circuit, ok := shard.inbound[id]; ok {
		shard.mu.RUnlock()
		return circuit.owner, true
	}
	if circuit, ok := shard.outbound[id]; ok {
		shard.mu.RUnlock()
		return circuit.owner, true
	}
	shard.mu.RUnlock()
	return foundation.Hash{}, false
}

// OutboundActivity returns the number of successfully handed-off blocks on a
// live local outbound circuit. Health checks use it only as passive evidence;
// it does not alter circuit selection.
func (r *Runtime) OutboundActivity(id uint32) (uint64, bool) {
	if r == nil || id == 0 {
		return 0, false
	}
	shard := r.shard(id)
	shard.mu.RLock()
	circuit, ok := shard.outbound[id]
	shard.mu.RUnlock()
	if !ok || circuit.activity == nil || r.expired(circuit.expiresAt) {
		return 0, false
	}
	return circuit.activity.Load(), true
}

// InboundActivity returns the number of successfully parsed and locally
// delivered tunnel messages on a live inbound endpoint circuit.
func (r *Runtime) InboundActivity(id uint32) (uint64, bool) {
	if r == nil || id == 0 {
		return 0, false
	}
	shard := r.shard(id)
	shard.mu.RLock()
	circuit, ok := shard.inbound[id]
	shard.mu.RUnlock()
	if !ok || circuit.activity == nil || r.expired(circuit.expiresAt) {
		return 0, false
	}
	return circuit.activity.Load(), true
}

// RemoveCircuit removes both local-gateway and receive-side state for id.
func (r *Runtime) RemoveCircuit(id uint32) {
	if r == nil || id == 0 {
		return
	}
	shard := r.shard(id)
	shard.mu.Lock()
	delete(shard.inbound, id)
	delete(shard.outbound, id)
	shard.mu.Unlock()
	r.publishActiveTunnelCounts()
}

// RemoveOwner removes all local endpoint and gateway circuits installed for
// one Destination owner. Router exploratory and transit circuits use the zero
// owner and are deliberately unaffected.
func (r *Runtime) RemoveOwner(owner foundation.Hash) {
	if r == nil || owner == (foundation.Hash{}) {
		return
	}
	for index := range r.shards {
		shard := &r.shards[index]
		shard.mu.Lock()
		for id, circuit := range shard.inbound {
			if circuit.owner == owner {
				delete(shard.inbound, id)
			}
		}
		for id, circuit := range shard.outbound {
			if circuit.owner == owner {
				delete(shard.outbound, id)
			}
		}
		shard.mu.Unlock()
	}
	r.publishActiveTunnelCounts()
}

// Expire removes circuits whose configured deadline is at or before nowMillis.
// It is safe to call from a builder maintenance loop while tunnel packet paths
// run on other goroutines.
func (r *Runtime) Expire(nowMillis uint64) (removed int) {
	if r == nil {
		return 0
	}
	for index := range r.shards {
		shard := &r.shards[index]
		shard.mu.Lock()
		for id, circuit := range shard.inbound {
			if circuit.expiresAt != 0 && circuit.expiresAt <= nowMillis {
				delete(shard.inbound, id)
				removed++
			}
		}
		for id, circuit := range shard.outbound {
			if circuit.expiresAt != 0 && circuit.expiresAt <= nowMillis {
				delete(shard.outbound, id)
				removed++
			}
		}
		shard.mu.Unlock()
	}
	if removed != 0 {
		r.publishActiveTunnelCounts()
	}
	return removed
}

// ActiveTunnelCounts reports active local endpoint/gateway circuits separated
// by exploratory (zero owner) and client Destination ownership. Transit
// forwarding circuits are deliberately excluded.
func (r *Runtime) ActiveTunnelCounts() (exploratoryInbound, exploratoryOutbound, clientInbound, clientOutbound uint64) {
	if r == nil {
		return
	}
	for index := range r.shards {
		shard := &r.shards[index]
		shard.mu.RLock()
		for _, circuit := range shard.inbound {
			if circuit.forward != nil || r.expired(circuit.expiresAt) {
				continue
			}
			if circuit.owner == (foundation.Hash{}) {
				exploratoryInbound++
			} else {
				clientInbound++
			}
		}
		for _, circuit := range shard.outbound {
			if r.expired(circuit.expiresAt) {
				continue
			}
			if circuit.owner == (foundation.Hash{}) {
				exploratoryOutbound++
			} else {
				clientOutbound++
			}
		}
		shard.mu.RUnlock()
	}
	return
}

func (r *Runtime) publishActiveTunnelCounts() {
	if r == nil || r.metrics == nil {
		return
	}
	r.metricsMu.Lock()
	exploratoryInbound, exploratoryOutbound, clientInbound, clientOutbound := r.ActiveTunnelCounts()
	r.metrics.SetTunnelExploratoryInboundActive(exploratoryInbound)
	r.metrics.SetTunnelExploratoryOutboundActive(exploratoryOutbound)
	r.metrics.SetTunnelClientInboundActive(clientInbound)
	r.metrics.SetTunnelClientOutboundActive(clientOutbound)
	r.metrics.SetTunnelActive(exploratoryInbound + exploratoryOutbound + clientInbound + clientOutbound)
	r.metricsMu.Unlock()
}

// SendBlock injects one embedded standard I2NP frame into a local outbound
// tunnel. Large frames are fragmented using i2pd tunnel block rules. It uses a
// fixed 64-slot stack batch and releases each pooled slab as soon as the direct
// transport returns, bounding memory during bursts.
func (r *Runtime) SendBlock(ctx context.Context, circuitID uint32, block Block) error {
	if r == nil {
		return ErrCircuitNotFound
	}
	shard := r.shard(circuitID)
	shard.mu.RLock()
	circuit, exists := shard.outbound[circuitID]
	shard.mu.RUnlock()
	if !exists {
		return ErrCircuitNotFound
	}
	if r.expired(circuit.expiresAt) {
		return ErrCircuitExpired
	}
	sender := r.currentSender()
	if sender == nil {
		return ErrTunnelSender
	}
	if block.FollowOn || block.Delivery > DeliveryRouter || len(block.Data) == 0 || len(block.Data) > i2np.I2PDMaxPayload {
		return ErrGatewayBlock
	}

	firstHeader, err := firstBlockLen(block, true)
	if err != nil {
		return err
	}
	count := 1
	if len(block.Data) > maxBlockBytes-firstHeader {
		firstData := maxBlockBytes - firstHeader
		count += (len(block.Data) - firstData + maxBlockBytes - 8) / (maxBlockBytes - 7)
	}
	if count > 64 {
		return ErrGatewayOutput
	}
	var buffers [64]*packet.Buffer
	for index := range count {
		buffer, acquired := packet.Acquire(0, i2np.TunnelDataMessageLen)
		if !acquired {
			releaseBuffers(buffers[:index])
			return ErrGatewayOutput
		}
		buffers[index] = buffer
	}
	count, err = r.gateway.Fragment(circuit.nextTunnelID, block, buffers[:count])
	if err != nil {
		releaseBuffers(buffers[:count])
		return err
	}
	for index := range count {
		buffer := buffers[index]
		payload, ok := buffer.Payload()
		if !ok {
			buffer.Release()
			releaseBuffers(buffers[index+1 : count])
			return ErrGatewayOutput
		}
		err = r.sendTunnelData(ctx, sender, circuit.firstHop, circuit.transforms, payload)
		buffer.Release()
		if err != nil {
			releaseBuffers(buffers[index+1 : count])
			return err
		}
	}
	if circuit.activity != nil {
		circuit.activity.Add(1)
	}
	return nil
}

// HandleGateway injects an embedded standard I2NP message received in a
// TunnelGateway envelope into the named local gateway circuit. Gateway
// envelopes are control-plane inputs, so the frame is revalidated before it
// enters the high-throughput tunnel block path.
func (r *Runtime) HandleGateway(tunnelID uint32, message i2np.Message) error {
	if r == nil {
		return ErrCircuitNotFound
	}
	if err := i2np.ValidatePayload(message.Header.Type, message.Payload); err != nil {
		return err
	}
	buffer, ok := packet.Acquire(0, message.EncodedLen())
	if !ok {
		return ErrGatewayOutput
	}
	frame, ok := buffer.Append(message.EncodedLen())
	if !ok {
		buffer.Release()
		return ErrGatewayOutput
	}
	if _, err := message.MarshalTo(frame); err != nil {
		buffer.Release()
		return err
	}
	err := r.SendBlock(context.Background(), tunnelID, Block{Delivery: DeliveryLocal, Last: true, Data: frame})
	buffer.Release()
	return err
}

// Handle accepts a directly received TunnelData I2NP message using Background.
// Use HandleContext when delivery is coupled to a request lifetime.
func (r *Runtime) Handle(message i2np.Message) error {
	return r.HandleContext(context.Background(), message)
}

// HandleContext transforms one registered receive-side circuit then either
// forwards it to the next participant or dispatches complete endpoint blocks.
func (r *Runtime) HandleContext(ctx context.Context, message i2np.Message) error {
	if r == nil || message.Header.Type != i2np.TunnelData {
		return ErrCircuitDirection
	}
	data, err := i2np.ParseTunnelData(message.Payload)
	if err != nil {
		return err
	}
	shard := r.shard(data.TunnelID)
	shard.mu.RLock()
	circuit, exists := shard.inbound[data.TunnelID]
	shard.mu.RUnlock()
	if !exists {
		return ErrCircuitNotFound
	}
	if r.expired(circuit.expiresAt) {
		return ErrCircuitExpired
	}

	buffer, ok := packet.Acquire(0, i2np.TunnelDataMessageLen)
	if !ok {
		return ErrGatewayOutput
	}
	payload, ok := buffer.Append(i2np.TunnelDataMessageLen)
	if !ok {
		buffer.Release()
		return ErrGatewayOutput
	}
	binary.BigEndian.PutUint32(payload[:4], data.TunnelID)
	copy(payload[4:], data.Data)
	for index := range circuit.transforms {
		if err := circuit.transforms[index].Transform(payload[4:], payload[4:]); err != nil {
			buffer.Release()
			return err
		}
	}

	if circuit.forward != nil {
		binary.BigEndian.PutUint32(payload[:4], circuit.forward.TunnelID)
		sender := r.currentSender()
		if sender == nil {
			buffer.Release()
			return ErrTunnelSender
		}
		err := r.sendTunnelData(ctx, sender, circuit.forward.Peer, nil, payload)
		buffer.Release()
		if err == nil && r.metrics != nil {
			r.metrics.IncTunnelParticipatingForwarded()
		}
		return err
	}

	blocks := r.blocks.Get().(*[]Block)
	count, err := circuit.endpoint.Parse(payload, *blocks)
	if err == nil {
		sender := r.currentSender()
		for _, block := range (*blocks)[:count] {
			if err = r.deliver(ctx, sender, circuit.local, block); err != nil {
				break
			}
		}
	}
	r.blocks.Put(blocks)
	buffer.Release()
	if err == nil && circuit.activity != nil {
		circuit.activity.Add(1)
	}
	return err
}

func (r *Runtime) deliver(ctx context.Context, sender Sender, local func(i2np.Message) error, block Block) error {
	message, used, err := i2np.ParseUnchecked(block.Data)
	if err != nil {
		return err
	}
	if used != len(block.Data) {
		return i2np.ErrMalformed
	}
	switch block.Delivery {
	case DeliveryLocal:
		if local == nil {
			return ErrDeliveryHandler
		}
		return local(message)
	case DeliveryRouter:
		if sender == nil {
			return ErrTunnelSender
		}
		return sender.Send(ctx, block.Gateway, message)
	case DeliveryTunnel:
		if sender == nil {
			return ErrTunnelSender
		}
		buffer, ok := packet.Acquire(0, i2np.TunnelGatewayHeaderLen+message.EncodedLen())
		if !ok {
			return ErrGatewayOutput
		}
		payload, ok := buffer.Append(i2np.TunnelGatewayHeaderLen + message.EncodedLen())
		if !ok {
			buffer.Release()
			return ErrGatewayOutput
		}
		binary.BigEndian.PutUint32(payload[:4], block.TunnelID)
		binary.BigEndian.PutUint16(payload[4:6], uint16(message.EncodedLen()))
		if _, err := message.MarshalTo(payload[6:]); err != nil {
			buffer.Release()
			return err
		}
		err = r.sendMessage(ctx, sender, block.Gateway, i2np.TunnelGateway, payload)
		buffer.Release()
		return err
	default:
		return ErrGatewayBlock
	}
}

func (r *Runtime) sendTunnelData(ctx context.Context, sender Sender, peer foundation.Hash, transforms []LayerCipher, payload []byte) error {
	if len(payload) != i2np.TunnelDataMessageLen {
		return ErrGatewayPayload
	}
	for index := range transforms {
		if err := transforms[index].Transform(payload[4:], payload[4:]); err != nil {
			return err
		}
	}
	return r.sendMessage(ctx, sender, peer, i2np.TunnelData, payload)
}

func (r *Runtime) sendMessage(ctx context.Context, sender Sender, peer foundation.Hash, kind i2np.MessageType, payload []byte) error {
	if sender == nil {
		return ErrTunnelSender
	}
	return sender.Send(ctx, peer, i2np.Message{Header: i2np.Header{
		Type:       kind,
		ID:         r.messageID(),
		Expiration: r.now() + uint64(defaultTunnelTTL/time.Millisecond),
	}, Payload: payload})
}

func (r *Runtime) messageID() uint32 {
	for {
		id := r.nextID.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (r *Runtime) currentSender() Sender {
	if current := r.sender.Load(); current != nil {
		return current.sender
	}
	return nil
}

func (r *Runtime) expired(expiresAt uint64) bool {
	return expiresAt != 0 && expiresAt <= r.now()
}

func (r *Runtime) shard(id uint32) *circuitShard {
	return &r.shards[id&(circuitShards-1)]
}

func releaseBuffers(buffers []*packet.Buffer) {
	for _, buffer := range buffers {
		if buffer != nil {
			buffer.Release()
		}
	}
}
