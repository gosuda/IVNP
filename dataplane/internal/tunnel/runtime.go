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
	"gosuda.org/ivnp/observability"
)

const (
	defaultTunnelTTL = time.Minute
	// Java I2P FragmentHandler removes incomplete messages after 45 seconds.
	fragmentReassemblyLifetime = 45 * time.Second
	defaultDeliveryBlocks      = TunnelPayloadLen / 3
	circuitShards              = 64
)

var (
	ErrCircuitID        = errors.New("tunnel: invalid circuit ID")
	ErrCircuitExists    = errors.New("tunnel: circuit already exists")
	ErrCircuitOwner     = errors.New("tunnel: replacement owner mismatch")
	ErrCircuitNotFound  = errors.New("tunnel: circuit not found")
	ErrCircuitExpired   = errors.New("tunnel: circuit expired")
	ErrCircuitDirection = errors.New("tunnel: invalid circuit direction")
	ErrTunnelSender     = errors.New("tunnel: sender unavailable")
	ErrDeliveryHandler  = errors.New("tunnel: local delivery handler unavailable")
)

// Sender sends an I2NP message to a directly connected router.
type Sender interface {
	Send(context.Context, foundation.Hash, foundation.I2NPMessage) error
}

// Forward identifies the next hop in a transit tunnel.
type Forward struct {
	Peer     foundation.Hash
	TunnelID uint32
}

// OutboundCircuit represents the local gateway for an outbound tunnel.
type OutboundCircuit struct {
	ID           uint32
	Owner        foundation.Hash
	FirstHop     foundation.Hash
	NextTunnelID uint32
	Transforms   []LayerCipher
	ExpiresAt    uint64
}

// InboundCircuit represents either a transit participant or local endpoint inbound tunnel.
type InboundCircuit struct {
	ID         uint32
	Owner      foundation.Hash
	Transforms []LayerCipher
	Forward    *Forward
	Endpoint   *Endpoint
	Local      func(foundation.I2NPMessage) error
	ExpiresAt  uint64
}

type inboundCircuit struct {
	lifetime   circuitLifetime
	owner      foundation.Hash
	transforms []LayerCipher
	forward    *Forward
	endpoint   *Endpoint
	local      func(foundation.I2NPMessage) error
	expiresAt  uint64
	activity   *atomic.Uint64
}

type outboundCircuit struct {
	lifetime     circuitLifetime
	owner        foundation.Hash
	firstHop     foundation.Hash
	nextTunnelID uint32
	transforms   []LayerCipher
	expiresAt    uint64
	activity     *atomic.Uint64
}

type circuitShard struct {
	mu       sync.RWMutex
	inbound  map[uint32]*inboundCircuit
	outbound map[uint32]*outboundCircuit
}

type senderBox struct{ sender Sender }

// RuntimeConfig configures a tunnel Runtime instance.
type RuntimeConfig struct {
	Sender  Sender
	Gateway *Gateway
	Now     func() uint64
	Metrics *observability.Registry
}

// Runtime manages active inbound and outbound tunnel circuits and routes tunnel messages.
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
		runtime.shards[index].inbound = make(map[uint32]*inboundCircuit)
		runtime.shards[index].outbound = make(map[uint32]*outboundCircuit)
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

// RegisterOutbound installs an unoccupied local gateway circuit.
func (r *Runtime) RegisterOutbound(circuit OutboundCircuit) (CircuitToken, error) {
	return r.installOutbound(circuit, CircuitToken{})
}

func (r *Runtime) installOutbound(circuit OutboundCircuit, previous CircuitToken) (CircuitToken, error) {
	if r == nil || circuit.ID == 0 || circuit.NextTunnelID == 0 {
		return CircuitToken{}, ErrCircuitID
	}
	shard := r.shard(circuit.ID)
	shard.mu.Lock()
	if r.expired(circuit.ExpiresAt) {
		shard.mu.Unlock()
		return CircuitToken{}, ErrCircuitExpired
	}
	old := shard.outbound[circuit.ID]
	if previous.generation != nil {
		if old == nil || &old.lifetime != previous.generation {
			shard.mu.Unlock()
			return CircuitToken{}, ErrCircuitNotFound
		}
		if old.owner != circuit.Owner {
			shard.mu.Unlock()
			return CircuitToken{}, ErrCircuitOwner
		}
	} else if old != nil || shard.inbound[circuit.ID] != nil {
		shard.mu.Unlock()
		return CircuitToken{}, ErrCircuitExists
	}
	installed := &outboundCircuit{
		owner: circuit.Owner, firstHop: circuit.FirstHop, nextTunnelID: circuit.NextTunnelID,
		transforms: append([]LayerCipher(nil), circuit.Transforms...), expiresAt: circuit.ExpiresAt,
		activity: new(atomic.Uint64),
	}
	installed.lifetime.refs.Store(1)
	shard.outbound[circuit.ID] = installed
	shard.mu.Unlock()
	if old != nil {
		old.release()
	}
	r.publishActiveTunnelCounts()
	return CircuitToken{circuit.ID, &installed.lifetime}, nil
}

// RegisterInbound takes exclusive ownership of Endpoint on success. Endpoint
// state cannot be installed again, including after its circuit is retired.
func (r *Runtime) RegisterInbound(circuit InboundCircuit) (CircuitToken, error) {
	return r.installInbound(circuit, CircuitToken{})
}

func (r *Runtime) installInbound(circuit InboundCircuit, previous CircuitToken) (CircuitToken, error) {
	if r == nil || circuit.ID == 0 {
		return CircuitToken{}, ErrCircuitID
	}
	if (circuit.Forward == nil) == (circuit.Endpoint == nil) {
		return CircuitToken{}, ErrCircuitDirection
	}
	var forward *Forward
	if circuit.Forward != nil {
		if circuit.Forward.TunnelID == 0 {
			return CircuitToken{}, ErrCircuitID
		}
		copy := *circuit.Forward
		forward = &copy
	}
	shard := r.shard(circuit.ID)
	shard.mu.Lock()
	if r.expired(circuit.ExpiresAt) {
		shard.mu.Unlock()
		return CircuitToken{}, ErrCircuitExpired
	}
	old := shard.inbound[circuit.ID]
	if previous.generation != nil {
		if old == nil || &old.lifetime != previous.generation {
			shard.mu.Unlock()
			return CircuitToken{}, ErrCircuitNotFound
		}
		if old.owner != circuit.Owner {
			shard.mu.Unlock()
			return CircuitToken{}, ErrCircuitOwner
		}
	} else if old != nil || shard.outbound[circuit.ID] != nil {
		shard.mu.Unlock()
		return CircuitToken{}, ErrCircuitExists
	}
	if circuit.Endpoint != nil && circuit.Endpoint.installed.Swap(true) {
		shard.mu.Unlock()
		return CircuitToken{}, ErrCircuitExists
	}
	installed := &inboundCircuit{
		owner: circuit.Owner, transforms: append([]LayerCipher(nil), circuit.Transforms...),
		forward: forward, endpoint: circuit.Endpoint, local: circuit.Local,
		expiresAt: circuit.ExpiresAt, activity: new(atomic.Uint64),
	}
	installed.lifetime.refs.Store(1)
	shard.inbound[circuit.ID] = installed
	shard.mu.Unlock()
	if old != nil {
		old.release()
	}
	r.publishActiveTunnelCounts()
	return CircuitToken{circuit.ID, &installed.lifetime}, nil
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

// RemoveCircuit retires only the installation identified by token. It never
// waits for a packet or callback; sensitive state is released by the last user.
func (r *Runtime) RemoveCircuit(token CircuitToken) bool {
	if r == nil || token.id == 0 || token.generation == nil {
		return false
	}
	shard := r.shard(token.id)
	shard.mu.Lock()
	removed := false
	if circuit := shard.inbound[token.id]; circuit != nil && &circuit.lifetime == token.generation {
		delete(shard.inbound, token.id)
		circuit.release()
		removed = true
	}
	if circuit := shard.outbound[token.id]; circuit != nil && &circuit.lifetime == token.generation {
		delete(shard.outbound, token.id)
		circuit.release()
		removed = true
	}
	shard.mu.Unlock()
	if removed {
		r.publishActiveTunnelCounts()
	}
	return removed
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
				circuit.release()
			}
		}
		for id, circuit := range shard.outbound {
			if circuit.owner == owner {
				delete(shard.outbound, id)
				circuit.release()
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
	fragmentLifetimeMillis := uint64(fragmentReassemblyLifetime / time.Millisecond)
	expireFragments := nowMillis >= fragmentLifetimeMillis
	var fragmentCutoff uint64
	if expireFragments {
		fragmentCutoff = nowMillis - fragmentLifetimeMillis
	}
	for index := range r.shards {
		shard := &r.shards[index]
		shard.mu.Lock()
		for id, circuit := range shard.inbound {
			if circuit.expiresAt != 0 && circuit.expiresAt <= nowMillis {
				delete(shard.inbound, id)
				circuit.release()
				removed++
				continue
			}
			if expireFragments && circuit.endpoint != nil {
				circuit.endpoint.Expire(fragmentCutoff)
			}
		}
		for id, circuit := range shard.outbound {
			if circuit.expiresAt != 0 && circuit.expiresAt <= nowMillis {
				delete(shard.outbound, id)
				circuit.release()
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
	return r.sendBlock(ctx, circuitID, nil, block)
}

// SendBlockPrepared executes only the installation selected by control policy.
func (r *Runtime) SendBlockPrepared(ctx context.Context, token CircuitToken, block Block) error {
	if token.generation == nil {
		return ErrCircuitNotFound
	}
	return r.sendBlock(ctx, token.id, token.generation, block)
}

func (r *Runtime) sendBlock(ctx context.Context, circuitID uint32, generation *circuitLifetime, block Block) error {
	if r == nil {
		return ErrCircuitNotFound
	}
	shard := r.shard(circuitID)
	shard.mu.RLock()
	circuit, exists := shard.outbound[circuitID]
	if !exists || generation != nil && &circuit.lifetime != generation {
		shard.mu.RUnlock()
		return ErrCircuitNotFound
	}
	if r.expired(circuit.expiresAt) {
		shard.mu.RUnlock()
		return ErrCircuitExpired
	}
	circuit.lifetime.refs.Add(1)
	shard.mu.RUnlock()
	defer circuit.release()
	sender := r.currentSender()
	if sender == nil {
		return ErrTunnelSender
	}
	if block.FollowOn || block.Delivery > DeliveryRouter || len(block.Data) == 0 || len(block.Data) > foundation.I2NPI2PDMaxPayload {
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
		buffer, acquired := packet.Acquire(0, foundation.I2NPTunnelDataMessageLen)
		if !acquired {
			releaseBuffers(buffers[:index])
			return ErrGatewayOutput
		}
		buffers[index] = buffer
	}
	written, err := r.gateway.Fragment(circuit.nextTunnelID, block, buffers[:count])
	if err != nil {
		releaseBuffers(buffers[:count])
		return err
	}
	count = written
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
// TunnelGateway envelope into the named local gateway circuit. ParseTunnelGateway
// has already validated the embedded frame; its payload remains opaque so an
// IBGW can relay future I2NP types exactly as Java I2P does.
func (r *Runtime) HandleGateway(tunnelID uint32, message foundation.I2NPMessage) error {
	if r == nil {
		return ErrCircuitNotFound
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
func (r *Runtime) Handle(message foundation.I2NPMessage) error {
	return r.HandleContext(context.Background(), message)
}

// HandleContext transforms one registered receive-side circuit then either
// forwards it to the next participant or dispatches complete endpoint blocks.
func (r *Runtime) HandleContext(ctx context.Context, message foundation.I2NPMessage) error {
	if r == nil || message.Header.Type != foundation.I2NPTunnelData {
		return ErrCircuitDirection
	}
	data, err := foundation.I2NPParseTunnelData(message.Payload)
	if err != nil {
		return err
	}
	shard := r.shard(data.TunnelID)
	shard.mu.RLock()
	circuit, exists := shard.inbound[data.TunnelID]
	if !exists {
		shard.mu.RUnlock()
		return ErrCircuitNotFound
	}
	if r.expired(circuit.expiresAt) {
		shard.mu.RUnlock()
		return ErrCircuitExpired
	}
	circuit.lifetime.refs.Add(1)
	shard.mu.RUnlock()
	defer circuit.release()

	buffer, ok := packet.Acquire(0, foundation.I2NPTunnelDataMessageLen)
	if !ok {
		return ErrGatewayOutput
	}
	payload, ok := buffer.Append(foundation.I2NPTunnelDataMessageLen)
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
	count, err := circuit.endpoint.Parse(payload, *blocks, r.now())
	if err == nil {
		sender := r.currentSender()
		for _, block := range (*blocks)[:count] {
			if err = r.deliver(ctx, sender, circuit.local, block); err != nil {
				break
			}
		}
	}
	clear((*blocks)[:count])
	r.blocks.Put(blocks)
	buffer.Release()
	if err == nil && circuit.activity != nil {
		circuit.activity.Add(1)
	}
	return err
}

func (r *Runtime) deliver(ctx context.Context, sender Sender, local func(foundation.I2NPMessage) error, block Block) error {
	message, used, err := foundation.I2NPParseUnchecked(block.Data)
	if err != nil {
		return err
	}
	if used != len(block.Data) {
		return foundation.I2NPErrMalformed
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
		buffer, ok := packet.Acquire(0, foundation.I2NPTunnelGatewayHeaderLen+message.EncodedLen())
		if !ok {
			return ErrGatewayOutput
		}
		payload, ok := buffer.Append(foundation.I2NPTunnelGatewayHeaderLen + message.EncodedLen())
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
		err = r.sendMessage(ctx, sender, block.Gateway, foundation.I2NPTunnelGateway, payload)
		buffer.Release()
		return err
	default:
		return ErrGatewayBlock
	}
}

func (r *Runtime) sendTunnelData(ctx context.Context, sender Sender, peer foundation.Hash, transforms []LayerCipher, payload []byte) error {
	if len(payload) != foundation.I2NPTunnelDataMessageLen {
		return ErrGatewayPayload
	}
	for index := range transforms {
		if err := transforms[index].Transform(payload[4:], payload[4:]); err != nil {
			return err
		}
	}
	return r.sendMessage(ctx, sender, peer, foundation.I2NPTunnelData, payload)
}

func (r *Runtime) sendMessage(ctx context.Context, sender Sender, peer foundation.Hash, kind foundation.I2NPMessageType, payload []byte) error {
	if sender == nil {
		return ErrTunnelSender
	}
	return sender.Send(ctx, peer, foundation.I2NPMessage{Header: foundation.I2NPHeader{
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
