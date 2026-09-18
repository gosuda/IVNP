package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/durable"
)

var (
	ErrHealthConfig  = errors.New("tunnel: invalid health configuration")
	ErrProbePending  = errors.New("tunnel: probe queue is full")
	ErrProbeNotReady = errors.New("tunnel: probe deferred until bidirectional circuit activity")
	ErrHealthClosed  = errors.New("tunnel: health checker is closed")
)

const (
	defaultMaxPendingProbes       = 64
	defaultHealthFailureThreshold = 3
)

// CircuitPair identifies an outbound test path and the local inbound reply
// route paired with it. OutboundEndpoint is the last outbound hop that must
// route router-delivery blocks. ReplyRouter is the gateway which receives the
// status through InboundID. Peers is a fixed union of the tested paths.
type CircuitPair struct {
	OutboundID       uint32
	OutboundEndpoint foundation.Hash
	InboundID        uint32
	InboundLocalID   uint32
	ReplyRouter      foundation.Hash
	PeerCount        uint8
	Peers            [2 * foundation.I2NPMaxVariableBuildRecords]foundation.Hash
}

type pendingProbe struct {
	peers            [2 * foundation.I2NPMaxVariableBuildRecords]foundation.Hash
	peerCount        uint8
	outboundID       uint32
	circuit          dataplane.TunnelCircuitToken
	inboundLocalID   uint32
	inboundCircuit   dataplane.TunnelCircuitToken
	outboundActivity uint64
	inboundActivity  uint64
	sentAt           uint64
	deadline         uint64
}
type healthMaintainer interface {
	Maintain(context.Context) (int, error)
}

// HealthConfig connects probe accounting to the owner-bound pool maintainer.
// Replacement is started before a failed circuit is discarded, so a
// maintenance/configuration error cannot tear down the last usable path. All
// work is driven by Probe and Expire; the health checker starts no goroutines.
type HealthConfig struct {
	Runtime             dataplane.TunnelCircuitRuntime
	Pool                *Pool
	Maintainer          healthMaintainer
	Profiles            *PeerProfiles
	Now                 func() uint64
	Timeout             uint64
	MaxPending          int
	FailureThreshold    uint8
	ProbeBeforeActivity bool
}

// Health sends delivery-status probes through an outbound/inbound circuit
// pair. Replies are correlated by both their bounded pending ID and timestamp.
type Health struct {
	runtime          dataplane.TunnelCircuitRuntime
	pool             *Pool
	maintainer       healthMaintainer
	profiles         *PeerProfiles
	now              func() uint64
	timeout          uint64
	max              int
	failureThreshold uint8
	requireActivity  bool

	lifecycleMu durable.RWMutex
	mu          sync.Mutex
	nextID      uint32
	pending     map[uint32]pendingProbe
	failures    map[dataplane.TunnelCircuitToken]uint8
	ctx         context.Context
	cancel      context.CancelFunc
	closed      bool
}

func NewHealth(config HealthConfig) (*Health, error) {
	newHealthRejected := config.Runtime == nil || config.Pool == nil || config.Maintainer == nil || config.Profiles == nil || config.Now == nil
	if !newHealthRejected {
		newHealthRejected = config.Timeout == 0
	}
	if newHealthRejected {
		return nil, ErrHealthConfig
	}
	switch maintainer := config.Maintainer.(type) {
	case *Rotator:
		if maintainer == nil || maintainer.runtime != config.Runtime || maintainer.pool != config.Pool {
			return nil, ErrHealthConfig
		}
	case *PairedPoolMaintainer:
		if maintainer == nil || maintainer.runtime != config.Runtime || maintainer.pool != config.Pool {
			return nil, ErrHealthConfig
		}
	default:
		return nil, ErrHealthConfig
	}
	if config.MaxPending <= 0 {
		config.MaxPending = defaultMaxPendingProbes
	}
	if config.FailureThreshold == 0 {
		config.FailureThreshold = defaultHealthFailureThreshold
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	owner := config.Pool.Owner()
	health := &Health{
		runtime: config.Runtime, pool: config.Pool, maintainer: config.Maintainer,
		profiles: config.Profiles, now: config.Now, timeout: config.Timeout,
		max: config.MaxPending, failureThreshold: config.FailureThreshold,
		requireActivity: owner != (foundation.Hash{}) && !config.ProbeBeforeActivity,
		pending:         make(map[uint32]pendingProbe), failures: make(map[dataplane.TunnelCircuitToken]uint8),
		ctx: lifecycle, cancel: cancel,
	}
	for offset := 0; offset < len(owner); offset += 4 {
		health.nextID ^= binary.BigEndian.Uint32(owner[offset : offset+4])
	}
	health.nextID |= uint32(1) << 31
	return health, nil
}

// Probe sends one DeliveryStatus message through pair. The endpoint delivers
// it back through pair's inbound route; callers wire HandleDeliveryStatus to
// that route's local I2NP handler.
func (h *Health) Probe(ctx context.Context, pair CircuitPair, peer foundation.Hash) (uint32, error) {
	h.lifecycleMu.RLock()
	defer h.lifecycleMu.RUnlock()
	if h.closed {
		return 0, ErrHealthClosed
	}
	if ctx == nil {
		ctx =
			context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	probeRejected := pair.OutboundID == 0 || pair.InboundID == 0 || pair.ReplyRouter == (foundation.Hash{})
	if !probeRejected {
		probeRejected = (pair.PeerCount == 0 && peer == (foundation.Hash{}))
	}
	if probeRejected {
		return 0, ErrHealthConfig
	}
	if h.requireActivity && !h.pairActive(pair) {
		return 0, ErrProbeNotReady
	}
	now := h.now()
	deadline := now + h.timeout
	if deadline < now {
		deadline = ^uint64(0)
	}
	info, exists := h.runtime.InspectCircuit(pair.OutboundID)
	if !exists || info.Owner != h.pool.Owner() {
		return 0, ErrHealthConfig
	}
	h.mu.Lock()
	if len(h.pending) >= h.max {
		h.mu.Unlock()
		return 0, ErrProbePending
	}
	for _, pending := range h.pending {
		if pending.outboundID == pair.OutboundID {
			h.mu.Unlock()
			return 0, ErrProbePending
		}
	}
	id := h.nextPendingIDLocked()
	probe := pendingProbe{outboundID: pair.OutboundID, circuit: info.Token, inboundLocalID: pair.InboundLocalID, sentAt: now, deadline: deadline}
	if pair.PeerCount != 0 {
		probe.peerCount = min(pair.PeerCount, uint8(len(probe.peers)))
		copy(probe.peers[:], pair.Peers[:probe.peerCount])
	} else {
		probe.peerCount = 1
		probe.peers[0] = peer
	}
	if pair.InboundLocalID != 0 {
		var ok bool
		probe.outboundActivity, ok = h.runtime.OutboundActivity(pair.OutboundID)
		if !ok {
			h.mu.Unlock()
			return 0, ErrHealthConfig
		}
		probe.inboundActivity, ok = h.runtime.InboundActivity(pair.InboundLocalID)
		if !ok {
			h.mu.Unlock()
			return 0, ErrHealthConfig
		}
		if inEntry, inOK := h.pool.Get(pair.InboundLocalID, now); inOK {
			probe.inboundCircuit = inEntry.Circuit
		}
	}
	h.pending[id] = probe
	h.mu.Unlock()

	var payload [12]byte
	binary.BigEndian.PutUint32(payload[:4], id)
	binary.BigEndian.PutUint64(payload[4:], now)
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDeliveryStatus, ID: id, Expiration: deadline},
		Payload: payload[:],
	}
	var frame [foundation.I2NPStandardHeaderLen + len(payload)]byte
	if _, err := message.MarshalTo(frame[:]); err != nil {
		h.dropPending(id)
		return 0, err
	}
	if err := h.runtime.SendBlockPrepared(ctx, probe.circuit, dataplane.TunnelBlock{
		Delivery: dataplane.TunnelDeliveryTunnel, Gateway: pair.ReplyRouter, TunnelID: pair.InboundID, Last: true, Data: frame[:],
	}); err != nil {
		h.dropPending(id)
		_ = h.fail(ctx, probe)
		return 0, err
	}
	if pair.InboundLocalID != 0 {
		if activity, ok := h.runtime.OutboundActivity(pair.OutboundID); ok {
			h.mu.Lock()
			if current, exists := h.pending[id]; exists {
				current.outboundActivity = activity
				h.pending[id] = current
			}
			h.mu.Unlock()
		}
	}
	return id, nil
}

// HandleMessage parses a local inbound I2NP delivery before correlating it as
// a probe result. It is suitable as the Local callback of the paired inbound
// endpoint.
func (h *Health) HandleMessage(message foundation.I2NPMessage) error {
	if message.Header.Type != foundation.I2NPDeliveryStatus {
		return foundation.I2NPErrMalformed
	}
	status, err := foundation.I2NPParseDeliveryStatus(message.Payload)
	if err != nil {
		return err
	}
	h.HandleDeliveryStatus(status)
	return nil
}

// HandleDeliveryStatus records a successful matching probe. Unknown, expired,
// and timestamp-mismatched statuses are ignored rather than changing health.
func (h *Health) HandleDeliveryStatus(status foundation.I2NPDeliveryStatusMessage) bool {
	h.lifecycleMu.RLock()
	defer h.lifecycleMu.RUnlock()
	if h.closed {
		return false
	}
	now := h.now()
	h.mu.Lock()
	probe, ok := h.pending[status.MessageID]
	if !ok || probe.deadline <= now || status.Timestamp != probe.sentAt {
		h.mu.Unlock()
		return false
	}
	delete(h.pending, status.MessageID)
	h.mu.Unlock()
	h.clearFailures(probe.circuit)
	if probe.inboundCircuit != (dataplane.TunnelCircuitToken{}) {
		h.clearFailures(probe.inboundCircuit)
	}
	h.record(probe, true, now-probe.sentAt)
	return true
}

// Expire marks overdue probes as failed, removes their unhealthy outbound
// circuits, and asks the existing Rotator to start needed replacement builds.
func (h *Health) Expire(ctx context.Context) (expired int, err error) {
	h.lifecycleMu.RLock()
	defer h.lifecycleMu.RUnlock()
	if h.closed {
		return 0, ErrHealthClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	now := h.now()
	h.mu.Lock()
	failed := make([]pendingProbe, 0)
	for id, probe := range h.pending {
		if probe.deadline <= now {
			delete(h.pending, id)
			failed = append(failed, probe)
		}
	}
	h.mu.Unlock()
	for index := range failed {
		expired++
		if h.passedTraffic(failed[index]) {
			h.clearFailures(failed[index].circuit)
			if failed[index].inboundCircuit != (dataplane.TunnelCircuitToken{}) {
				h.clearFailures(failed[index].inboundCircuit)
			}
			continue
		}
		if err = h.fail(ctx, failed[index]); err != nil {
			return expired, err
		}
	}
	return expired, nil
}

func (h *Health) passedTraffic(probe pendingProbe) bool {
	if probe.inboundLocalID == 0 {
		return false
	}
	outbound, outboundOK := h.runtime.OutboundActivity(probe.outboundID)
	inbound, inboundOK := h.runtime.InboundActivity(probe.inboundLocalID)
	return outboundOK && inboundOK && outbound > probe.outboundActivity && inbound > probe.inboundActivity
}

func (h *Health) pairActive(pair CircuitPair) bool {
	if pair.InboundLocalID == 0 {
		return false
	}
	outbound, outboundOK := h.runtime.OutboundActivity(pair.OutboundID)
	inbound, inboundOK := h.runtime.InboundActivity(pair.InboundLocalID)
	return outboundOK && inboundOK && outbound != 0 && inbound != 0
}

func (h *Health) clearFailures(circuit dataplane.TunnelCircuitToken) {
	h.mu.Lock()
	delete(h.failures, circuit)
	h.mu.Unlock()
}

// Pending reports the bounded number of probes awaiting a matching status.
func (h *Health) Pending() int {
	h.mu.Lock()
	count := len(h.pending)
	h.mu.Unlock()
	return count
}

// Close cancels active probe work, rejects future work, and clears every
// pending correlation before returning.
func (h *Health) Close() error {
	if h == nil {
		return nil
	}
	h.cancel()
	h.lifecycleMu.Lock()
	if !h.closed {
		h.closed = true
		h.mu.Lock()
		clear(h.pending)
		clear(h.failures)
		h.mu.Unlock()
	}
	h.lifecycleMu.Unlock()
	return nil
}

func (h *Health) nextPendingIDLocked() uint32 {
	for {
		h.nextID = (h.nextID + 1) | (uint32(1) << 31)
		if h.nextID == uint32(1)<<31 {
			h.nextID++
		}
		if _, exists := h.pending[h.nextID]; !exists {
			return h.nextID
		}
	}
}

func (h *Health) dropPending(id uint32) {
	h.mu.Lock()
	delete(h.pending, id)
	h.mu.Unlock()
}

func (h *Health) fail(ctx context.Context, probe pendingProbe) error {
	return h.failExplicit(ctx, probe, 1, 1)
}

func (h *Health) failExplicit(ctx context.Context, probe pendingProbe, outIncrement, inIncrement uint8) error {
	h.record(probe, false, 0)
	h.mu.Lock()
	outFailures := h.failures[probe.circuit] + outIncrement
	h.failures[probe.circuit] = outFailures
	var inFailures uint8
	if probe.inboundCircuit != (dataplane.TunnelCircuitToken{}) {
		inFailures = h.failures[probe.inboundCircuit] + inIncrement
		h.failures[probe.inboundCircuit] = inFailures
	}
	outFailed := outFailures >= h.failureThreshold
	inFailed := inFailures >= h.failureThreshold
	if !outFailed && !inFailed {
		h.mu.Unlock()
		return nil
	}
	if outFailed {
		delete(h.failures, probe.circuit)
	}
	if inFailed && probe.inboundCircuit != (dataplane.TunnelCircuitToken{}) {
		delete(h.failures, probe.inboundCircuit)
	}
	h.mu.Unlock()
	now := h.now()
	var outEntry, inEntry Entry
	var haveOutEntry, haveInEntry bool
	if outFailed {
		if entry, ok := h.pool.Get(probe.outboundID, now); ok && entry.Circuit == probe.circuit {
			if h.pool.Remove(entry) {
				outEntry, haveOutEntry = entry, true
			}
		}
	}
	if inFailed && probe.inboundLocalID != 0 {
		if entry, ok := h.pool.Get(probe.inboundLocalID, now); ok && entry.Direction == Inbound {
			if h.pool.Remove(entry) {
				inEntry, haveInEntry = entry, true
			}
		}
	}
	if !haveOutEntry && !haveInEntry {
		return nil
	}
	_, err := h.maintainer.Maintain(ctx)
	if err != nil {
		if haveOutEntry && h.pool.Count(outEntry.Direction, h.now()) == 0 {
			_ = h.pool.Add(outEntry, h.now())
			haveOutEntry = false
		}
		if haveInEntry && h.pool.Count(inEntry.Direction, h.now()) == 0 {
			_ = h.pool.Add(inEntry, h.now())
			haveInEntry = false
		}
		if !haveOutEntry && !haveInEntry {
			return err
		}
	}
	if haveOutEntry {
		h.runtime.RemoveCircuit(probe.circuit)
	}
	if haveInEntry {
		h.runtime.RemoveCircuit(inEntry.Circuit)
	}
	return err
}

func (h *Health) record(probe pendingProbe, success bool, latency uint64) {
	for index := range int(probe.peerCount) {
		h.profiles.Record(probe.peers[index], Observation{Kind: DeliveryObservation, Success: success, LatencyMillis: latency, AtMillis: h.now()})
	}
}
