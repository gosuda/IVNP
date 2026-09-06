// Package router coordinates I2NP message dispatch, transport managers, and router lifecycle.
package router

import (
	"context"
	"errors"
	"sync"

	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
)

var (
	ErrExpired          = errors.New("router: expired I2NP message")
	ErrFutureExpiration = errors.New("router: I2NP message expiration is too far in the future")
	ErrDuplicate        = errors.New("router: duplicate I2NP message")
	ErrUnhandledI2NP    = errors.New("router: unhandled I2NP message")
)

const (
	i2npMessageClockSkewMillis uint64 = 60_000
	i2npMessageMaxFutureMillis        = 3 * i2npMessageClockSkewMillis
	replayBucketDurationMillis        = i2npMessageClockSkewMillis
	replayBucketCount                 = 5
	replayFilterBits                  = 1 << 18
	replayFilterWords                 = replayFilterBits / 64
	replayFilterHashes                = 4
)

type replayShard struct {
	mu      sync.Mutex
	buckets [replayBucketCount][]uint64
	epoch   uint64
	current uint8
	started bool
}

type replayFilter struct {
	once   sync.Once
	shards []replayShard
}

// I2NPSource tracks the origin peer and transport connection type for a received message.
type I2NPSource struct {
	Peer   foundation.Hash
	Direct bool
}

type Sinks struct {
	Router        func(foundation.Hash, foundation.I2NPMessage) error
	Destination   func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error
	Tunnel        func(foundation.Hash, uint32, foundation.I2NPMessage) error
	Garlic        func(I2NPSource, foundation.I2NPMessage) error
	TunnelData    func(foundation.I2NPMessage) error
	TunnelGateway func(uint32, foundation.I2NPMessage) error
	Control       ControlIngress
}

// Service provides I2NP message admission, replay filtering, and dispatch.
type Service struct {
	sinks  Sinks
	replay replayFilter
}

type replayScope uint64

const (
	replayI2NP replayScope = iota
	replayGarlicSet
	replayGarlicClove
)

type preparedI2NP struct {
	gateway foundation.I2NPTunnelGatewayMessage
}

func NewService(sinks Sinks) *Service {
	return &Service{sinks: sinks}
}

// SetControlIngress installs the nonblocking control handoff before ingress starts.
func (s *Service) SetControlIngress(control ControlIngress) {
	s.sinks.Control = control
}

// SetTunnelDataSink installs the authenticated TunnelData hand-off before
// transports start. Router.New uses it to wire an embedded tunnel Runtime
// without making the Service depend on a concrete circuit implementation.
func (s *Service) SetTunnelDataSink(sink func(foundation.I2NPMessage) error) {
	s.sinks.TunnelData = sink
}

// SetTunnelGatewaySink installs the pre-transport tunnel-gateway injection
// hand-off before transports start.
func (s *Service) SetTunnelGatewaySink(sink func(uint32, foundation.I2NPMessage) error) {
	s.sinks.TunnelGateway = sink
}

// SetRouterSink installs router-directed Garlic clove forwarding.
func (s *Service) SetRouterSink(sink func(foundation.Hash, foundation.I2NPMessage) error) {
	s.sinks.Router = sink
}

// SetTunnelSink installs tunnel-directed Garlic clove forwarding.
func (s *Service) SetTunnelSink(sink func(foundation.Hash, uint32, foundation.I2NPMessage) error) {
	s.sinks.Tunnel = sink
}

// SetGarlicSink installs authenticated Garlic ciphertext processing.
func (s *Service) SetGarlicSink(sink func(I2NPSource, foundation.I2NPMessage) error) {
	s.sinks.Garlic = sink
}

// SetDestinationSink installs parsed Garlic destination-clove delivery.
func (s *Service) SetDestinationSink(sink func(foundation.Hash, foundation.Hash, foundation.I2NPMessage) error) {
	s.sinks.Destination = sink
}

// HandleI2NP validates and dispatches an authenticated I2NP frame.
func (s *Service) HandleI2NP(message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
	return s.handleI2NP(message, nowMillis, fromFloodfill, I2NPSource{})
}

// HandleI2NPFrom validates and dispatches an I2NP frame from an identified peer with rate-limiting.
func (s *Service) HandleI2NPFrom(peer foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
	return s.handleI2NP(message, nowMillis, fromFloodfill, I2NPSource{Peer: peer, Direct: true})
}

// HandleI2NPFromContext validates and dispatches an I2NP frame respecting context cancellation.
func (s *Service) HandleI2NPFromContext(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.handleI2NP(message, nowMillis, fromFloodfill, I2NPSource{Peer: peer, Direct: true})
	if err != nil {
		return err
	}
	return ctx.Err()
}

func (s *Service) handleI2NP(message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool, source I2NPSource) error {
	prepared, err := s.prepareI2NP(message, nowMillis, true)
	if err != nil {
		return err
	}
	if s.seen(replayI2NP, message.Header.ID, message.Header.Expiration, nowMillis) {
		return ErrDuplicate
	}
	return s.dispatchPreparedI2NP(source, message, prepared, nowMillis, fromFloodfill)
}

func (s *Service) prepareI2NP(message foundation.I2NPMessage, nowMillis uint64, requireSink bool) (preparedI2NP, error) {
	if err := validateI2NPExpiration(message.Header.Expiration, nowMillis); err != nil {
		return preparedI2NP{}, err
	}

	switch message.Header.Type {
	case foundation.I2NPDatabaseStore, foundation.I2NPDatabaseLookup, foundation.I2NPDatabaseSearchReply, foundation.I2NPDeliveryStatus:
		if err := foundation.I2NPValidatePayload(message.Header.Type, message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && !s.acceptsControl(message) {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPGarlic:
		if _, err := foundation.I2NPParseGarlic(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.Garlic == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPData:
		if _, err := foundation.I2NPParseData(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		// Data is meaningful only under an authenticated Garlic destination
		// delivery instruction; it has no direct-router dispatch route.
		if requireSink {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPTunnelData:
		if _, err := foundation.I2NPParseTunnelData(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelData == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPTunnelGateway:
		gateway, err := foundation.I2NPParseTunnelGateway(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelGateway == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{gateway: gateway}, nil
	case foundation.I2NPOutboundTunnelBuildReply:
		if _, err := foundation.I2NPParseBuildRecords(message.Header.Type, message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPTunnelBuild, foundation.I2NPTunnelBuildReply, foundation.I2NPVariableTunnelBuild, foundation.I2NPVariableTunnelBuildReply, foundation.I2NPShortTunnelBuild:
		if _, err := foundation.I2NPParseBuildRecords(message.Header.Type, message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && !s.acceptsControl(message) {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case foundation.I2NPTunnelTest:
		if _, err := foundation.I2NPParseTunnelTest(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && !s.acceptsControl(message) {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	default:
		return preparedI2NP{}, ErrUnhandledI2NP
	}
}

func (s *Service) dispatchPreparedI2NP(source I2NPSource, message foundation.I2NPMessage, prepared preparedI2NP, nowMillis uint64, fromFloodfill bool) error {
	switch message.Header.Type {
	case foundation.I2NPGarlic:
		return s.sinks.Garlic(source, message)
	case foundation.I2NPTunnelData:
		return s.sinks.TunnelData(message)
	case foundation.I2NPTunnelGateway:
		return s.sinks.TunnelGateway(prepared.gateway.TunnelID, prepared.gateway.Embedded)
	default:
		if s.acceptsControl(message) {
			return s.sinks.Control.Enqueue(ControlMessage{Source: source, Message: message, NowMillis: nowMillis, FromFloodfill: fromFloodfill})
		}
	}
	return ErrUnhandledI2NP
}

func (s *Service) acceptsControl(message foundation.I2NPMessage) bool {
	return s.sinks.Control != nil && s.sinks.Control.Accepts(message)
}

// HandleGarlicCloveSet dispatches decrypted garlic cloves through I2NP replay filters and sinks.
func (s *Service) HandleGarlicCloveSet(set dataplanegarlic.CloveSet, nowMillis uint64, fromFloodfill bool) error {
	if err := validateI2NPExpiration(set.Expiration, nowMillis); err != nil {
		return err
	}
	if s.seen(replayGarlicSet, set.MessageID, set.Expiration, nowMillis) {
		return ErrDuplicate
	}

	var result error
	iterator := set.Cloves()
	for {
		clove, ok, err := iterator.Next()
		if err != nil {
			return appendError(result, err)
		}
		if !ok {
			return result
		}
		if err = validateI2NPExpiration(clove.Expiration, nowMillis); err != nil {
			result = appendError(result, err)
			continue
		}
		prepared, err := s.prepareClove(clove.Delivery, clove.Message, nowMillis)
		if err != nil {
			result = appendError(result, err)
			continue
		}
		if s.seen(replayGarlicClove, clove.ID, clove.Expiration, nowMillis) {
			result = appendError(result, ErrDuplicate)
			continue
		}
		if s.seen(replayI2NP, clove.Message.Header.ID, clove.Message.Header.Expiration, nowMillis) {
			result = appendError(result, ErrDuplicate)
			continue
		}
		if err = s.dispatchPreparedClove(foundation.Hash{}, clove.Delivery, clove.Message, prepared, nowMillis, fromFloodfill); err != nil {
			result = appendError(result, err)
		}
	}
}

func (s *Service) dispatchClove(source foundation.Hash, delivery dataplanegarlic.Delivery, message foundation.I2NPMessage, nowMillis uint64, fromFloodfill bool) error {
	prepared, err := s.prepareClove(delivery, message, nowMillis)
	if err != nil {
		return err
	}
	if s.seen(replayI2NP, message.Header.ID, message.Header.Expiration, nowMillis) {
		return ErrDuplicate
	}
	return s.dispatchPreparedClove(source, delivery, message, prepared, nowMillis, fromFloodfill)
}

func (s *Service) prepareClove(delivery dataplanegarlic.Delivery, message foundation.I2NPMessage, nowMillis uint64) (preparedI2NP, error) {
	requireSink := delivery.Type == dataplanegarlic.DeliveryLocal
	if requireSink && message.Header.Type == foundation.I2NPOutboundTunnelBuildReply && s.acceptsControl(message) {
		requireSink = false
	}
	prepared, err := s.prepareI2NP(message, nowMillis, requireSink)
	if err != nil {
		return preparedI2NP{}, err
	}
	switch delivery.Type {
	case dataplanegarlic.DeliveryLocal:
		return prepared, nil
	case dataplanegarlic.DeliveryRouter:
		if s.sinks.Router != nil {
			return prepared, nil
		}
	case dataplanegarlic.DeliveryDestination:
		if s.sinks.Destination != nil {
			return prepared, nil
		}
	case dataplanegarlic.DeliveryTunnel:
		if s.sinks.Tunnel != nil {
			return prepared, nil
		}
	}
	return preparedI2NP{}, ErrUnhandledI2NP
}

func (s *Service) dispatchPreparedClove(source foundation.Hash, delivery dataplanegarlic.Delivery, message foundation.I2NPMessage, prepared preparedI2NP, nowMillis uint64, fromFloodfill bool) error {
	switch delivery.Type {
	case dataplanegarlic.DeliveryLocal:
		return s.dispatchPreparedI2NP(I2NPSource{Peer: source}, message, prepared, nowMillis, fromFloodfill)
	case dataplanegarlic.DeliveryRouter:
		return s.sinks.Router(delivery.To, message)
	case dataplanegarlic.DeliveryDestination:
		return s.sinks.Destination(source, delivery.To, message)
	case dataplanegarlic.DeliveryTunnel:
		return s.sinks.Tunnel(delivery.To, delivery.TunnelID, message)
	}
	return ErrUnhandledI2NP
}

func validateI2NPExpiration(expiration, nowMillis uint64) error {
	if expiredI2NP(expiration, nowMillis) {
		return ErrExpired
	}
	if futureI2NP(expiration, nowMillis) {
		return ErrFutureExpiration
	}
	return nil
}

func appendError(previous, next error) error {
	if previous == nil {
		return next
	}
	return errors.Join(previous, next)
}

// The ordered subtractions keep the inclusive i2pd skew boundaries without
// constructing a potentially overflowing expiration ± skew timestamp.
func expiredI2NP(expiration, nowMillis uint64) bool {
	return expiration < nowMillis && nowMillis-expiration > i2npMessageClockSkewMillis
}

func futureI2NP(expiration, nowMillis uint64) bool {
	return expiration > nowMillis && expiration-nowMillis > i2npMessageMaxFutureMillis
}

func (s *Service) seen(scope replayScope, id uint32, expiration, nowMillis uint64) bool {
	first, step := replayHashes(scope, id, expiration)
	s.replay.once.Do(s.replay.initialize)
	shard := &s.replay.shards[first%uint64(len(s.replay.shards))]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.advance(nowMillis)
	for index := range shard.buckets {
		if replayBucketContains(shard.buckets[index], first, step) {
			return true
		}
	}
	replayBucketAdd(shard.buckets[shard.current], first, step)
	return false
}

func (filter *replayFilter) initialize() {
	shardCount := parallelism.Workers(replayFilterWords)
	wordsPerShard := (replayFilterWords + shardCount - 1) / shardCount
	filter.shards = make([]replayShard, shardCount)
	for shardIndex := range filter.shards {
		for bucketIndex := range filter.shards[shardIndex].buckets {
			filter.shards[shardIndex].buckets[bucketIndex] = make([]uint64, wordsPerShard)
		}
	}
}

func (shard *replayShard) advance(nowMillis uint64) {
	epoch := nowMillis / replayBucketDurationMillis
	if !shard.started {
		shard.epoch = epoch
		shard.current = uint8(epoch % replayBucketCount)
		shard.started = true
		return
	}
	if epoch <= shard.epoch {
		return
	}

	elapsed := epoch - shard.epoch
	if elapsed >= replayBucketCount {
		for index := range shard.buckets {
			clear(shard.buckets[index])
		}
	} else {
		for step := uint64(1); step <= elapsed; step++ {
			clear(shard.buckets[(shard.epoch+step)%replayBucketCount])
		}
	}
	shard.epoch = epoch
	shard.current = uint8(epoch % replayBucketCount)
}

func replayHashes(scope replayScope, id uint32, expiration uint64) (uint64, uint64) {
	first := replayMix(expiration ^ uint64(id)*0x9e3779b97f4a7c15 ^ uint64(scope)*0x94d049bb133111eb)
	return first, replayMix(first^0xd1b54a32d192ed03) | 1
}

func replayMix(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	return value ^ value>>31
}

func replayBucketContains(bucket []uint64, first, step uint64) bool {
	bits := uint64(len(bucket) * 64)
	for index := range uint64(replayFilterHashes) {
		bit := (first + index*step) % bits
		if bucket[bit/64]&(uint64(1)<<(bit&63)) == 0 {
			return false
		}
	}
	return true
}

func replayBucketAdd(bucket []uint64, first, step uint64) {
	bits := uint64(len(bucket) * 64)
	for index := range uint64(replayFilterHashes) {
		bit := (first + index*step) % bits
		bucket[bit/64] |= uint64(1) << (bit & 63)
	}
}
