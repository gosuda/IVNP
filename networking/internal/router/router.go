// Package router coordinates I2NP message dispatch, transport managers, and router lifecycle.
package router

import (
	"context"
	"errors"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
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
	Router              func(foundation.Hash, i2np.Message) error
	Destination         func(foundation.Hash, foundation.Hash, i2np.Message) error
	Tunnel              func(foundation.Hash, uint32, i2np.Message) error
	DatabaseLookup      func(i2np.DatabaseLookupMessage) error
	DatabaseSearchReply func(i2np.DatabaseSearchReplyMessage) error
	// DatabaseStoreCompleted observes a store only after Database admitted and
	// verified it. RequestManager uses this to complete coalesced lookups.
	DatabaseStoreCompleted func(i2np.DatabaseStoreMessage)
	// DatabaseStoreExpected classifies a store as a live lookup reply before
	// admission so floodfill responses never expose lookup-derived LeaseSets.
	DatabaseStoreExpected func(i2np.DatabaseStoreMessage) bool
	// DatabaseStoreFlood hands an admitted reply-requesting store to the
	// optional floodfill propagation worker with its authenticated source.
	DatabaseStoreFlood func(I2NPSource, i2np.DatabaseStoreMessage) error
	DeliveryStatus     func(i2np.DeliveryStatusMessage) error
	// DatabaseStoreReply delivers a successful DatabaseStore acknowledgement
	// through the reply gateway and optional tunnel specified by the store.
	DatabaseStoreReply       func(foundation.Hash, uint32, i2np.DeliveryStatusMessage) error
	Garlic                   func(I2NPSource, i2np.Message) error
	TunnelBuild              func(I2NPSource, i2np.BuildRecords, i2np.Message) error
	OutboundTunnelBuildReply func(i2np.Message) error
	TunnelTest               func(i2np.DeliveryStatusMessage) error
	TunnelData               func(i2np.Message) error
	TunnelGateway            func(uint32, i2np.Message) error
}

// Service provides I2NP message admission, replay filtering, and dispatch.
type Service struct {
	database *netdb.Database
	sinks    Sinks
	replay   replayFilter
}

type replayScope uint64

const (
	replayI2NP replayScope = iota
	replayGarlicSet
	replayGarlicClove
)

type preparedI2NP struct {
	store   i2np.DatabaseStoreMessage
	lookup  i2np.DatabaseLookupMessage
	search  i2np.DatabaseSearchReplyMessage
	status  i2np.DeliveryStatusMessage
	gateway i2np.TunnelGatewayMessage
	records i2np.BuildRecords
}

func NewService(database *netdb.Database) *Service { return NewWithSinks(database, Sinks{}) }
func NewWithSinks(database *netdb.Database, sinks Sinks) *Service {
	return &Service{database: database, sinks: sinks}
}

// SetTunnelDataSink installs the authenticated TunnelData hand-off before
// transports start. Router.New uses it to wire an embedded tunnel Runtime
// without making the Service depend on a concrete circuit implementation.
func (s *Service) SetTunnelDataSink(sink func(i2np.Message) error) {
	s.sinks.TunnelData = sink
}

// SetTunnelGatewaySink installs the pre-transport tunnel-gateway injection
// hand-off before transports start.
func (s *Service) SetTunnelGatewaySink(sink func(uint32, i2np.Message) error) {
	s.sinks.TunnelGateway = sink
}

// SetOutboundTunnelBuildReplySink installs the endpoint-only build-reply
// hand-off before transports start.
func (s *Service) SetOutboundTunnelBuildReplySink(sink func(i2np.Message) error) {
	s.sinks.OutboundTunnelBuildReply = sink
}

// SetTunnelBuildSink installs the modern build-record processor before
// transports start. The parsed records are supplied for callers that need
// them; BuildManager reparses only the supported short-record message.
func (s *Service) SetTunnelBuildSink(sink func(I2NPSource, i2np.BuildRecords, i2np.Message) error) {
	s.sinks.TunnelBuild = sink
}

// SetDatabaseSearchReplySink installs the NetDB lookup continuation hand-off.
func (s *Service) SetDatabaseSearchReplySink(sink func(i2np.DatabaseSearchReplyMessage) error) {
	s.sinks.DatabaseSearchReply = sink
}

// SetDatabaseStoreCompletedSink installs the post-admission NetDB store hook.
func (s *Service) SetDatabaseStoreCompletedSink(sink func(i2np.DatabaseStoreMessage)) {
	s.sinks.DatabaseStoreCompleted = sink
}

// SetDatabaseStoreExpectedSink installs lookup-reply classification.
func (s *Service) SetDatabaseStoreExpectedSink(sink func(i2np.DatabaseStoreMessage) bool) {
	s.sinks.DatabaseStoreExpected = sink
}

// SetDatabaseStoreFloodSink installs the bounded floodfill propagation route.
func (s *Service) SetDatabaseStoreFloodSink(sink func(I2NPSource, i2np.DatabaseStoreMessage) error) {
	s.sinks.DatabaseStoreFlood = sink
}

// SetDatabaseStoreReplySink installs the DatabaseStore acknowledgement route.
func (s *Service) SetDatabaseStoreReplySink(sink func(foundation.Hash, uint32, i2np.DeliveryStatusMessage) error) {
	s.sinks.DatabaseStoreReply = sink
}

// SetDatabaseLookupSink installs the bounded NetDB lookup responder before
// transports start.
func (s *Service) SetDatabaseLookupSink(sink func(i2np.DatabaseLookupMessage) error) {
	s.sinks.DatabaseLookup = sink
}

// SetDeliveryStatusSink installs the shared correlation mux before transports
// start.
func (s *Service) SetDeliveryStatusSink(sink func(i2np.DeliveryStatusMessage) error) {
	s.sinks.DeliveryStatus = sink
}

// SetTunnelTestSink installs the live tunnel-health control route.
func (s *Service) SetTunnelTestSink(sink func(i2np.DeliveryStatusMessage) error) {
	s.sinks.TunnelTest = sink
}

// SetRouterSink installs router-directed Garlic clove forwarding.
func (s *Service) SetRouterSink(sink func(foundation.Hash, i2np.Message) error) {
	s.sinks.Router = sink
}

// SetTunnelSink installs tunnel-directed Garlic clove forwarding.
func (s *Service) SetTunnelSink(sink func(foundation.Hash, uint32, i2np.Message) error) {
	s.sinks.Tunnel = sink
}

// SetGarlicSink installs authenticated Garlic ciphertext processing.
func (s *Service) SetGarlicSink(sink func(I2NPSource, i2np.Message) error) {
	s.sinks.Garlic = sink
}

// SetDestinationSink installs parsed Garlic destination-clove delivery.
func (s *Service) SetDestinationSink(sink func(foundation.Hash, foundation.Hash, i2np.Message) error) {
	s.sinks.Destination = sink
}

// HandleI2NP validates and dispatches an authenticated I2NP frame.
func (s *Service) HandleI2NP(message i2np.Message, nowMillis uint64, fromFloodfill bool) error {
	return s.handleI2NP(message, nowMillis, fromFloodfill, I2NPSource{})
}

// HandleI2NPFrom validates and dispatches an I2NP frame from an identified peer with rate-limiting.
func (s *Service) HandleI2NPFrom(peer foundation.Hash, message i2np.Message, nowMillis uint64, fromFloodfill bool) error {
	return s.handleI2NP(message, nowMillis, fromFloodfill, I2NPSource{Peer: peer, Direct: true})
}

// HandleI2NPFromContext validates and dispatches an I2NP frame respecting context cancellation.
func (s *Service) HandleI2NPFromContext(ctx context.Context, peer foundation.Hash, message i2np.Message, nowMillis uint64, fromFloodfill bool) error {
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

func (s *Service) handleI2NP(message i2np.Message, nowMillis uint64, fromFloodfill bool, source I2NPSource) error {
	prepared, err := s.prepareI2NP(message, nowMillis, true)
	if err != nil {
		return err
	}
	if s.seen(replayI2NP, message.Header.ID, message.Header.Expiration, nowMillis) {
		return ErrDuplicate
	}
	return s.dispatchPreparedI2NP(source, message, prepared, nowMillis, fromFloodfill)
}

func (s *Service) prepareI2NP(message i2np.Message, nowMillis uint64, requireSink bool) (preparedI2NP, error) {
	if err := validateI2NPExpiration(message.Header.Expiration, nowMillis); err != nil {
		return preparedI2NP{}, err
	}

	switch message.Header.Type {
	case i2np.DatabaseStore:
		store, err := i2np.ParseDatabaseStore(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.database == nil {
			return preparedI2NP{}, errors.New("router: database store without netdb")
		}
		if requireSink && store.ReplyToken != 0 && s.sinks.DatabaseStoreReply == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{store: store}, nil
	case i2np.DatabaseLookup:
		lookup, err := i2np.ParseDatabaseLookup(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.DatabaseLookup == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{lookup: lookup}, nil
	case i2np.DatabaseSearchReply:
		search, err := i2np.ParseDatabaseSearchReply(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.DatabaseSearchReply == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{search: search}, nil
	case i2np.DeliveryStatus:
		status, err := i2np.ParseDeliveryStatus(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.DeliveryStatus == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{status: status}, nil
	case i2np.Garlic:
		if _, err := i2np.ParseGarlic(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.Garlic == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case i2np.Data:
		if _, err := i2np.ParseData(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		// Data is meaningful only under an authenticated Garlic destination
		// delivery instruction; it has no direct-router dispatch route.
		if requireSink {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case i2np.TunnelData:
		if _, err := i2np.ParseTunnelData(message.Payload); err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelData == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{}, nil
	case i2np.TunnelGateway:
		gateway, err := i2np.ParseTunnelGateway(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelGateway == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{gateway: gateway}, nil
	case i2np.OutboundTunnelBuildReply:
		records, err := i2np.ParseBuildRecords(message.Header.Type, message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{records: records}, nil
	case i2np.TunnelBuild, i2np.TunnelBuildReply, i2np.VariableTunnelBuild, i2np.VariableTunnelBuildReply, i2np.ShortTunnelBuild:
		records, err := i2np.ParseBuildRecords(message.Header.Type, message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelBuild == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{records: records}, nil
	case i2np.TunnelTest:
		status, err := i2np.ParseTunnelTest(message.Payload)
		if err != nil {
			return preparedI2NP{}, err
		}
		if requireSink && s.sinks.TunnelTest == nil {
			return preparedI2NP{}, ErrUnhandledI2NP
		}
		return preparedI2NP{status: status}, nil
	default:
		return preparedI2NP{}, ErrUnhandledI2NP
	}
}

func (s *Service) dispatchPreparedI2NP(source I2NPSource, message i2np.Message, prepared preparedI2NP, nowMillis uint64, fromFloodfill bool) error {
	switch message.Header.Type {
	case i2np.DatabaseStore:
		published := s.sinks.DatabaseStoreExpected == nil || !s.sinks.DatabaseStoreExpected(prepared.store)
		if err := s.database.HandleDatabaseStoreAsPublished(prepared.store, fromFloodfill, nowMillis, published); err != nil {
			if prepared.store.ReplyToken == 0 {
				return err
			}
			return s.sendDatabaseStoreReply(prepared.store, nowMillis)
		}
		if s.sinks.DatabaseStoreCompleted != nil {
			s.sinks.DatabaseStoreCompleted(prepared.store)
		}
		if prepared.store.ReplyToken == 0 {
			return nil
		}
		var floodErr error
		if s.sinks.DatabaseStoreFlood != nil {
			floodErr = s.sinks.DatabaseStoreFlood(source, prepared.store)
		}
		replyErr := s.sendDatabaseStoreReply(prepared.store, nowMillis)
		return errors.Join(floodErr, replyErr)
	case i2np.DatabaseLookup:
		return s.sinks.DatabaseLookup(prepared.lookup)
	case i2np.DatabaseSearchReply:
		return s.sinks.DatabaseSearchReply(prepared.search)
	case i2np.DeliveryStatus:
		return s.sinks.DeliveryStatus(prepared.status)
	case i2np.Garlic:
		return s.sinks.Garlic(source, message)
	case i2np.TunnelData:
		return s.sinks.TunnelData(message)
	case i2np.TunnelGateway:
		return s.sinks.TunnelGateway(prepared.gateway.TunnelID, prepared.gateway.Embedded)
	case i2np.OutboundTunnelBuildReply:
		return s.sinks.OutboundTunnelBuildReply(message)
	case i2np.TunnelBuild, i2np.TunnelBuildReply, i2np.VariableTunnelBuild, i2np.VariableTunnelBuildReply, i2np.ShortTunnelBuild:
		return s.sinks.TunnelBuild(source, prepared.records, message)
	case i2np.TunnelTest:
		return s.sinks.TunnelTest(prepared.status)
	}
	return ErrUnhandledI2NP
}

func (s *Service) sendDatabaseStoreReply(store i2np.DatabaseStoreMessage, nowMillis uint64) error {
	return s.sinks.DatabaseStoreReply(store.ReplyGateway, store.ReplyTunnelID, i2np.DeliveryStatusMessage{
		MessageID: store.ReplyToken,
		Timestamp: nowMillis,
	})
}

// HandleGarlicCloveSet dispatches decrypted garlic cloves through I2NP replay filters and sinks.
func (s *Service) HandleGarlicCloveSet(set garlic.CloveSet, nowMillis uint64, fromFloodfill bool) error {
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

func (s *Service) dispatchClove(source foundation.Hash, delivery garlic.Delivery, message i2np.Message, nowMillis uint64, fromFloodfill bool) error {
	prepared, err := s.prepareClove(delivery, message, nowMillis)
	if err != nil {
		return err
	}
	if s.seen(replayI2NP, message.Header.ID, message.Header.Expiration, nowMillis) {
		return ErrDuplicate
	}
	return s.dispatchPreparedClove(source, delivery, message, prepared, nowMillis, fromFloodfill)
}

func (s *Service) prepareClove(delivery garlic.Delivery, message i2np.Message, nowMillis uint64) (preparedI2NP, error) {
	requireSink := delivery.Type == garlic.DeliveryLocal
	if requireSink && message.Header.Type == i2np.OutboundTunnelBuildReply && s.sinks.OutboundTunnelBuildReply != nil {
		requireSink = false
	}
	prepared, err := s.prepareI2NP(message, nowMillis, requireSink)
	if err != nil {
		return preparedI2NP{}, err
	}
	switch delivery.Type {
	case garlic.DeliveryLocal:
		return prepared, nil
	case garlic.DeliveryRouter:
		if s.sinks.Router != nil {
			return prepared, nil
		}
	case garlic.DeliveryDestination:
		if s.sinks.Destination != nil {
			return prepared, nil
		}
	case garlic.DeliveryTunnel:
		if s.sinks.Tunnel != nil {
			return prepared, nil
		}
	}
	return preparedI2NP{}, ErrUnhandledI2NP
}

func (s *Service) dispatchPreparedClove(source foundation.Hash, delivery garlic.Delivery, message i2np.Message, prepared preparedI2NP, nowMillis uint64, fromFloodfill bool) error {
	switch delivery.Type {
	case garlic.DeliveryLocal:
		if message.Header.Type == i2np.OutboundTunnelBuildReply && s.sinks.OutboundTunnelBuildReply != nil {
			return s.sinks.OutboundTunnelBuildReply(message)
		}
		return s.dispatchPreparedI2NP(I2NPSource{}, message, prepared, nowMillis, fromFloodfill)
	case garlic.DeliveryRouter:
		return s.sinks.Router(delivery.To, message)
	case garlic.DeliveryDestination:
		return s.sinks.Destination(source, delivery.To, message)
	case garlic.DeliveryTunnel:
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
