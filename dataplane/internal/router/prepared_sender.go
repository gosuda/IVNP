package router

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"sync"

	dataplanedatagram "gosuda.org/ivnp/dataplane/internal/datagram"
	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	dataplanetunnel "gosuda.org/ivnp/dataplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/internal/pool"
	"gosuda.org/ivnp/observability"
)

type MessageIDSource func() (uint32, error)

type PreparedTunnelWriter interface {
	SendBlockPrepared(context.Context, dataplanetunnel.CircuitToken, dataplanetunnel.Block) error
}

type PreparedRouteSenderConfig struct {
	Owner         foundation.Hash
	Garlic        *dataplanegarlic.SessionManager
	Ratchet       *dataplanegarlic.RatchetManager
	Tunnels       PreparedTunnelWriter
	Now           func() uint64
	NextID        MessageIDSource
	Limiter       *DestinationBandwidthLimiter
	Metrics       *observability.Registry
	Logger        *slog.Logger
	RouteCapacity int
}

type PreparedRouteSender struct {
	owner         foundation.Hash
	garlic        *dataplanegarlic.SessionManager
	ratchet       *dataplanegarlic.RatchetManager
	tunnels       PreparedTunnelWriter
	now           func() uint64
	nextID        MessageIDSource
	lifecycleMu   sync.RWMutex
	released      bool
	limiter       *DestinationBandwidthLimiter
	scratch       chan *streamingSenderScratch
	scratchSlots  int
	metrics       *observability.Registry
	logger        *slog.Logger
	routesMu      sync.Mutex
	routes        map[foundation.Hash]*preparedRouteEntry
	retiring      map[*preparedRouteEntry]struct{}
	generation    uint64
	routeCapacity int
	routeClock    uint64
}

func NewPreparedRouteSender(config PreparedRouteSenderConfig) (*PreparedRouteSender, error) {
	missingIdentityOrClock := config.Owner == (foundation.Hash{}) || config.Now == nil
	missingExecution := config.Tunnels == nil || (config.Garlic == nil && config.Ratchet == nil)
	if missingIdentityOrClock || missingExecution || config.RouteCapacity < 0 {
		return nil, ErrDataPlaneConfig
	}
	if config.NextID == nil {
		config.NextID = RandomMessageID
	}
	if config.RouteCapacity == 0 {
		config.RouteCapacity = 64
	}
	slots := parallelism.CPUs()
	s := &PreparedRouteSender{
		owner: config.Owner, garlic: config.Garlic, ratchet: config.Ratchet, tunnels: config.Tunnels,
		now: config.Now, nextID: config.NextID, limiter: config.Limiter, metrics: config.Metrics, logger: config.Logger,
		scratch: make(chan *streamingSenderScratch, slots), scratchSlots: slots,
		routes: make(map[foundation.Hash]*preparedRouteEntry, config.RouteCapacity), routeCapacity: config.RouteCapacity, generation: 1,
		retiring: make(map[*preparedRouteEntry]struct{}, config.RouteCapacity),
	}
	for range slots {
		s.scratch <- new(streamingSenderScratch)
	}
	return s, nil
}

func (s *PreparedRouteSender) ReleaseSensitive() {
	if s == nil {
		return
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.released {
		return
	}
	s.released = true
	for _, route := range s.routes {
		route.retire()
	}
	s.routes = nil
	for route := range s.retiring {
		route.retire()
	}
	s.retiring = nil
	for range s.scratchSlots {
		clearStreamingSenderScratch(<-s.scratch)
	}
	s.scratch = nil
}

func (s *PreparedRouteSender) RetireRatchetPeer(peer foundation.Hash) {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if !s.released && s.ratchet != nil {
		s.ratchet.RetirePeer(peer)
	}
}

type streamingSenderScratch struct {
	data      senderScratchBuffer
	clove     senderScratchBuffer
	ratchet   senderScratchBuffer
	plain     senderScratchBuffer
	encrypted senderScratchBuffer
}

type senderScratchBuffer struct {
	exposed []byte
}

// bytes records the entire writable span before handing it to serializers or
// crypto: an error may leave output beyond the successfully returned length.
func (b *senderScratchBuffer) bytes(size int) []byte {
	size = min(size, foundation.I2NPI2PDMaxPayload)
	if cap(b.exposed) < size {
		clear(b.exposed)
		capacity := 4096
		if size > capacity {
			capacity = foundation.I2NPI2PDMaxPayload
		}
		b.exposed = make([]byte, size, capacity)
	} else {
		b.exposed = b.exposed[:max(size, len(b.exposed))]
	}
	return b.exposed[:size:size]
}

func (b *senderScratchBuffer) clear() {
	clear(b.exposed)
	b.exposed = b.exposed[:0]
}

func (s *PreparedRouteSender) BandwidthSnapshot() DestinationBandwidthSnapshot {
	if s == nil || s.limiter == nil {
		return DestinationBandwidthSnapshot{}
	}
	return s.limiter.Snapshot()
}
func (s *PreparedRouteSender) SendTunnel(ctx context.Context, delivery dataplanestreamingtunnel.Delivery) error {
	return s.sendTunnel(ctx, delivery, nil)
}

// SendTunnelOnRoute rejects replacement rather than sending a handshake on an
// installation different from the one its feedback can retire.
func (s *PreparedRouteSender) SendTunnelOnRoute(ctx context.Context, delivery dataplanestreamingtunnel.Delivery, receipt PreparedRouteReceipt) error {
	return s.sendTunnel(ctx, delivery, &receipt)
}

func (s *PreparedRouteSender) sendTunnel(ctx context.Context, delivery dataplanestreamingtunnel.Delivery, receipt *PreparedRouteReceipt) error {
	if s == nil || delivery.Protocol == 0 {
		return dataplanestreamingtunnel.ErrTunnelProtocol
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	if delivery.From != s.owner {
		return ErrGarlicDestination
	}

	if len(delivery.Payload) > foundation.I2NPI2PDMaxPayload-4-destinationDataHeaderLen {
		return foundation.I2NPErrPayloadTooLarge
	}
	entry, err := s.acquireRoute(delivery.To)
	if err != nil {
		return err
	}
	defer entry.active.Done()
	if receipt != nil && (!receipt.matches(s.owner, entry) || receipt.Remote != delivery.To) {
		return ErrPreparedRouteMissing
	}
	route := &entry.route
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, uint64(len(delivery.Payload))); err != nil {
			return err
		}
	}
	now := s.now()
	expires := min(saturatingAdd(now, dataPlaneEnvelopeLifetime), route.Expires)
	scratch, err := s.acquireScratch(ctx)
	if err != nil {
		return err
	}
	scratchHeld := true
	defer func() {
		if scratchHeld {
			s.releaseScratch(scratch)
		}
	}()
	var encrypted []byte
	if !route.Legacy {
		if s.ratchet == nil {
			return ErrUnsupportedEncryption
		}
		payloadLen := 3 + 1 + foundation.HashLength + 9 + 4 + destinationDataHeaderLen + len(delivery.Payload)
		if shouldBundleLeaseSet(delivery) && route.LocalLeaseSet2 && len(route.LocalLeaseSet) != 0 {
			payloadLen += 3 + 1 + 9 + len(route.LocalLeaseSet)
		}
		ratchetPayload, payloadErr := s.destinationRatchetPayloadTo(scratch.ratchet.bytes(payloadLen), scratch.data.bytes(4+destinationDataHeaderLen+len(delivery.Payload)), delivery, expires, route)
		if payloadErr != nil {
			return payloadErr
		}
		packetLen, plainLen, sizeErr := dataplanegarlic.RatchetEncryptBufferSizes(len(ratchetPayload), uint16(route.KeyType))
		if sizeErr != nil {
			return sizeErr
		}
		if destinationProtocolRepliable(delivery.Protocol) {
			encrypted, err = s.ratchet.EncryptWithScratch(scratch.encrypted.bytes(packetLen), scratch.plain.bytes(plainLen), delivery.To, route.KeyData, uint16(route.KeyType), ratchetPayload, now)
		} else {
			encrypted, err = s.ratchet.EncryptUnbound(scratch.encrypted.bytes(packetLen), route.KeyData, uint16(route.KeyType), ratchetPayload, now)
		}
		if err != nil {
			return err
		}
	} else {
		if s.garlic == nil {
			return ErrUnsupportedEncryption
		}
		cloves := [2]dataplanegarlic.Clove{{Delivery: dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination}, Message: foundation.I2NPMessage{Payload: delivery.Payload}}}
		cloveCount := 1
		if shouldBundleLeaseSet(delivery) && len(route.LocalLeaseSet) != 0 {
			cloves[1] = dataplanegarlic.Clove{Delivery: dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, Message: foundation.I2NPMessage{Payload: route.LocalLeaseSet}}
			cloveCount++
		}
		cloveLen, sizeErr := dataplanegarlic.CloveSetEncodedLen(cloves[:cloveCount])
		if sizeErr != nil {
			return sizeErr
		}
		cloveSet, cloveErr := s.destinationCloveSetTo(scratch.clove.bytes(cloveLen+4+destinationDataHeaderLen), scratch.data.bytes(4+destinationDataHeaderLen+len(delivery.Payload)), delivery, expires, route)
		if cloveErr != nil {
			return cloveErr
		}
		packetLen, sizeErr := s.garlic.EncryptBufferSize(len(cloveSet))
		if sizeErr != nil {
			return sizeErr
		}
		encrypted, err = s.garlic.Encrypt(scratch.encrypted.bytes(packetLen), delivery.To, route.LegacyKey, cloveSet, now)
		if err != nil {
			return err
		}
	}
	scratchHeld = false
	err = s.finishEncryptedSend(ctx, route, encrypted, expires, scratch)
	if err == nil && s.metrics != nil {
		s.metrics.IncGarlicTunnelClovesForwarded()
	}
	if err != nil && s.logger != nil {
		s.logger.Debug("streaming Garlic send failed", "target", foundation.EncodeI2PBase64(delivery.To[:]), "error", err)
	}
	return err
}
func (s *PreparedRouteSender) SendRatchetReply(ctx context.Context, target foundation.Hash, packet []byte) error {
	if s == nil || len(packet) == 0 {
		return ErrGarlicPacket
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	entry, err := s.acquireRoute(target)
	if err != nil {
		return err
	}
	defer entry.active.Done()
	route := &entry.route
	if route.Legacy {
		return ErrUnsupportedEncryption
	}
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, uint64(len(packet))); err != nil {
			return err
		}
	}
	scratch, err := s.acquireScratch(ctx)
	if err != nil {
		return err
	}
	return s.finishEncryptedSend(ctx, route, packet, min(saturatingAdd(s.now(), dataPlaneEnvelopeLifetime), route.Expires), scratch)
}
func (s *PreparedRouteSender) acquireScratch(ctx context.Context) (*streamingSenderScratch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case scratch := <-s.scratch:
		if err := ctx.Err(); err != nil {
			s.scratch <- scratch
			return nil, err
		}
		return scratch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *PreparedRouteSender) releaseScratch(scratch *streamingSenderScratch) {
	clearStreamingSenderScratch(scratch)
	s.scratch <- scratch
}

func clearStreamingSenderScratch(scratch *streamingSenderScratch) {
	if scratch == nil {
		return
	}
	scratch.data.clear()
	scratch.clove.clear()
	scratch.ratchet.clear()
	scratch.plain.clear()
	scratch.encrypted.clear()
}

func (s *PreparedRouteSender) finishEncryptedSend(ctx context.Context, route *PreparedRoute, encrypted []byte, expires uint64, scratch *streamingSenderScratch) error {
	encoded, frameLease, err := s.frameEncrypted(encrypted, expires)
	s.releaseScratch(scratch)
	if err != nil {
		return err
	}
	defer frameLease.Release()
	return s.sendFramedTo(ctx, route, encoded)
}

func (s *PreparedRouteSender) frameEncrypted(encrypted []byte, expires uint64) ([]byte, *pool.Lease, error) {
	if len(encrypted) > foundation.I2NPI2PDMaxPayload-4 {
		return nil, nil, foundation.I2NPErrPayloadTooLarge
	}
	garlicPayloadLen := 4 + len(encrypted)
	encodedLen := foundation.I2NPStandardHeaderLen + garlicPayloadLen
	frameLease, ok := pool.AcquireLease(encodedLen)
	if !ok {
		return nil, nil, foundation.I2NPErrPayloadTooLarge
	}
	encoded, ok := frameLease.Bytes(encodedLen)
	if !ok {
		frameLease.Release()
		return nil, nil, foundation.I2NPErrPayloadTooLarge
	}
	garlicPayload := encoded[foundation.I2NPStandardHeaderLen:]
	binary.BigEndian.PutUint32(garlicPayload, uint32(len(encrypted)))
	copy(garlicPayload[4:], encrypted)
	garlicID, err := s.id()
	if err != nil {
		frameLease.Release()
		return nil, nil, err
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: garlicID, Expiration: expires}, Payload: garlicPayload}
	if _, err = message.MarshalTo(encoded); err != nil {
		frameLease.Release()
		return nil, nil, err
	}
	return encoded, frameLease, nil
}
func (s *PreparedRouteSender) sendFramedTo(ctx context.Context, route *PreparedRoute, encoded []byte) error {
	if route.Expires <= s.now() {
		return ErrPreparedRouteMissing
	}
	return s.tunnels.SendBlockPrepared(ctx, route.Circuit, dataplanetunnel.Block{Delivery: dataplanetunnel.DeliveryTunnel, Gateway: route.Gateway, TunnelID: route.TunnelID, Data: encoded})
}
func (s *PreparedRouteSender) destinationCloveSetTo(set, dataPayload []byte, delivery dataplanestreamingtunnel.Delivery, expires uint64, route *PreparedRoute) ([]byte, error) {
	dataPayload, err := marshalDestinationDataTo(dataPayload, delivery)
	if err != nil {
		return nil, err
	}
	dataID, err := s.id()
	if err != nil {
		return nil, err
	}
	cloveID, err := s.id()
	if err != nil {
		return nil, err
	}
	cloves := [2]dataplanegarlic.Clove{}
	cloveCount := 0
	if shouldBundleLeaseSet(delivery) && route != nil && len(route.LocalLeaseSet) != 0 {
		storePayload := route.LocalLeaseSet
		storeID, idErr := s.id()
		if idErr != nil {
			return nil, idErr
		}
		storeCloveID, idErr := s.id()
		if idErr != nil {
			return nil, idErr
		}
		cloves[cloveCount] = dataplanegarlic.Clove{
			Delivery:   dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal},
			Message:    foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: storeID, Expiration: expires}, Payload: storePayload},
			ID:         storeCloveID,
			Expiration: expires,
		}
		cloveCount++
	}
	cloves[cloveCount] = dataplanegarlic.Clove{
		Delivery:   dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: delivery.To},
		Message:    foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPData, ID: dataID, Expiration: expires}, Payload: dataPayload},
		ID:         cloveID,
		Expiration: expires,
	}
	cloveCount++
	length, err := dataplanegarlic.CloveSetEncodedLen(cloves[:cloveCount])
	if err != nil || len(set) < length {
		if err ==
			nil {
			err = foundation.I2NPErrPayloadTooLarge
		}

		return nil, err
	}
	setID, err := s.id()
	if err != nil {
		return nil, err
	}
	if _, err = dataplanegarlic.MarshalCloveSetTo(set[:length], cloves[:cloveCount], setID, expires); err != nil {
		return nil, err
	}
	return set[:length], nil
}

func (s *PreparedRouteSender) destinationRatchetPayloadTo(dst, dataPayload []byte, delivery dataplanestreamingtunnel.Delivery, expires uint64, route *PreparedRoute) ([]byte, error) {
	dataPayload, err := marshalDestinationDataTo(dataPayload, delivery)
	if err != nil {
		return nil, err
	}

	used := 0
	if shouldBundleLeaseSet(delivery) && route != nil && route.LocalLeaseSet2 && len(route.LocalLeaseSet) != 0 {
		storePayload := route.LocalLeaseSet
		storeID, idErr := s.id()
		if idErr != nil {
			return nil, idErr
		}
		block, blockErr := appendRatchetGarlicClove(dst[used:], dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, foundation.I2NPMessage{
			Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: storeID, Expiration: expires},
			Payload: storePayload,
		})
		if blockErr != nil {
			return nil, blockErr
		}
		used += len(block)
	}
	dataID, err := s.id()
	if err != nil {
		return nil, err
	}
	block, err := appendRatchetGarlicClove(dst[used:], dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryDestination, To: delivery.To}, foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPData, ID: dataID, Expiration: expires},
		Payload: dataPayload,
	})
	if err != nil {
		return nil, err
	}
	used += len(block)
	return dst[:used], nil
}
func destinationProtocolRepliable(protocol uint8) bool {
	switch protocol {
	case dataplanestreamingtunnel.ProtocolStreaming, dataplanedatagram.ProtocolDatagram1, dataplanedatagram.ProtocolDatagram2, dataplanedatagram.ProtocolDatagram3:
		return true
	default:
		return false
	}
}

func shouldBundleLeaseSet(delivery dataplanestreamingtunnel.Delivery) bool {
	if delivery.Protocol != dataplanestreamingtunnel.ProtocolStreaming {
		return destinationProtocolRepliable(delivery.Protocol)
	}
	packet, err := dataplanestreaming.Parse(delivery.Payload)
	return err == nil && packet.SendStreamID == 0 && packet.Flags&dataplanestreamingtunnel.FlagSynchronize != 0
}

func appendRatchetGarlicClove(dst []byte, delivery dataplanegarlic.Delivery, message foundation.I2NPMessage) ([]byte, error) {
	deliveryLen := 1
	if delivery.Type == dataplanegarlic.DeliveryDestination {
		deliveryLen += foundation.HashLength
	} else if delivery.Type != dataplanegarlic.DeliveryLocal {
		return nil, dataplanegarlic.ErrDelivery
	}
	bodyLen := deliveryLen + 9 + len(message.Payload)
	if bodyLen > int(^uint16(0)) || len(dst) < 3+bodyLen {
		return nil, foundation.I2NPErrPayloadTooLarge
	}
	expiration, ok := foundation.I2NPEncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		return nil, foundation.I2NPErrPayloadTooLarge
	}
	dst[0] = 11
	binary.BigEndian.PutUint16(dst[1:3], uint16(bodyLen))
	off := 3
	if delivery.Type == dataplanegarlic.DeliveryDestination {
		dst[off] = byte(dataplanegarlic.DeliveryDestination << 5)
		copy(dst[off+1:off+1+foundation.HashLength], delivery.To[:])
		off += 1 + foundation.HashLength
	} else {
		dst[off] = 0
		off++
	}
	dst[off] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(dst[off+1:off+5], message.Header.ID)
	binary.BigEndian.PutUint32(dst[off+5:off+9], expiration)
	copy(dst[off+9:], message.Payload)
	return dst[:3+bodyLen], nil
}
func (s *PreparedRouteSender) id() (uint32, error) {
	id, err := s.nextID()
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, ErrDataPlaneConfig
	}
	return id, nil
}

func RandomMessageID() (uint32, error) {
	var value [4]byte
	for {
		if _, err := rand.Read(value[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint32(value[:])
		if id != 0 {
			return id, nil
		}
	}
}
