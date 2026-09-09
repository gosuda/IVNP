package router

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"log/slog"
	"sync"

	"gosuda.org/ivnp/cryptography"
	dataplanegarlic "gosuda.org/ivnp/dataplane/internal/garlic"
	dataplanegarlicecies "gosuda.org/ivnp/dataplane/internal/garlic/ecies"
	dataplanestreaming "gosuda.org/ivnp/dataplane/internal/streaming"
	dataplanestreamingtunnel "gosuda.org/ivnp/dataplane/internal/streaming/tunnel"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

var (
	ErrDataPlaneConfig       = errors.New("router: invalid data-plane configuration")
	ErrLeaseSetUnavailable   = errors.New("router: legacy LeaseSet unavailable")
	ErrLeaseSetExpired       = errors.New("router: LeaseSet has no unexpired lease")
	ErrGarlicDestination     = errors.New("router: Garlic destination is not configured")
	ErrGarlicPacket          = errors.New("router: malformed Garlic packet")
	ErrUnsupportedEncryption = errors.New("router: unsupported Garlic encryption")
)

const (
	dataPlaneEnvelopeLifetime uint64 = 60_000
	destinationDataHeaderLen         = 23
	maxGarlicDestinations            = 256
)

// GarlicDestination identifies one local Garlic endpoint. ECIES state is
// destination-scoped; legacy session state is optional remote compatibility.
type GarlicDestination struct {
	Private             cryptography.ElGamalPrivateKey
	Sessions            *dataplanegarlic.SessionManager
	Ratchet             *dataplanegarlic.RatchetManager
	ReserveRatchetReply func(foundation.Hash) (RatchetReplyReservation, error)
	Limiter             *DestinationBandwidthLimiter
}

// Activate pins commit admission against shutdown; callers must then immediately
// commit their candidate and Send or Release. Release is idempotent.
type RatchetReplyReservation interface {
	Activate() error
	Send(context.Context, []byte) error
	// SendEstablished transfers an unactivated ACK/rekey response without
	// making application sends depend on its delivery.
	SendEstablished(context.Context, []byte) error
	Release()
}

// GarlicReceiverConfig configures the bounded authenticated Garlic adapter.
// Destinations map local hashes to their matching ECIES and optional legacy
// session state. ReplyKeys are reserved for short-build endpoint replies.
type GarlicReceiverConfig struct {
	Service       *Service
	Destinations  map[foundation.Hash]GarlicDestination
	ReplyKeys     *dataplanegarlic.ReplyKeyRegistry
	Now           func() uint64
	Metrics       *observability.Registry
	Logger        *slog.Logger
	StaticPrivate []byte
}

// GarlicReceiver authenticates ECIES or explicitly compatible legacy Garlic
// before dispatching parsed cloves to the existing Service sinks.
type GarlicReceiver struct {
	service        *Service
	destinations   map[foundation.Hash]*garlicDestinationState
	lifecycleMu    sync.RWMutex
	released       bool
	destinationsMu sync.RWMutex
	replyKeys      *dataplanegarlic.ReplyKeyRegistry
	now            func() uint64
	metrics        *observability.Registry
	logger         *slog.Logger
	staticPrivate  [32]byte
	hasStatic      bool
	replyScratch   sync.Pool
}

func (r *GarlicReceiver) MatchesService(service *Service) bool {
	return r.service == service
}

// getReplyScratch borrows a reply-decrypt buffer from the pool, allocating one
// lazily on a cold pool so idle receivers hold no scratch memory.
func (r *GarlicReceiver) getReplyScratch() *[foundation.I2NPI2PDMaxPayload]byte {
	if v, ok := r.replyScratch.Get().(*[foundation.I2NPI2PDMaxPayload]byte); ok {
		return v
	}
	return new([foundation.I2NPI2PDMaxPayload]byte)
}

type garlicReceiveScratch struct {
	plaintext [foundation.I2NPI2PDMaxPayload]byte
	reply     [foundation.I2NPI2PDMaxPayload]byte
}

type garlicDestinationState struct {
	GarlicDestination
	scratch      sync.Pool
	inFlightMu   sync.Mutex
	inFlightCond *sync.Cond
	inFlight     int
	retired      bool
}

// getScratch borrows a receive-decrypt buffer pair from the pool, allocating
// one lazily on a cold pool so idle destinations hold no scratch memory.
func (s *garlicDestinationState) getScratch() *garlicReceiveScratch {
	if v, ok := s.scratch.Get().(*garlicReceiveScratch); ok {
		return v
	}
	return new(garlicReceiveScratch)
}

func (s *garlicDestinationState) acquire() bool {
	s.inFlightMu.Lock()
	if s.retired {
		s.inFlightMu.Unlock()
		return false
	}
	s.inFlight++
	s.inFlightMu.Unlock()
	return true
}

func (s *garlicDestinationState) done() {
	s.inFlightMu.Lock()
	s.inFlight--
	if s.inFlight == 0 && s.inFlightCond != nil {
		s.inFlightCond.Broadcast()
	}
	s.inFlightMu.Unlock()
}

func (s *garlicDestinationState) retireAndWait() {
	s.inFlightMu.Lock()
	s.retired = true
	if s.inFlightCond == nil {
		s.inFlightCond = sync.NewCond(&s.inFlightMu)
	}
	for s.inFlight != 0 {
		s.inFlightCond.Wait()
	}
	s.inFlightMu.Unlock()
	// Buffers must be wiped before pooling because a GC may discard them.
	s.scratch = sync.Pool{}
}

func releaseGarlicSnapshot(destinations []*garlicDestinationState) {
	for _, destination := range destinations {
		destination.done()
	}
}

func NewGarlicReceiver(config GarlicReceiverConfig) (*GarlicReceiver, error) {
	newGarlicReceiverRejected := config.Service == nil || config.ReplyKeys == nil || config.Now == nil || len(config.Destinations) > maxGarlicDestinations
	if !newGarlicReceiverRejected {
		newGarlicReceiverRejected = len(config.StaticPrivate) != 0 && len(config.StaticPrivate) != 32
	}
	if newGarlicReceiverRejected {
		return nil, ErrDataPlaneConfig
	}
	receiver := &GarlicReceiver{
		service: config.Service, destinations: make(map[foundation.Hash]*garlicDestinationState, len(config.Destinations)),
		replyKeys: config.ReplyKeys, now: config.Now, metrics: config.Metrics, logger: config.Logger, hasStatic: len(config.StaticPrivate) == 32,
	}
	copy(receiver.staticPrivate[:], config.StaticPrivate)
	for hash, destination := range config.Destinations {
		if _, err := receiver.RegisterDestination(hash, destination); err != nil {
			receiver.ReleaseSensitive()
			return nil, err
		}
	}
	return receiver, nil
}

// RegisterDestination adds one destination-local authenticated Garlic state.
// It returns an idempotent removal function which waits for in-flight receive
// work before releasing the destination's sensitive state.
func (r *GarlicReceiver) RegisterDestination(hash foundation.Hash, destination GarlicDestination) (func(), error) {
	registerDestinationRejected := r == nil || hash == (foundation.Hash{})
	if !registerDestinationRejected {
		registerDestinationRejected = (destination.Sessions == nil && destination.Ratchet == nil)
	}
	if registerDestinationRejected {
		return nil, ErrDataPlaneConfig
	}
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	r.destinationsMu.Lock()
	if r.released || len(r.destinations) >= maxGarlicDestinations {
		r.destinationsMu.Unlock()
		return nil, ErrDataPlaneConfig
	}
	if _, exists := r.destinations[hash]; exists {
		r.destinationsMu.Unlock()
		return nil, ErrDataPlaneConfig
	}
	state := &garlicDestinationState{GarlicDestination: destination}
	r.destinations[hash] = state
	r.destinationsMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.destinationsMu.Lock()
			if r.destinations[hash] == state {
				delete(r.destinations, hash)
			}
			r.destinationsMu.Unlock()
			state.retireAndWait()
		})
	}, nil
}

// ReleaseSensitive prevents new receive work, waits for current handlers and
// destination removals, and clears the copied router static private key.
func (r *GarlicReceiver) ReleaseSensitive() {
	if r == nil {
		return
	}
	r.lifecycleMu.Lock()
	r.destinationsMu.Lock()
	if r.released {
		r.destinationsMu.Unlock()
		r.lifecycleMu.Unlock()
		return
	}
	r.released = true
	states := make([]*garlicDestinationState, 0, len(r.destinations))
	for hash, state := range r.destinations {
		states = append(states, state)
		delete(r.destinations, hash)
	}
	r.destinationsMu.Unlock()
	for _, state := range states {
		state.retireAndWait()
	}
	clear(r.staticPrivate[:])
	// Every acquire path below clears its reply buffer before returning it to
	// the pool, even on error, so dropping the pool here is safe; the GC
	// reclaims its contents once unreferenced.
	r.replyScratch = sync.Pool{}
	r.hasStatic = false
	r.lifecycleMu.Unlock()
}

// BandwidthSnapshot returns one configured local destination's non-sensitive
// pacing state.
func (r *GarlicReceiver) BandwidthSnapshot(destination foundation.Hash) (DestinationBandwidthSnapshot, bool) {
	if r == nil {
		return DestinationBandwidthSnapshot{}, false
	}
	r.destinationsMu.RLock()
	state, ok := r.destinations[destination]
	if !ok || state.Limiter == nil {
		r.destinationsMu.RUnlock()
		return DestinationBandwidthSnapshot{}, ok
	}
	snapshot := state.Limiter.Snapshot()
	r.destinationsMu.RUnlock()
	return snapshot, true
}

// HandleGarlic authenticates ECIES or legacy Garlic and dispatches its cloves.
// A one-time build or DatabaseLookup reply tag is consumed before any
// destination session lookup.
func (r *GarlicReceiver) HandleGarlic(message foundation.I2NPMessage) error {
	return r.HandleGarlicFrom(I2NPSource{}, message)
}

// HandleGarlicFrom preserves the authenticated outer transport predecessor for
// anonymous router Noise-N cloves.
func (r *GarlicReceiver) HandleGarlicFrom(source I2NPSource, message foundation.I2NPMessage) error {
	if r == nil || r.service == nil || r.replyKeys == nil || r.now == nil {
		return ErrDataPlaneConfig
	}
	if message.Header.Type != foundation.I2NPGarlic {
		return ErrGarlicPacket
	}
	outer, err := foundation.I2NPParseGarlic(message.Payload)
	if err != nil {
		return err
	}
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	if r.released {
		return ErrDataPlaneConfig
	}
	r.destinationsMu.RLock()
	var destinationStorage [maxGarlicDestinations]*garlicDestinationState
	destinations := destinationStorage[:0]
	for _, destination := range r.destinations {
		if destination.acquire() {
			destinations = append(destinations, destination)
		}
	}
	r.destinationsMu.RUnlock()
	defer releaseGarlicSnapshot(destinations)
	now := r.now()
	if len(outer.Encrypted) >= 8 {
		var tag [8]byte
		copy(tag[:], outer.Encrypted[:8])
		if key, found := r.replyKeys.ConsumeGarlicReplyKey(tag, now); found {
			if r.logger != nil {
				r.logger.Info("tunnel build reply stage", "stage", "creator_key_matched", "garlic_id", message.Header.ID)
			}
			if len(outer.Encrypted) < 8+16 {
				return dataplanegarlicecies.ErrOneTimeReplyExistingSession
			}
			plainLen := len(outer.Encrypted) - 8 - 16
			if plainLen > foundation.I2NPI2PDMaxPayload {
				return foundation.I2NPErrPayloadTooLarge
			}
			scratch := r.getReplyScratch()
			reply, unwrapErr := dataplanegarlicecies.OpenOneTimeReplyExistingSession(scratch[:plainLen], key.Key, key.Tag, outer.Encrypted)
			if unwrapErr == nil {
				if r.logger != nil {
					r.logger.Info("tunnel build reply stage", "stage", "creator_decrypted", "garlic_id", message.Header.ID, "reply_id", reply.Header.ID)
				}
				unwrapErr = r.service.
					dispatchClove(foundation.
						Hash{}, dataplanegarlic.Delivery{Type: dataplanegarlic.DeliveryLocal}, reply, now, false)
			} else if r.logger != nil {
				r.logger.Warn("tunnel build reply stage", "stage", "creator_decrypt_failed", "garlic_id", message.Header.ID, "error", unwrapErr)
			}

			clear(scratch[:plainLen])
			r.replyScratch.Put(scratch)
			return unwrapErr
		}
	}
	if r.hasStatic {
		plainLen := len(outer.Encrypted) - 32 - 16
		if plainLen > 0 && plainLen <= foundation.I2NPI2PDMaxPayload {
			scratch := r.getReplyScratch()
			inner, openErr := dataplanegarlicecies.OpenRouterMessage(scratch[:plainLen], r.staticPrivate[:], outer.Encrypted, now)
			if openErr == nil {
				openErr = r.service.
					handleI2NP(inner, now, false, source)
			}

			clear(scratch[:plainLen])
			r.replyScratch.Put(scratch)
			if openErr == nil {
				return nil
			}
		}
	}
	for _, destination := range destinations {
		if destination.Ratchet == nil || len(outer.Encrypted) > foundation.I2NPI2PDMaxPayload {
			continue
		}
		scratch := destination.getScratch()
		result, receiveErr := destination.Ratchet.Receive(scratch.plaintext[:], scratch.reply[:], outer.Encrypted, now)
		if receiveErr != nil {
			clear(scratch.plaintext[:])
			clear(scratch.reply[:])
			destination.scratch.Put(scratch)
			continue
		}
		if result.Candidate != nil {
			defer result.Candidate.Discard()
		}
		if destination.Limiter != nil && !destination.Limiter.TryAcquire(uint64(len(outer.Encrypted))) {
			clear(scratch.plaintext[:])
			clear(scratch.reply[:])
			destination.scratch.Put(scratch)
			return ErrDestinationBandwidth
		}
		receiveErr = r.handleRatchetResult(destination, result, scratch.reply[:], now)
		clear(scratch.plaintext[:])
		clear(scratch.reply[:])
		destination.scratch.Put(scratch)
		return receiveErr
	}
	for _, destination := range destinations {
		if destination.Sessions == nil || len(outer.Encrypted) > foundation.I2NPI2PDMaxPayload {
			continue
		}
		scratch := destination.getScratch()
		payload, _, _, receiveErr := destination.Sessions.Receive(scratch.plaintext[:], outer.Encrypted, destination.Private, now)
		if receiveErr != nil {
			clear(scratch.plaintext[:])
			clear(scratch.reply[:])
			destination.scratch.Put(scratch)
			continue
		}
		if destination.Limiter != nil && !destination.Limiter.TryAcquire(uint64(len(outer.Encrypted))) {
			clear(scratch.plaintext[:])
			destination.scratch.Put(scratch)
			return ErrDestinationBandwidth
		}
		set, parseErr := dataplanegarlic.ParseCloveSet(payload)
		if parseErr ==
			nil {
			parseErr = r.service.HandleGarlicCloveSet(set, now, false)
		}

		clear(scratch.plaintext[:])
		destination.scratch.Put(scratch)
		return parseErr
	}
	return ErrGarlicDestination
}

func (r *GarlicReceiver) handleRatchetResult(destination *garlicDestinationState, result dataplanegarlic.RatchetResult, replyDst []byte, now uint64) error {
	if len(result.Payload) == 0 && len(result.Reply) == 0 && !result.ReplyRequested {
		return nil
	}
	cloves, err := parseRatchetGarlicCloves(result.Payload)
	if err != nil {
		return err
	}
	if result.Candidate == nil {
		var dispatchErr error
		for _, clove := range cloves {
			dispatchErr = appendError(dispatchErr, r.service.dispatchClove(result.Peer, clove.Delivery, clove.Message, now, false))
		}
		if result.ReplyRequested && !result.Terminated {
			dispatchErr = appendError(dispatchErr, sendRatchetResponse(destination, result, replyDst, now))
		}
		return dispatchErr
	}
	target, targetErr := ratchetReplyTarget(cloves, result.Peer)
	if targetErr != nil {
		return targetErr
	}
	retained, err := destination.Ratchet.RetainNew(result.Candidate, target, now)
	if err != nil {
		return err
	}
	var reservation RatchetReplyReservation
	if !retained {
		if destination.ReserveRatchetReply == nil {
			return ErrGarlicDestination
		}
		reservation, err = destination.ReserveRatchetReply(target)
		if err != nil {
			return err
		}
		defer reservation.Release()
		if err := reservation.Activate(); err != nil {
			return err
		}
		commit, err := destination.Ratchet.CommitNew(result.Candidate, target, now)
		if err != nil {
			return err
		}
		if commit == dataplanegarlic.NewSessionRetained {
			reservation.Release()
			reservation = nil
		}
	}
	result.Peer = target
	remaining := cloves[:0]
	var dispatchErr error
	for _, clove := range cloves {
		if clove.Delivery.Type == dataplanegarlic.DeliveryLocal && clove.Message.Header.Type == foundation.I2NPDatabaseStore {
			dispatchErr = appendError(dispatchErr, r.service.dispatchClove(foundation.Hash{}, clove.Delivery, clove.Message, now, false))
			continue
		}
		remaining = append(remaining, clove)
	}
	if reservation != nil {
		if err := reservation.Send(context.Background(), result.Reply); err != nil {
			return appendError(dispatchErr, err)
		}
		if r.metrics != nil {
			r.metrics.IncGarlicECIESNewSessionSent()
		}
	}
	for _, clove := range remaining {
		dispatchErr = appendError(dispatchErr, r.service.dispatchClove(result.Peer, clove.Delivery, clove.Message, now, false))
	}
	return dispatchErr
}

func sendRatchetResponse(destination *garlicDestinationState, result dataplanegarlic.RatchetResult, replyDst []byte, now uint64) error {
	if destination.ReserveRatchetReply == nil || result.Peer == (foundation.Hash{}) {
		return ErrGarlicDestination
	}
	reservation, err := destination.ReserveRatchetReply(result.Peer)
	if err != nil {
		return err
	}
	defer reservation.Release()
	// At most one ACK per packet and one NextKey per direction.
	var plain [7 + 2*38]byte
	packet, err := destination.Ratchet.EncryptExistingWithScratch(replyDst, plain[:], result.Peer, nil, dataplanegarlic.RatchetOptions{ACKs: result.ACKRequests}, now)
	if err != nil {
		return err
	}
	return reservation.SendEstablished(context.Background(), packet)
}

func parseRatchetGarlicCloves(payload []byte) ([]dataplanegarlic.Clove, error) {
	var cloves []dataplanegarlic.Clove
	for len(payload) != 0 {
		if len(payload) < 3 {
			return nil, ErrGarlicPacket
		}
		kind, size := payload[0], int(binary.BigEndian.Uint16(payload[1:3]))
		payload = payload[3:]
		if size > len(payload) {
			return nil, ErrGarlicPacket
		}
		if kind == 11 {
			clove, err := parseRatchetGarlicClove(payload[:size])
			if err != nil {
				return nil, err
			}
			if cloves == nil {
				cloves = make([]dataplanegarlic.Clove, 0, 4)
			}
			cloves = append(cloves, clove)
		}
		payload = payload[size:]
	}
	return cloves, nil
}

func parseRatchetGarlicClove(body []byte) (dataplanegarlic.Clove, error) {
	delivery, used, err := dataplanegarlic.ParseDelivery(body)
	if err != nil || len(body)-used < 9 {
		return dataplanegarlic.Clove{}, ErrGarlicPacket
	}
	header := body[used : used+9]
	expiration := uint64(binary.BigEndian.Uint32(header[5:9])) * 1000
	message := foundation.I2NPMessage{
		Header: foundation.I2NPHeader{
			Type:       foundation.I2NPMessageType(header[0]),
			ID:         binary.BigEndian.Uint32(header[1:5]),
			Expiration: expiration,
		},
		Payload: body[used+9:],
	}
	return dataplanegarlic.Clove{Delivery: delivery, Message: message, Expiration: expiration}, nil
}

// HandleDestinationData is the concrete Service destination sink. It accepts
// only Data cloves addressed to a configured local Destination and forwards the
// protocol, ports, and borrowed payload to its DestinationManager.
func marshalDestinationDataTo(dst []byte, delivery dataplanestreamingtunnel.Delivery) ([]byte, error) {
	if len(delivery.Payload) > int(^uint16(0)) {
		return nil, foundation.I2NPErrPayloadTooLarge
	}
	dataLen := 4 + destinationDataHeaderLen + len(delivery.Payload)
	if len(dst) < dataLen {
		return nil, foundation.I2NPErrPayloadTooLarge
	}
	dst = dst[:dataLen]
	gzip := dst[4:]
	copy(gzip[:11], []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x01})
	binary.BigEndian.PutUint16(gzip[4:6], delivery.FromPort)
	binary.BigEndian.PutUint16(gzip[6:8], delivery.ToPort)
	gzip[9] = delivery.Protocol
	binary.LittleEndian.PutUint16(gzip[11:13], uint16(len(delivery.Payload)))
	binary.LittleEndian.PutUint16(gzip[13:15], ^uint16(len(delivery.Payload)))
	copy(gzip[15:], delivery.Payload)
	binary.LittleEndian.PutUint32(gzip[15+len(delivery.Payload):], crc32.ChecksumIEEE(delivery.Payload))
	binary.LittleEndian.PutUint32(gzip[19+len(delivery.Payload):], uint32(len(delivery.Payload)))
	binary.BigEndian.PutUint32(dst[:4], uint32(len(gzip)))
	return dst, nil
}

func parseDestinationData(payload []byte) (protocol uint8, fromPort, toPort uint16, decoded []byte, err error) {
	data, err := foundation.I2NPParseData(payload)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	gzip := data.Data
	if len(gzip) < 18 || gzip[0] != 0x1f || gzip[1] != 0x8b || gzip[2] != 8 || gzip[3] != 0 {
		return 0, 0, 0, nil, ErrGarlicPacket
	}
	size := int(binary.LittleEndian.Uint32(gzip[len(gzip)-4:]))
	if size > foundation.I2NPI2PDMaxPayload {
		return 0, 0, 0, nil, foundation.I2NPErrPayloadTooLarge
	}
	inflater := flate.NewReader(bytes.NewReader(gzip[10 : len(gzip)-8]))
	decoded = make([]byte, size)
	if _, err = io.ReadFull(inflater, decoded); err != nil {
		_ = inflater.Close()
		return 0, 0, 0, nil, ErrGarlicPacket
	}
	var extra [1]byte
	if n, readErr := inflater.Read(extra[:]); n != 0 || readErr != io.EOF {
		_ = inflater.Close()
		return 0, 0, 0, nil, ErrGarlicPacket
	}
	if err = inflater.Close(); err != nil || crc32.ChecksumIEEE(decoded) != binary.LittleEndian.Uint32(gzip[len(gzip)-8:len(gzip)-4]) {
		return 0, 0, 0, nil, ErrGarlicPacket
	}
	return gzip[9], binary.BigEndian.Uint16(gzip[4:6]), binary.BigEndian.Uint16(gzip[6:8]), decoded, nil
}

func (r *GarlicReceiver) HandleDestinationData(from, to foundation.Hash, message foundation.I2NPMessage, destinations *DestinationManager) error {
	if r == nil || destinations == nil || message.Header.Type != foundation.I2NPData {
		return ErrGarlicPacket
	}
	if _, ok := r.destinations[to]; !ok {
		return ErrGarlicDestination
	}
	protocol, fromPort, toPort, payload, err := parseDestinationData(message.Payload)
	if err != nil {
		return err
	}
	if protocol == dataplanestreamingtunnel.ProtocolStreaming {
		packet, parseErr := dataplanestreaming.Parse(payload)
		if parseErr != nil {
			return parseErr
		}
		if packet.Flags&dataplanestreamingtunnel.FlagFromIncluded != 0 {
			options := packet.Options
			if packet.Flags&dataplanestreamingtunnel.FlagDelayRequested != 0 {
				if len(options) < 2 {
					return dataplanestreamingtunnel.ErrTunnelPacket
				}
				options = options[2:]
			}
			identity, _, identityErr := foundation.ParseIdentity(options)
			if identityErr != nil {
				return identityErr
			}
			claimed := identity.Hash()
			if from != (foundation.Hash{}) && claimed != from {
				return dataplanestreamingtunnel.ErrTunnelDestination
			}
			from = claimed
		}
	}
	if from == (foundation.Hash{}) && protocol == dataplanestreamingtunnel.ProtocolStreaming {
		return ErrGarlicDestination
	}
	return destinations.HandleStreaming(context.Background(), dataplanestreamingtunnel.Delivery{
		From: from, To: to, Protocol: protocol, FromPort: fromPort, ToPort: toPort, Payload: payload,
	})
}

func ratchetReplyTarget(cloves []dataplanegarlic.Clove, observed foundation.Hash) (foundation.Hash, error) {
	for _, clove := range cloves {
		if clove.Delivery.Type != dataplanegarlic.DeliveryLocal || clove.Message.Header.Type != foundation.I2NPDatabaseStore {
			continue
		}
		store, err := foundation.I2NPParseDatabaseStore(clove.Message.Payload)
		if err != nil || store.Type != foundation.I2NPStoreLeaseSet2 {
			continue
		}
		set, err := foundation.NetworkDatabaseParseLeaseSet2(store.Data)
		if err != nil || set.Hash() != store.Key {
			continue
		}
		valid, verifyErr := set.Verify()
		if verifyErr != nil || !valid {
			continue
		}
		keys := set.Keys()
		for {
			key, ok, keyErr := keys.Next()
			if keyErr != nil {
				break
			}
			if !ok {
				return foundation.Hash{}, ErrGarlicPacket
			}
			ratchetReplyTargetRejected := (key.Type == foundation.CryptoX25519 || key.Type == foundation.CryptoMLKEM768X25519 || key.Type == foundation.CryptoMLKEM1024X25519)
			if ratchetReplyTargetRejected {
				ratchetReplyTargetRejected = foundation.Sum(key.Data) == observed
			}
			if ratchetReplyTargetRejected {
				return store.Key, nil
			}
		}
	}
	return foundation.Hash{}, ErrGarlicPacket
}

func saturatingAdd(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}
