package router

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking/internal/datagram"
	"gosuda.org/ivnp/networking/internal/garlic"
	"gosuda.org/ivnp/networking/internal/garlic/ecies"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/network_database"
	"gosuda.org/ivnp/networking/internal/streaming"
	streamtunnel "gosuda.org/ivnp/networking/internal/streaming/tunnel"
	"gosuda.org/ivnp/networking/internal/tunnel"
	"gosuda.org/ivnp/observability"
	"hash/crc32"
	"io"
	"sync"
	"time"
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
	dataPlaneEnvelopeLifetime   uint64 = 60_000
	destinationDataHeaderLen           = 23
	streamingSeedCacheCapacity         = 64
	streamingSeedFailureBackoff        = 10_000
	maxGarlicDestinations              = 64
)

// MessageIDSource allocates one non-zero I2NP or Garlic metadata ID. It is
// injectable so data-plane construction is deterministic in tests.
type MessageIDSource func() (uint32, error)

// StreamingTunnelSenderConfig wires the outbound destination data plane.
// LeaseSet lookup manager is used only when the target is absent from Database;
// all messages and Delivery.Payload remain borrowed until SendTunnel returns.
type StreamingTunnelSenderConfig struct {
	Database *netdb.Database
	Requests *netdb.RequestManager
	// Garlic is retained solely for explicitly stored legacy remote LeaseSets.
	// Local destinations use Ratchet and LS2/ELS2 by default.
	Garlic  *garlic.SessionManager
	Ratchet *garlic.RatchetManager
	// RemoteELS authorizes ELS2 lookup and decryption for an unblinded remote
	// destination. Presence forbids plaintext LS2 or legacy downgrade.
	RemoteELS      map[ivnp.Hash]RemoteELSContext
	Tunnels        *tunnel.Runtime
	Pool           *tunnel.Pool
	SeedRouterInfo tunnel.ReplyRouterInfoSeeder
	Now            func() uint64
	NextID         MessageIDSource
	Limiter        *DestinationBandwidthLimiter
	Metrics        *observability.Registry
}

// RemoteELSContext supplies the unblinded identity, blinding secret, and
// optional DH or PSK credential for one remote encrypted LeaseSet.
type RemoteELSContext struct {
	Identity      ivnp.Identity
	Secret        []byte
	Authorization netdb.ELSClientAuthorization
}

// StreamingTunnelSender resolves LS2 destinations and sends authenticated
// ECIES-X25519-AEAD Garlic cloves through its owning outbound tunnel pool.
// Legacy ElGamal remains available only for explicit remote compatibility.
type StreamingTunnelSender struct {
	database       *netdb.Database
	requests       *netdb.RequestManager
	garlic         *garlic.SessionManager
	ratchet        *garlic.RatchetManager
	tunnels        *tunnel.Runtime
	pool           *tunnel.Pool
	seedRouterInfo tunnel.ReplyRouterInfoSeeder
	now            func() uint64
	nextID         MessageIDSource
	lifecycleMu    sync.RWMutex
	released       bool
	remoteMu       sync.RWMutex
	remoteELS      map[ivnp.Hash]RemoteELSContext
	limiter        *DestinationBandwidthLimiter
	scratch        chan *streamingSenderScratch
	scratchSlots   int
	metrics        *observability.Registry
	seedMu         sync.Mutex
	seedCache      [streamingSeedCacheCapacity]streamingSeedCacheEntry
	seedNext       uint8
}

type streamingSenderScratch struct {
	data      [i2np.I2PDMaxPayload]byte
	clove     [i2np.I2PDMaxPayload]byte
	ratchet   [i2np.I2PDMaxPayload]byte
	plain     [i2np.I2PDMaxPayload]byte
	encrypted [i2np.I2PDMaxPayload]byte
	frame     [i2np.I2PDMaxFrame]byte
}

type streamingSeedCacheEntry struct {
	endpoint   ivnp.Hash
	gateway    ivnp.Hash
	expires    uint64
	retryAfter uint64
}

func NewStreamingTunnelSender(config StreamingTunnelSenderConfig) (*StreamingTunnelSender, error) {
	newStreamingTunnelSenderRejected := config.Database == nil || config.Requests == nil || config.Tunnels == nil || config.Pool == nil || config.Now == nil
	if !newStreamingTunnelSenderRejected {
		newStreamingTunnelSenderRejected = (config.Ratchet == nil && config.Garlic == nil)
	}
	if newStreamingTunnelSenderRejected {
		return nil, ErrDataPlaneConfig
	}
	if config.NextID == nil {
		config.NextID = randomMessageID
	}
	scratchSlots := parallelism.CPUs()
	sender := &StreamingTunnelSender{
		database: config.Database, requests: config.Requests, garlic: config.Garlic, ratchet: config.Ratchet,
		tunnels: config.Tunnels, pool: config.Pool, seedRouterInfo: config.SeedRouterInfo,
		now: config.Now, nextID: config.NextID, limiter: config.Limiter, metrics: config.Metrics,
		scratch: make(chan *streamingSenderScratch, scratchSlots), scratchSlots: scratchSlots,
	}
	for range scratchSlots {
		sender.scratch <- new(streamingSenderScratch)
	}
	if err := sender.UpdateRemoteELS(config.RemoteELS); err != nil {
		sender.ReleaseSensitive()
		return nil, err
	}
	return sender, nil
}

// BandwidthSnapshot reports this sender's destination-local pacing state.
func (s *StreamingTunnelSender) BandwidthSnapshot() DestinationBandwidthSnapshot {
	if s == nil || s.limiter == nil {
		return DestinationBandwidthSnapshot{}
	}
	return s.limiter.Snapshot()
}

// UpdateRemoteELS atomically replaces the sender's remote ELS2 policy table.
// Each entry remains an explicit encrypted-only policy, including entries with
// no DH or PSK credential, so resolution can never downgrade to plaintext.
func (s *StreamingTunnelSender) UpdateRemoteELS(policies map[ivnp.Hash]RemoteELSContext) error {
	if s == nil {
		return ErrDataPlaneConfig
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	updated, err := cloneValidatedRemoteELS(policies)
	if err != nil {
		return err
	}
	s.remoteMu.Lock()
	previous := s.remoteELS
	s.remoteELS = updated
	s.remoteMu.Unlock()
	releaseRemoteELSPolicies(previous)
	return nil
}

// ValidateRemoteELSContexts applies the exact sender validation without
// retaining any credentials. Daemon persistence uses it before committing a
// durable address-policy update.
func ValidateRemoteELSContexts(policies map[ivnp.Hash]RemoteELSContext) error {
	validated, err := cloneValidatedRemoteELS(policies)
	releaseRemoteELSPolicies(validated)
	return err
}

func cloneValidatedRemoteELS(policies map[ivnp.Hash]RemoteELSContext) (map[ivnp.Hash]RemoteELSContext, error) {
	updated := make(map[ivnp.Hash]RemoteELSContext, len(policies))
	for hash, policy := range policies {
		cloneValidatedRemoteELSSelected := hash == (ivnp.Hash{}) || policy.Identity.Hash() != hash || len(policy.Identity.Bytes()) == 0 || len(policy.Secret) > 0xffff
		if !cloneValidatedRemoteELSSelected {
			cloneValidatedRemoteELSSelected = (policy.Authorization.UseDH && policy.Authorization.UsePSK)
		}
		if cloneValidatedRemoteELSSelected {
			releaseRemoteELSPolicies(updated)
			return nil, ErrDataPlaneConfig
		}
		if policy.Authorization.UseDH {
			private, privateErr := ecdh.X25519().NewPrivateKey(policy.Authorization.DHPrivate[:])
			public, publicErr := ecdh.X25519().NewPublicKey(policy.Authorization.DHPublic[:])
			if privateErr != nil || publicErr != nil || !bytes.Equal(private.PublicKey().Bytes(), public.Bytes()) {
				releaseRemoteELSPolicies(updated)
				return nil, ErrDataPlaneConfig
			}
		}
		policy.Secret = append([]byte(nil), policy.Secret...)
		updated[hash] = policy
	}
	return updated, nil
}

func releaseRemoteELSPolicies(policies map[ivnp.Hash]RemoteELSContext) {
	for hash, policy := range policies {
		clear(policy.Secret)
		clear(policy.Authorization.DHPrivate[:])
		clear(policy.Authorization.DHPublic[:])
		clear(policy.Authorization.PSK[:])
		policies[hash] = policy
		delete(policies, hash)
	}
}

// ReleaseSensitive retires the sender and clears every copied remote ELS
// credential and preallocated plaintext/ciphertext work buffer.
func (s *StreamingTunnelSender) ReleaseSensitive() {
	if s == nil {
		return
	}
	s.lifecycleMu.Lock()
	if s.released {
		s.lifecycleMu.Unlock()
		return
	}
	s.released = true
	s.remoteMu.Lock()
	remote := s.remoteELS
	s.remoteELS = nil
	s.remoteMu.Unlock()
	releaseRemoteELSPolicies(remote)
	s.seedMu.Lock()
	clear(s.seedCache[:])
	s.seedNext = 0
	s.seedMu.Unlock()
	for range s.scratchSlots {
		scratch := <-s.scratch
		clearStreamingSenderScratch(scratch)
	}
	s.scratch = nil
	s.lifecycleMu.Unlock()
}

// SendTunnel builds a destination Data clove and routes it through this
// destination's outbound pool. LS2 takes precedence over a legacy record for
// the same target; legacy encryption is used only when no LS2 exists.
func (s *StreamingTunnelSender) SendTunnel(ctx context.Context, delivery streamtunnel.Delivery) error {
	if s == nil || delivery.Protocol == 0 {
		return streamtunnel.ErrTunnelProtocol
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if len(delivery.Payload) > i2np.I2PDMaxPayload-4-destinationDataHeaderLen {
		return i2np.ErrPayloadTooLarge
	}
	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, uint64(len(delivery.Payload))); err != nil {
			return err
		}
	}
	now := s.now()
	set2, legacy, err := s.resolveLeaseSet(ctx, delivery.To)
	if err != nil {
		return err
	}
	expires := saturatingAdd(now, dataPlaneEnvelopeLifetime)
	scratch, err := s.acquireScratch(ctx)
	if err != nil {
		return err
	}
	defer s.releaseScratch(scratch)
	var (
		encrypted []byte
		lease     netdb.Lease
	)
	if set2 != nil {
		if s.ratchet == nil {
			return ErrUnsupportedEncryption
		}
		key, keyErr := set2.SelectUsableEncryptionKey(now, ivnp.CryptoMLKEM1024X25519, ivnp.CryptoMLKEM768X25519, ivnp.CryptoX25519)
		if keyErr != nil {
			return keyErr
		}
		lease, err = selectLease2(*set2, now)
		if err != nil {
			return err
		}
		ratchetPayload, payloadErr := s.destinationRatchetPayloadTo(scratch.ratchet[:], scratch.data[:], delivery, expires)
		if payloadErr != nil {
			return payloadErr
		}
		if destinationProtocolRepliable(delivery.Protocol) {
			encrypted, err = s.ratchet.EncryptWithScratch(scratch.encrypted[:], scratch.plain[:], delivery.To, key.Data, uint16(key.Type), ratchetPayload, now)
		} else {
			encrypted, err = s.ratchet.EncryptUnbound(scratch.encrypted[:], key.Data, uint16(key.Type), ratchetPayload, now)
		}
		clear(ratchetPayload)
		if err != nil {
			return err
		}
	} else {
		if s.garlic == nil {
			return ErrUnsupportedEncryption
		}
		var recipient cryptx.ElGamalPublicKey
		lease, recipient, err = selectLegacyLease(*legacy, now)
		if err != nil {
			return err
		}
		cloveSet, cloveErr := s.destinationCloveSetTo(scratch.clove[:], scratch.data[:], delivery, expires)
		if cloveErr != nil {
			return cloveErr
		}
		encrypted, err = s.garlic.Encrypt(scratch.encrypted[:], delivery.To, recipient, cloveSet, now)
		if err != nil {
			return err
		}
	}
	err = s.sendEncryptedTo(ctx, lease, encrypted, expires, scratch.frame[:])
	if err == nil && s.metrics != nil {
		s.metrics.IncGarlicTunnelClovesForwarded()
	}
	return err
}

// SendRatchetReply delivers an authenticated NSR packet through this
// destination's own lease and outbound tunnel. It deliberately bypasses
// encryption: packet is already a complete ratchet reply.
func (s *StreamingTunnelSender) SendRatchetReply(ctx context.Context, target ivnp.Hash, packet []byte) error {
	if s == nil || len(packet) == 0 {
		return ErrGarlicPacket
	}
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.released {
		return ErrDataPlaneConfig
	}
	if ctx == nil {
		ctx = context.
			Background()
	}

	if s.limiter != nil {
		if err := s.limiter.Wait(ctx, uint64(len(packet))); err != nil {
			return err
		}
	}
	now := s.now()
	set2, _, err := s.resolveLeaseSet(ctx, target)
	if err != nil {
		return err
	}
	if set2 == nil {
		return ErrUnsupportedEncryption
	}
	lease, err := selectLease2(*set2, now)
	if err != nil {
		return err
	}
	scratch, err := s.acquireScratch(ctx)
	if err != nil {
		return err
	}
	defer s.releaseScratch(scratch)
	return s.sendEncryptedTo(ctx, lease, packet, saturatingAdd(now, dataPlaneEnvelopeLifetime), scratch.frame[:])
}
func (s *StreamingTunnelSender) acquireScratch(ctx context.Context) (*streamingSenderScratch, error) {
	select {
	case scratch := <-s.scratch:
		return scratch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *StreamingTunnelSender) releaseScratch(scratch *streamingSenderScratch) {
	clearStreamingSenderScratch(scratch)
	s.scratch <- scratch
}

func clearStreamingSenderScratch(scratch *streamingSenderScratch) {
	if scratch == nil {
		return
	}
	clear(scratch.data[:])
	clear(scratch.clove[:])
	clear(scratch.ratchet[:])
	clear(scratch.plain[:])
	clear(scratch.encrypted[:])
	clear(scratch.frame[:])
}

func (s *StreamingTunnelSender) sendEncryptedTo(ctx context.Context, lease netdb.Lease, encrypted []byte, expires uint64, frame []byte) error {
	outbound, ok := s.pool.Select(tunnel.Outbound, s.now())
	if !ok {
		return tunnel.ErrCircuitNotFound
	}
	s.seedLeaseGateway(ctx, outbound, lease.Gateway)
	if len(encrypted) > i2np.I2PDMaxPayload-4 {
		return i2np.ErrPayloadTooLarge
	}
	garlicPayloadLen := 4 + len(encrypted)
	if len(frame) < i2np.StandardHeaderLen+garlicPayloadLen {
		return i2np.ErrPayloadTooLarge
	}
	garlicPayload := frame[i2np.StandardHeaderLen : i2np.StandardHeaderLen+garlicPayloadLen]
	binary.BigEndian.PutUint32(garlicPayload, uint32(len(encrypted)))
	copy(garlicPayload[4:], encrypted)
	garlicID, err := s.id()
	if err != nil {
		return err
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.Garlic, ID: garlicID, Expiration: expires}, Payload: garlicPayload}
	encoded := frame[:message.EncodedLen()]
	if _, err = message.MarshalTo(encoded); err != nil {
		return err
	}
	return s.tunnels.SendBlock(ctx, outbound.ID, tunnel.Block{Delivery: tunnel.DeliveryTunnel, Gateway: lease.Gateway, TunnelID: lease.TunnelID, Data: encoded})
}
func (s *StreamingTunnelSender) seedLeaseGateway(ctx context.Context, outbound tunnel.Entry, gateway ivnp.Hash) {
	if s.seedRouterInfo == nil || outbound.HopCount == 0 || gateway == (ivnp.Hash{}) {
		return
	}
	endpoint := outbound.Hops[outbound.HopCount-1]
	if endpoint == (ivnp.Hash{}) {
		return
	}
	now := s.now()
	s.seedMu.Lock()
	slot := -1
	for index := range s.seedCache {
		entry := s.seedCache[index]
		if entry.endpoint == endpoint && entry.gateway == gateway {
			if entry.expires > now || entry.retryAfter > now {
				s.seedMu.Unlock()
				return
			}
			slot = index
			break
		}
		if slot == -1 && entry.expires <= now && entry.retryAfter <= now {
			slot = index
		}
	}
	if slot == -1 {
		slot = int(s.seedNext) % len(s.seedCache)
		s.seedNext = uint8((slot + 1) % len(s.seedCache))
	}
	entry := streamingSeedCacheEntry{endpoint: endpoint, gateway: gateway}
	if err := s.seedRouterInfo(ctx, endpoint, gateway); err != nil {
		entry.retryAfter = saturatingAdd(now, streamingSeedFailureBackoff)
	} else {
		entry.expires = outbound.Expires
		if entry.expires <= now {
			entry.expires = saturatingAdd(now, streamingSeedFailureBackoff)
		}
	}
	s.seedCache[slot] = entry
	s.seedMu.Unlock()
}

func (s *StreamingTunnelSender) destinationCloveSetTo(set, dataPayload []byte, delivery streamtunnel.Delivery, expires uint64) ([]byte, error) {
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
	cloves := [2]garlic.Clove{}
	cloveCount := 0
	if shouldBundleLeaseSet(delivery) {
		if storeType, stored, ok := s.database.StoredLeaseSet(delivery.From); ok {
			storePayload, storeErr := netdb.MarshalDatabaseStore(delivery.From, storeType, stored, 0, ivnp.Hash{}, 0)
			if storeErr != nil {
				return nil, storeErr
			}
			storeID, idErr := s.id()
			if idErr != nil {
				return nil, idErr
			}
			storeCloveID, idErr := s.id()
			if idErr != nil {
				return nil, idErr
			}
			cloves[cloveCount] = garlic.Clove{
				Delivery:   garlic.Delivery{Type: garlic.DeliveryLocal},
				Message:    i2np.Message{Header: i2np.Header{Type: i2np.DatabaseStore, ID: storeID, Expiration: expires}, Payload: storePayload},
				ID:         storeCloveID,
				Expiration: expires,
			}
			cloveCount++
		}
	}
	cloves[cloveCount] = garlic.Clove{
		Delivery:   garlic.Delivery{Type: garlic.DeliveryDestination, To: delivery.To},
		Message:    i2np.Message{Header: i2np.Header{Type: i2np.Data, ID: dataID, Expiration: expires}, Payload: dataPayload},
		ID:         cloveID,
		Expiration: expires,
	}
	cloveCount++
	length, err := garlic.CloveSetEncodedLen(cloves[:cloveCount])
	if err != nil || len(set) < length {
		if err ==
			nil {
			err = i2np.ErrPayloadTooLarge
		}

		return nil, err
	}
	setID, err := s.id()
	if err != nil {
		return nil, err
	}
	if _, err = garlic.MarshalCloveSetTo(set[:length], cloves[:cloveCount], setID, expires); err != nil {
		return nil, err
	}
	return set[:length], nil
}

func (s *StreamingTunnelSender) destinationRatchetPayloadTo(dst, dataPayload []byte, delivery streamtunnel.Delivery, expires uint64) ([]byte, error) {
	dataPayload, err := marshalDestinationDataTo(dataPayload, delivery)
	if err != nil {
		return nil, err
	}

	used := 0
	if shouldBundleLeaseSet(delivery) {
		if storeType, stored, ok := s.database.StoredLeaseSet(delivery.From); ok && storeType == i2np.StoreLeaseSet2 {
			storePayload, storeErr := netdb.MarshalDatabaseStore(delivery.From, storeType, stored, 0, ivnp.Hash{}, 0)
			if storeErr != nil {
				return nil, storeErr
			}
			storeID, idErr := s.id()
			if idErr != nil {
				return nil, idErr
			}
			block, blockErr := appendRatchetGarlicClove(dst[used:], garlic.Delivery{Type: garlic.DeliveryLocal}, i2np.Message{
				Header:  i2np.Header{Type: i2np.DatabaseStore, ID: storeID, Expiration: expires},
				Payload: storePayload,
			})
			if blockErr != nil {
				return nil, blockErr
			}
			used += len(block)
		}
	}
	dataID, err := s.id()
	if err != nil {
		return nil, err
	}
	block, err := appendRatchetGarlicClove(dst[used:], garlic.Delivery{Type: garlic.DeliveryDestination, To: delivery.To}, i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: dataID, Expiration: expires},
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
	case streamtunnel.ProtocolStreaming, datagram.ProtocolDatagram1, datagram.ProtocolDatagram2, datagram.ProtocolDatagram3:
		return true
	default:
		return false
	}
}

func shouldBundleLeaseSet(delivery streamtunnel.Delivery) bool {
	if delivery.Protocol != streamtunnel.ProtocolStreaming {
		return destinationProtocolRepliable(delivery.Protocol)
	}
	packet, err := streaming.Parse(delivery.Payload)
	return err == nil && packet.SendStreamID == 0 && packet.Flags&streamtunnel.FlagSynchronize != 0
}

func appendRatchetGarlicClove(dst []byte, delivery garlic.Delivery, message i2np.Message) ([]byte, error) {
	deliveryLen := 1
	if delivery.Type == garlic.DeliveryDestination {
		deliveryLen += ivnp.HashLength
	} else if delivery.Type != garlic.DeliveryLocal {
		return nil, garlic.ErrDelivery
	}
	bodyLen := deliveryLen + 9 + len(message.Payload)
	if bodyLen > int(^uint16(0)) || len(dst) < 3+bodyLen || message.Header.Expiration/1000 > uint64(^uint32(0)) {
		return nil, i2np.ErrPayloadTooLarge
	}
	dst[0] = 11
	binary.BigEndian.PutUint16(dst[1:3], uint16(bodyLen))
	off := 3
	if delivery.Type == garlic.DeliveryDestination {
		dst[off] = byte(garlic.DeliveryDestination << 5)
		copy(dst[off+1:off+1+ivnp.HashLength], delivery.To[:])
		off += 1 + ivnp.HashLength
	} else {
		dst[off] = 0
		off++
	}
	dst[off] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(dst[off+1:off+5], message.Header.ID)
	binary.BigEndian.PutUint32(dst[off+5:off+9], uint32(message.Header.Expiration/1000))
	copy(dst[off+9:], message.Payload)
	return dst[:3+bodyLen], nil
}

func (s *StreamingTunnelSender) resolveLeaseSet(ctx context.Context, target ivnp.Hash) (*netdb.LeaseSet2, *netdb.LeaseSet, error) {
	s.remoteMu.RLock()
	policy, encrypted := s.remoteELS[target]
	if encrypted {
		policy.Secret = append([]byte(nil), policy.Secret...)
	}
	s.remoteMu.RUnlock()
	if encrypted {
		set, legacy, err := s.resolveEncryptedLeaseSet(ctx, policy)
		clear(policy.Secret)
		return set, legacy, err
	}
	if set, ok := s.database.LeaseSet2(target); ok {
		return &set, nil, nil
	}
	if set, ok := s.database.LeaseSet(target); ok {
		return nil, &set, nil
	}
	if err := s.lookupLeaseSet(ctx, target); err != nil {
		return nil, nil, err
	}
	if set, ok := s.database.LeaseSet2(target); ok {
		return &set, nil, nil
	}
	if set, ok := s.database.LeaseSet(target); ok {
		return nil, &set, nil
	}
	return nil, nil, ErrLeaseSetUnavailable
}

func (s *StreamingTunnelSender) resolveEncryptedLeaseSet(ctx context.Context, policy RemoteELSContext) (*netdb.LeaseSet2, *netdb.LeaseSet, error) {
	key, err := encryptedLeaseSetDHTKey(policy.Identity, policy.Secret, s.now())
	if err != nil {
		return nil, nil, err
	}
	set, found := s.database.EncryptedLeaseSet(key)
	if !found {
		if err = s.lookupLeaseSet(ctx, key); err != nil {
			return nil, nil, err
		}
		set, found = s.database.EncryptedLeaseSet(key)
		if !found {
			return nil, nil, ErrLeaseSetUnavailable
		}
	}
	inner, err := netdb.DecryptEncryptedLeaseSet(set, policy.Identity, policy.Secret, policy.Authorization, s.now())
	if err != nil {
		return nil, nil, err
	}
	return &inner, nil, nil
}

func (s *StreamingTunnelSender) lookupLeaseSet(ctx context.Context, key ivnp.Hash) error {
	result, err := s.requests.LookupLeaseSet(ctx, key)
	if err != nil {
		return err
	}
	select {
	case outcome, ok := <-result:
		if !ok {
			return ErrLeaseSetUnavailable
		}
		return outcome.Err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func encryptedLeaseSetDHTKey(identity ivnp.Identity, secret []byte, now uint64) (ivnp.Hash, error) {
	kind := identity.SigningKeyType()
	public, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		return ivnp.Hash{}, netdb.ErrEncryptedLeaseSet
	}
	blinded, err := ivnp.BlindEncryptedLeaseSetPublic(kind, public, time.UnixMilli(int64(now)), secret)
	if err != nil {
		return ivnp.Hash{}, err
	}
	var input [34]byte
	binary.BigEndian.PutUint16(input[:2], uint16(ivnp.SigningRedDSASHA512Ed25519))
	copy(input[2:], blinded[:])
	return ivnp.Sum(input[:]), nil
}

func selectLease2(set netdb.LeaseSet2, now uint64) (netdb.Lease, error) {
	var selected netdb.Lease
	iterator := set.Leases()
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return netdb.Lease{}, err
		}
		if !ok {
			break
		}
		end := uint64(lease.EndDate) * 1000
		if end > now && (selected.TunnelID == 0 || end > selected.EndDate) {
			selected = netdb.Lease{Gateway: lease.Gateway, TunnelID: lease.TunnelID, EndDate: end}
		}
	}
	if selected.TunnelID == 0 {
		return netdb.Lease{}, ErrLeaseSetExpired
	}
	return selected, nil
}

func selectLegacyLease(set netdb.LeaseSet, now uint64) (netdb.Lease, cryptx.ElGamalPublicKey, error) {
	if len(set.EncryptionKey) != cryptx.ElGamalPublicKeySize {
		return netdb.Lease{}, cryptx.ElGamalPublicKey{}, ErrUnsupportedEncryption
	}
	var recipient cryptx.ElGamalPublicKey
	copy(recipient[:], set.EncryptionKey)
	var selected netdb.Lease
	iterator := set.Leases()
	for {
		lease, ok, err := iterator.Next()
		if err != nil {
			return netdb.Lease{}, cryptx.ElGamalPublicKey{}, err
		}
		if !ok {
			break
		}
		if lease.EndDate > now && (selected.TunnelID == 0 || lease.EndDate > selected.EndDate) {
			selected = lease
		}
	}
	if selected.TunnelID == 0 {
		return netdb.Lease{}, cryptx.ElGamalPublicKey{}, ErrLeaseSetExpired
	}
	return selected, recipient, nil
}

func (s *StreamingTunnelSender) id() (uint32, error) {
	id, err := s.nextID()
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, ErrDataPlaneConfig
	}
	return id, nil
}

func randomMessageID() (uint32, error) {
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

// GarlicDestination identifies one local Garlic endpoint. ECIES state is
// destination-scoped; legacy session state is optional remote compatibility.
type GarlicDestination struct {
	Private  cryptx.ElGamalPrivateKey
	Sessions *garlic.SessionManager
	Ratchet  *garlic.RatchetManager
	// SendRatchetReply transports an already-authenticated New Session Reply
	// through this destination's own lease and outbound tunnel.
	SendRatchetReply func(context.Context, ivnp.Hash, []byte) error
	Limiter          *DestinationBandwidthLimiter
}

// GarlicReceiverConfig configures the bounded authenticated Garlic adapter.
// Destinations map local hashes to their matching ECIES and optional legacy
// session state. ReplyKeys are reserved for short-build endpoint replies.
type GarlicReceiverConfig struct {
	Service       *Service
	Destinations  map[ivnp.Hash]GarlicDestination
	ReplyKeys     *garlic.ReplyKeyRegistry
	Now           func() uint64
	Metrics       *observability.Registry
	StaticPrivate []byte
}

// GarlicReceiver authenticates ECIES or explicitly compatible legacy Garlic
// before dispatching parsed cloves to the existing Service sinks.
type GarlicReceiver struct {
	service        *Service
	destinations   map[ivnp.Hash]*garlicDestinationState
	lifecycleMu    sync.RWMutex
	released       bool
	destinationsMu sync.RWMutex
	replyKeys      *garlic.ReplyKeyRegistry
	now            func() uint64
	metrics        *observability.Registry
	staticPrivate  [32]byte
	hasStatic      bool
	replyScratch   chan *[i2np.I2PDMaxPayload]byte
}

type garlicReceiveScratch struct {
	plaintext [i2np.I2PDMaxPayload]byte
	reply     [i2np.I2PDMaxPayload]byte
}

type garlicDestinationState struct {
	GarlicDestination
	scratch      chan *garlicReceiveScratch
	inFlightMu   sync.Mutex
	inFlightCond *sync.Cond
	inFlight     int
	retired      bool
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
	for range cap(s.scratch) {
		scratch := <-s.scratch
		clear(scratch.plaintext[:])
		clear(scratch.reply[:])
	}
	s.scratch = nil
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
	replySlots := parallelism.CPUs()
	receiver := &GarlicReceiver{
		service: config.Service, destinations: make(map[ivnp.Hash]*garlicDestinationState, len(config.Destinations)),
		replyKeys: config.ReplyKeys, now: config.Now, metrics: config.Metrics, hasStatic: len(config.StaticPrivate) == 32,
		replyScratch: make(chan *[i2np.I2PDMaxPayload]byte, replySlots),
	}
	for range replySlots {
		receiver.replyScratch <- new([i2np.I2PDMaxPayload]byte)
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
func (r *GarlicReceiver) RegisterDestination(hash ivnp.Hash, destination GarlicDestination) (func(), error) {
	registerDestinationRejected := r == nil || hash == (ivnp.Hash{})
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
	scratchSlots := parallelism.CPUs()
	state := &garlicDestinationState{GarlicDestination: destination, scratch: make(chan *garlicReceiveScratch, scratchSlots)}
	for range scratchSlots {
		state.scratch <- new(garlicReceiveScratch)
	}
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
	for range cap(r.replyScratch) {
		scratch := <-r.replyScratch
		clear(scratch[:])
	}
	r.replyScratch = nil
	r.hasStatic = false
	r.lifecycleMu.Unlock()
}

// BandwidthSnapshot returns one configured local destination's non-sensitive
// pacing state.
func (r *GarlicReceiver) BandwidthSnapshot(destination ivnp.Hash) (DestinationBandwidthSnapshot, bool) {
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
func (r *GarlicReceiver) HandleGarlic(message i2np.Message) error {
	return r.HandleGarlicFrom(I2NPSource{}, message)
}

// HandleGarlicFrom preserves the authenticated outer transport predecessor for
// anonymous router Noise-N cloves.
func (r *GarlicReceiver) HandleGarlicFrom(source I2NPSource, message i2np.Message) error {
	if r == nil || r.service == nil || r.replyKeys == nil || r.now == nil {
		return ErrDataPlaneConfig
	}
	if message.Header.Type != i2np.Garlic {
		return ErrGarlicPacket
	}
	outer, err := i2np.ParseGarlic(message.Payload)
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
			if len(outer.Encrypted) < 8+16 {
				return ecies.ErrOneTimeReplyExistingSession
			}
			plainLen := len(outer.Encrypted) - 8 - 16
			if plainLen > i2np.I2PDMaxPayload {
				return i2np.ErrPayloadTooLarge
			}
			scratch := <-r.replyScratch
			reply, unwrapErr := ecies.OpenOneTimeReplyExistingSession(scratch[:plainLen], key.Key, key.Tag, outer.Encrypted)
			if unwrapErr ==
				nil {
				unwrapErr = r.service.
					dispatchClove(ivnp.
						Hash{}, garlic.Delivery{Type: garlic.
						DeliveryLocal}, reply, now, false)
			}

			clear(scratch[:plainLen])
			r.replyScratch <- scratch
			return unwrapErr
		}
	}
	if r.hasStatic {
		plainLen := len(outer.Encrypted) - 32 - 16
		if plainLen > 0 && plainLen <= i2np.I2PDMaxPayload {
			scratch := <-r.replyScratch
			inner, openErr := ecies.OpenRouterMessage(scratch[:plainLen], r.staticPrivate[:], outer.Encrypted, now)
			if openErr == nil {
				openErr = r.service.
					handleI2NP(inner, now, false, source)
			}

			clear(scratch[:plainLen])
			r.replyScratch <- scratch
			if openErr == nil {
				return nil
			}
		}
	}
	for _, destination := range destinations {
		if destination.Ratchet == nil || len(outer.Encrypted) > i2np.I2PDMaxPayload {
			continue
		}
		scratch := <-destination.scratch
		result, receiveErr := destination.Ratchet.Receive(scratch.plaintext[:], scratch.reply[:], outer.Encrypted, now)
		if receiveErr != nil {
			destination.scratch <- scratch
			continue
		}
		if destination.Limiter != nil && !destination.Limiter.TryAcquire(uint64(len(outer.Encrypted))) {
			clear(scratch.plaintext[:])
			clear(scratch.reply[:])
			destination.scratch <- scratch
			return ErrDestinationBandwidth
		}
		receiveErr = r.handleRatchetResult(destination, result, now)
		clear(scratch.plaintext[:])
		clear(scratch.reply[:])
		destination.scratch <- scratch
		return receiveErr
	}
	for _, destination := range destinations {
		if destination.Sessions == nil || len(outer.Encrypted) > i2np.I2PDMaxPayload {
			continue
		}
		scratch := <-destination.scratch
		payload, _, _, receiveErr := destination.Sessions.Receive(scratch.plaintext[:], outer.Encrypted, destination.Private, now)
		if receiveErr != nil {
			destination.scratch <- scratch
			continue
		}
		if destination.Limiter != nil && !destination.Limiter.TryAcquire(uint64(len(outer.Encrypted))) {
			clear(scratch.plaintext[:])
			destination.scratch <- scratch
			return ErrDestinationBandwidth
		}
		set, parseErr := garlic.ParseCloveSet(payload)
		if parseErr ==
			nil {
			parseErr = r.service.HandleGarlicCloveSet(set, now, false)
		}

		clear(scratch.plaintext[:])
		destination.scratch <- scratch
		return parseErr
	}
	return ErrGarlicDestination
}

func (r *GarlicReceiver) handleRatchetResult(destination *garlicDestinationState, result garlic.RatchetResult, now uint64) error {
	if len(result.Payload) == 0 && len(result.Reply) == 0 {
		return nil
	}
	cloves, err := parseRatchetGarlicCloves(result.Payload)
	if err != nil {
		return err
	}
	if len(result.Reply) != 0 {
		target, targetErr := ratchetReplyTarget(cloves, result.Peer)
		if targetErr != nil {
			return targetErr
		}
		remaining := cloves[:0]
		for _, clove := range cloves {
			if clove.Delivery.Type == garlic.DeliveryLocal && clove.Message.Header.Type == i2np.DatabaseStore {
				if err = r.service.dispatchClove(ivnp.Hash{}, clove.Delivery, clove.Message, now, false); err != nil {
					return err
				}
				continue
			}
			remaining = append(remaining, clove)
		}
		cloves = remaining
		if bindErr := destination.Ratchet.BindPeer(result.Peer, target); bindErr != nil {
			return bindErr
		}
		result.Peer = target
		if destination.SendRatchetReply == nil {
			return ErrGarlicDestination
		}
		if sendErr := destination.SendRatchetReply(context.Background(), target, result.Reply); sendErr != nil {
			return sendErr
		}
		if r.metrics != nil {
			r.metrics.IncGarlicECIESNewSessionSent()
		}
	}
	var dispatchErr error
	for _, clove := range cloves {
		dispatchErr = appendError(dispatchErr, r.service.dispatchClove(result.Peer, clove.Delivery, clove.Message, now, false))
	}
	return dispatchErr
}

func parseRatchetGarlicCloves(payload []byte) ([]garlic.Clove, error) {
	cloves := make([]garlic.Clove, 0, 4)
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
			cloves = append(cloves, clove)
		}
		payload = payload[size:]
	}
	if len(cloves) == 0 {
		return nil, ErrGarlicPacket
	}
	return cloves, nil
}

func parseRatchetGarlicClove(body []byte) (garlic.Clove, error) {
	delivery, used, err := garlic.ParseDelivery(body)
	if err != nil || len(body)-used < 9 {
		return garlic.Clove{}, ErrGarlicPacket
	}
	header := body[used : used+9]
	expiration := uint64(binary.BigEndian.Uint32(header[5:9])) * 1000
	message := i2np.Message{
		Header: i2np.Header{
			Type:       i2np.MessageType(header[0]),
			ID:         binary.BigEndian.Uint32(header[1:5]),
			Expiration: expiration,
		},
		Payload: body[used+9:],
	}
	return garlic.Clove{Delivery: delivery, Message: message, Expiration: expiration}, nil
}

// HandleDestinationData is the concrete Service destination sink. It accepts
// only Data cloves addressed to a configured local Destination and forwards the
// protocol, ports, and borrowed payload to its DestinationManager.
func marshalDestinationDataTo(dst []byte, delivery streamtunnel.Delivery) ([]byte, error) {
	if len(delivery.Payload) > int(^uint16(0)) {
		return nil, i2np.ErrPayloadTooLarge
	}
	dataLen := 4 + destinationDataHeaderLen + len(delivery.Payload)
	if len(dst) < dataLen {
		return nil, i2np.ErrPayloadTooLarge
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
	data, err := i2np.ParseData(payload)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	gzip := data.Data
	if len(gzip) < 18 || gzip[0] != 0x1f || gzip[1] != 0x8b || gzip[2] != 8 || gzip[3] != 0 {
		return 0, 0, 0, nil, ErrGarlicPacket
	}
	size := int(binary.LittleEndian.Uint32(gzip[len(gzip)-4:]))
	if size > i2np.I2PDMaxPayload {
		return 0, 0, 0, nil, i2np.ErrPayloadTooLarge
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

func (r *GarlicReceiver) HandleDestinationData(from, to ivnp.Hash, message i2np.Message, destinations *DestinationManager) error {
	if r == nil || destinations == nil || message.Header.Type != i2np.Data {
		return ErrGarlicPacket
	}
	if _, ok := r.destinations[to]; !ok {
		return ErrGarlicDestination
	}
	protocol, fromPort, toPort, payload, err := parseDestinationData(message.Payload)
	if err != nil {
		return err
	}
	if protocol == streamtunnel.ProtocolStreaming {
		packet, parseErr := streaming.Parse(payload)
		if parseErr != nil {
			return parseErr
		}
		if packet.Flags&streamtunnel.FlagFromIncluded != 0 {
			identity, _, identityErr := ivnp.ParseIdentity(packet.Options)
			if identityErr != nil {
				return identityErr
			}
			claimed := identity.Hash()
			if from != (ivnp.Hash{}) && claimed != from {
				return streamtunnel.ErrTunnelDestination
			}
			from = claimed
		}
	}
	if from == (ivnp.Hash{}) && protocol == streamtunnel.ProtocolStreaming {
		return ErrGarlicDestination
	}
	return destinations.HandleStreaming(context.Background(), streamtunnel.Delivery{
		From: from, To: to, Protocol: protocol, FromPort: fromPort, ToPort: toPort, Payload: payload,
	})
}

func ratchetReplyTarget(cloves []garlic.Clove, observed ivnp.Hash) (ivnp.Hash, error) {
	for _, clove := range cloves {
		if clove.Delivery.Type != garlic.DeliveryLocal || clove.Message.Header.Type != i2np.DatabaseStore {
			continue
		}
		store, err := i2np.ParseDatabaseStore(clove.Message.Payload)
		if err != nil || store.Type != i2np.StoreLeaseSet2 {
			continue
		}
		set, err := netdb.ParseLeaseSet2(store.Data)
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
				return ivnp.Hash{}, ErrGarlicPacket
			}
			ratchetReplyTargetRejected := (key.Type == ivnp.CryptoX25519 || key.Type == ivnp.CryptoMLKEM768X25519 || key.Type == ivnp.CryptoMLKEM1024X25519)
			if ratchetReplyTargetRejected {
				ratchetReplyTargetRejected = ivnp.Sum(key.Data) == observed
			}
			if ratchetReplyTargetRejected {
				return store.Key, nil
			}
		}
	}
	return ivnp.Hash{}, ErrGarlicPacket
}

func saturatingAdd(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}
