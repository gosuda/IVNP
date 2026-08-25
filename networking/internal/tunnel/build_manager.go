package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"sync"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	garlicecies "gosuda.org/ivnp/networking/internal/garlic/ecies"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/observability"
)

const (
	defaultMaxPendingBuilds  = 13 // Java BuildExecutor.MAX_CONCURRENT_BUILDS
	shortBuildPastSkew       = 8 * 60_000
	shortBuildFutureSkew     = 5 * 60_000
	shortBuildReplayLifetime = 10 * 60_000
	buildMessageLifetime     = 60_000
	buildRequestTimeout      = 5_000 // Java BuildRequestor.REQUEST_TIMEOUT
)

var (
	ErrBuildConfig     = errors.New("tunnel: invalid build configuration")
	ErrBuildPending    = errors.New("tunnel: build is not pending")
	ErrBuildRejected   = errors.New("tunnel: build rejected")
	ErrBuildTransit    = errors.New("tunnel: invalid transit build")
	ErrBuildFakeRecord = errors.New("tunnel: inbound creator fake record modified")
)

// ShortBuildHop is one ECIES-X25519 participant in path order.
type ShortBuildHop struct {
	Router          foundation.Hash
	StaticKey       [32]byte
	ReceiveTunnelID uint32
	Options         ShortBuildOptions
}

// ShortBuildOptions are optional per-hop bandwidth parameters. Zero omits a
// parameter; nonzero values are tunnel-message KBps.
type ShortBuildOptions struct {
	Minimum   uint32
	Requested uint32
	Limit     uint32
}

// OutboundBuild describes one modern short-record outbound tunnel. ReplyRouter
// and ReplyTunnelID identify an existing inbound tunnel used by the OBEP for
// the OutboundTunnelBuildReply.
type OutboundBuild struct {
	CircuitID     uint32
	Hops          []ShortBuildHop
	ReplyRouter   foundation.Hash
	ReplyTunnelID uint32
	ExpiresAt     uint64

	// retireID is assigned by Rotator for a renewal. It is intentionally kept
	// out of the source-facing build contract: no caller may retire a tunnel
	// unless the rotator selected it from the renewal window.
	retireID uint32
}

// InboundBuild describes a modern short-record inbound tunnel.
type InboundBuild struct {
	CircuitID        uint32
	OutboundTunnelID uint32
	CarrierEndpoint  foundation.Hash
	Hops             []ShortBuildHop
	ExpiresAt        uint64

	// retireID is assigned by paired maintenance for a renewal. It stays
	// private so only a selection made from the renewal window can retire a
	// live inbound path.
	retireID uint32
}

// BuildReplySender garlic-wraps the OBEP reply using the one-time key
// material derived from its endpoint build record and delivers it through the
// requested inbound tunnel. Implementations own the ECIES existing-session
// packet codec; BuildManager owns neither a garlic session nor packet buffers.
type BuildReplySender interface {
	SendBuildReply(context.Context, foundation.Hash, uint32, GarlicReplyKey, i2np.Message) error
}

// BuildAdmission decides whether a valid transit request may consume local
// tunnel capacity. It is invoked only after the request is authenticated and
// passes the protocol's time, lifetime, loop, and collision checks.
type BuildAdmission func(ShortBuildRequest) bool

// BuildBandwidth returns the KBps available to an authenticated transit build.
type BuildBandwidth func(ShortBuildRequest) uint32

// BuildStaticKeyLookup returns a retained RouterInfo identity encryption key.
type BuildStaticKeyLookup func(foundation.Hash) ([32]byte, bool)

// ReplyRouterInfoSeeder sends the selected inbound gateway RouterInfo to the
// outbound endpoint before its build request. The endpoint needs that address
// to route OutboundTunnelBuildReply through the requested inbound tunnel.
type ReplyRouterInfoSeeder func(context.Context, foundation.Hash, foundation.Hash) error

// BuildSource identifies how a build reached the local router. Direct sources
// are authenticated transport peers; a zero source is tunnel-originated.
type BuildSource struct {
	Router foundation.Hash
	Direct bool
}

type synchronizedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *synchronizedReader) Read(dst []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(dst)
}

// BuildManager creates and processes short-record and compatibility variable
// tunnel builds. Pending creator and transit replay state is bounded.
type BuildManager struct {
	runtime             *Runtime
	pool                *Pool
	sender              Sender
	replyKeys           GarlicReplyKeyRegistry
	replySender         BuildReplySender
	local               foundation.Hash
	staticPrivateKey    *ecdh.PrivateKey
	legacyPrivate       cryptography.ElGamalPrivateKey
	legacyEnabled       bool
	admit               BuildAdmission
	bandwidth           BuildBandwidth
	staticKeyLookup     BuildStaticKeyLookup
	seedReplyRouterInfo ReplyRouterInfoSeeder
	localDelivery       func(i2np.Message) error
	now                 func() uint64
	random              io.Reader
	profiles            *PeerProfiles
	maxPending          int
	logger              *slog.Logger
	metrics             *observability.Registry

	lifecycleMu     sync.RWMutex
	mu              sync.Mutex
	pending         map[uint32]*pendingOutboundBuild
	pendingInbound  map[uint32]*pendingInboundBuild
	pendingVariable map[uint32]*pendingVariableBuild
	transit         map[uint32]uint64
	transitRecords  map[[32]byte]uint64
	released        bool
	ctx             context.Context
	cancel          context.CancelFunc
}

type pendingOutboundBuild struct {
	build       OutboundBuild
	keys        []ShortBuildKeys
	positions   []uint8
	replyID     uint32
	replyTag    [8]byte
	recordCount uint8
	startedAt   uint64
	deadline    uint64
}

type pendingInboundBuild struct {
	build        InboundBuild
	keys         []ShortBuildKeys
	positions    []uint8
	replyID      uint32
	recordCount  uint8
	fakePosition uint8
	fakeHash     [32]byte
	startedAt    uint64
	deadline     uint64
}

type pendingVariableBuild struct {
	build       VariableOutboundBuild
	keys        []VariableBuildKeys
	positions   []uint8
	replyID     uint32
	recordCount uint8
	deadline    uint64
}

// VariableOutboundBuild creates the historical 528-byte VariableTunnelBuild
// form. It is only for mixed ElGamal/long-ECIES interoperability.
type VariableOutboundBuild struct {
	CircuitID     uint32
	Hops          []VariableBuildHop
	ReplyRouter   foundation.Hash
	ReplyTunnelID uint32
	ExpiresAt     uint64
	retireID      uint32
}

// BuildManagerConfig provides the network handoff and local ECIES or legacy
// ElGamal identity needed by short and compatibility build processing.
type BuildManagerConfig struct {
	Runtime             *Runtime
	Pool                *Pool
	Sender              Sender
	ReplyKeys           GarlicReplyKeyRegistry
	ReplySender         BuildReplySender
	LocalRouter         foundation.Hash
	StaticPrivate       []byte
	LegacyPrivate       []byte
	Admission           BuildAdmission
	Bandwidth           BuildBandwidth
	StaticKeyLookup     BuildStaticKeyLookup
	SeedReplyRouterInfo ReplyRouterInfoSeeder
	LocalDelivery       func(i2np.Message) error
	Now                 func() uint64
	Random              io.Reader
	// Profiles receives terminal authenticated build observations. It is
	// optional for compatibility-only runtimes without tunnel selection.
	Profiles   *PeerProfiles
	MaxPending int
	Logger     *slog.Logger
	Metrics    *observability.Registry
}

func NewBuildManager(config BuildManagerConfig) (*BuildManager, error) {
	newBuildManagerRejected := config.Runtime == nil || config.Sender == nil || config.ReplyKeys == nil || config.Now == nil || len(config.StaticPrivate) != 0 && len(config.StaticPrivate) != 32
	if !newBuildManagerRejected {
		newBuildManagerRejected = len(config.LegacyPrivate) != 0 && len(config.LegacyPrivate) != cryptography.ElGamalPrivateKeySize
	}
	if newBuildManagerRejected {
		return nil, ErrBuildConfig
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MaxPending <= 0 {
		config.MaxPending = defaultMaxPendingBuilds
	}
	var staticPrivateKey *ecdh.PrivateKey
	if len(config.StaticPrivate) != 0 {
		var err error
		staticPrivateKey, err = ecdh.X25519().NewPrivateKey(config.StaticPrivate)
		if err != nil {
			return nil, ErrBuildConfig
		}
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	manager := &BuildManager{
		runtime: config.Runtime, pool: config.Pool, sender: config.Sender, replyKeys: config.ReplyKeys, replySender: config.ReplySender,
		local: config.LocalRouter, admit: config.Admission, bandwidth: config.Bandwidth, staticKeyLookup: config.StaticKeyLookup,
		seedReplyRouterInfo: config.SeedReplyRouterInfo,
		localDelivery:       config.LocalDelivery, now: config.Now, random: &synchronizedReader{reader: config.Random}, profiles: config.Profiles,
		maxPending: config.MaxPending, pending: make(map[uint32]*pendingOutboundBuild), pendingInbound: make(map[uint32]*pendingInboundBuild),
		pendingVariable: make(map[uint32]*pendingVariableBuild), transit: make(map[uint32]uint64),
		transitRecords: make(map[[32]byte]uint64), staticPrivateKey: staticPrivateKey,
		logger: config.Logger, metrics: config.Metrics, ctx: lifecycle, cancel: cancel,
	}
	if len(config.LegacyPrivate) != 0 {
		copy(manager.legacyPrivate[:], config.LegacyPrivate)
		manager.legacyEnabled = true
	}
	return manager, nil
}

// ReleaseSensitive retires the manager after its lifecycle owner has stopped
// build work. It clears all retained pending build keys and IVNP-owned static
// private material; the standard-library X25519 key is dropped as an opaque
// reference because its internals are not erasable by callers.
func (m *BuildManager) ReleaseSensitive() {
	if m == nil {
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	if m.released {
		m.mu.Unlock()
		return
	}
	m.released = true
	for id, pending := range m.pending {
		if pending.replyTag != ([8]byte{}) {
			m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		}
		clear(pending.keys)
		clear(pending.positions)
		clear(pending.replyTag[:])
		delete(m.pending, id)
	}
	for id, pending := range m.pendingInbound {
		clear(pending.keys)
		clear(pending.positions)
		clear(pending.fakeHash[:])
		delete(m.pendingInbound, id)
	}
	for id, pending := range m.pendingVariable {
		clear(pending.keys)
		clear(pending.positions)
		delete(m.pendingVariable, id)
	}
	clear(m.transit)
	clear(m.transitRecords)
	m.staticPrivateKey = nil
	clear(m.legacyPrivate[:])
	m.legacyEnabled = false
	m.random = nil
	m.mu.Unlock()
}

// Close cancels and joins active build work before clearing pending sensitive
// keys. ReleaseSensitive remains the sensitive-owner spelling.
func (m *BuildManager) Close() error {
	m.ReleaseSensitive()
	return nil
}

func (m *BuildManager) isReleased() bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	released := m.released
	m.mu.Unlock()
	return released
}

// StartOutbound creates, conceals, and sends one ShortTunnelBuild message. The
// returned ID identifies the expected OutboundTunnelBuildReply.
func (m *BuildManager) StartOutbound(ctx context.Context, build OutboundBuild) (uint32, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return 0, ErrBuildConfig
	}
	if ctx == nil {
		ctx = context.
			Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := m.now()
	startOutboundRejected := build.CircuitID == 0 || len(build.Hops) < 1 || len(build.Hops) > i2np.MaxVariableBuildRecords || build.ReplyRouter == (foundation.Hash{}) || build.ReplyTunnelID == 0 || build.Hops[len(build.Hops)-1].Router == build.ReplyRouter
	if !startOutboundRejected {
		startOutboundRejected = build.ExpiresAt <= now
	}
	if startOutboundRejected {
		return 0, ErrBuildConfig
	}
	for index, hop := range build.Hops {
		if hop.ReceiveTunnelID == 0 || hop.Router == (foundation.Hash{}) || hop.StaticKey == ([32]byte{}) || !validShortBuildOptions(hop.Options, false) || !m.validHopStaticKey(hop) {
			return 0, ErrBuildConfig
		}
		for previous := range index {
			if build.Hops[previous].Router == hop.Router || build.Hops[previous].ReceiveTunnelID == hop.ReceiveTunnelID {
				return 0, ErrBuildConfig
			}
		}
	}

	var messageIDStorage [i2np.MaxVariableBuildRecords + 1]uint32
	messageIDs := messageIDStorage[:len(build.Hops)+1]
	for index := range messageIDs {
		id, err := m.uniqueMessageID(messageIDs[:index])
		if err != nil {
			return 0, err
		}
		messageIDs[index] = id
	}
	recordCount := max(4, len(build.Hops))
	positions, err := m.randomPositions(len(build.Hops), recordCount)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 1+recordCount*ShortBuildRecordSize)
	payload[0] = byte(recordCount)
	if _, err = io.ReadFull(m.random, payload[1:]); err != nil {
		return 0, err
	}
	keys := make([]ShortBuildKeys, len(build.Hops))
	for index, hop := range build.Hops {
		nextRouter, nextTunnel := build.ReplyRouter, build.ReplyTunnelID
		if index+1 < len(build.Hops) {
			nextRouter = build.Hops[index+1].Router
			nextTunnel = build.Hops[index+1].ReceiveTunnelID
		}
		request := ShortBuildRequest{
			ReceiveTunnelID: hop.ReceiveTunnelID,
			NextTunnelID:    nextTunnel,
			NextRouter:      nextRouter,
			Endpoint:        index+1 == len(build.Hops),
			RequestMinutes:  uint32(now / 60_000),
			LifetimeSeconds: shortBuildLifetime,
			NextMessageID:   messageIDs[index+1],
		}
		var plaintext [ShortBuildRequestPlainSize]byte
		options, optionsErr := marshalShortBuildOptions(hop.Options)
		if optionsErr != nil {
			clearBuildKeys(keys)
			return 0, optionsErr
		}
		if err = marshalShortBuildRequest(plaintext[:], request, options, m.random); err != nil {
			clearBuildKeys(keys)
			return 0, err
		}
		offset := 1 + int(positions[index])*ShortBuildRecordSize
		keys[index], err = encryptShortBuildRequest(payload[offset:offset+ShortBuildRecordSize], hop.Router, hop.StaticKey[:], plaintext[:], m.random)
		clear(plaintext[:])
		if err != nil {
			clearBuildKeys(keys)
			return 0, err
		}
	}
	if err = PreprocessShortBuildRecords(payload[1:], keys, positions); err != nil {
		clearBuildKeys(keys)
		return 0, err
	}

	if m.seedReplyRouterInfo != nil {
		endpoint := build.Hops[len(build.Hops)-1].Router
		if err = m.seedReplyRouterInfo(ctx, endpoint, build.ReplyRouter); err != nil {
			m.recordShortBuild(build.Hops[len(build.Hops)-1:], false, 0)
			if m.metrics != nil {
				m.metrics.IncTunnelBuildFailures()
			}
			if m.logger != nil {
				m.logger.Warn("tunnel build reply RouterInfo seed failed", "direction", "outbound", "endpoint", foundation.EncodeI2PBase64(endpoint[:]), "error", err)
			}
			clearBuildKeys(keys)
			return 0, err
		}
	}
	replyID := messageIDs[len(messageIDs)-1]
	endpointKeys := keys[len(keys)-1]
	if !endpointKeys.HasGarlicKeys {
		clearBuildKeys(keys)
		return 0, ErrBuildConfig
	}
	pending := &pendingOutboundBuild{
		build: cloneOutboundBuild(build), keys: keys, positions: positions, replyID: replyID, replyTag: endpointKeys.GarlicTag,
		recordCount: uint8(recordCount), startedAt: now, deadline: min(build.ExpiresAt, now+buildRequestTimeout),
	}
	m.mu.Lock()
	if len(m.pending)+len(m.pendingInbound)+len(m.pendingVariable) >= m.maxPending || m.pending[replyID] != nil || m.pendingInbound[replyID] != nil || m.pendingVariable[replyID] != nil {
		m.mu.Unlock()
		clearBuildKeys(keys)
		return 0, ErrBuildPending
	}
	m.pending[replyID] = pending
	m.mu.Unlock()
	if err = m.replyKeys.RegisterGarlicReplyKey(GarlicReplyKey{
		Key: endpointKeys.GarlicKey, Tag: endpointKeys.GarlicTag, ExpiresAt: pending.deadline,
	}); err != nil {
		m.removePending(replyID)
		return 0, err
	}

	if m.metrics != nil {
		m.metrics.IncTunnelBuilds()
	}
	if m.logger != nil {
		m.logger.Info("tunnel build send", "direction", "outbound", "reply_id", replyID, "hop_count", len(build.Hops), "peers", buildPeerDiagnostics(build.Hops))
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: messageIDs[0], Expiration: now + buildMessageLifetime}, Payload: payload}
	if err = m.sender.Send(ctx, build.Hops[0].Router, message); err != nil {
		m.removePending(replyID)
		m.recordShortBuild(build.Hops, false, 0)
		if m.metrics != nil {
			m.metrics.IncTunnelBuildFailures()
		}
		if m.logger != nil {
			m.logger.Warn("tunnel build send failed", "direction", "outbound", "reply_id", replyID, "peer", foundation.EncodeI2PBase64(build.Hops[0].Router[:]), "error", err)
		}
		return 0, err
	}
	return replyID, nil
}

// StartInbound creates an inbound short-build request. Normally it injects the
// request through an already-established outbound tunnel. During startup only,
// OutboundTunnelID zero is the explicit fake zero-hop outbound path and sends
// the request directly to its selected inbound gateway.
func (m *BuildManager) StartInbound(ctx context.Context, build InboundBuild) (uint32, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return 0, ErrBuildConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := m.now()
	carrierEndpoint := build.CarrierEndpoint
	if build.OutboundTunnelID != 0 && carrierEndpoint == (foundation.Hash{}) && m.pool != nil {
		if carrier, ok := m.pool.Get(build.OutboundTunnelID, now); ok && carrier.Direction == Outbound && carrier.HopCount != 0 {
			carrierEndpoint = carrier.Hops[carrier.HopCount-1]
		}
	}
	if build.OutboundTunnelID != 0 && carrierEndpoint == (foundation.Hash{}) {
		return 0, ErrBuildConfig
	}
	startInboundRejected := build.CircuitID == 0 || build.CircuitID == build.OutboundTunnelID || m.local == (foundation.Hash{}) || m.localDelivery == nil || build.ExpiresAt <= now || len(build.Hops) < 1
	if !startInboundRejected {
		startInboundRejected = len(build.Hops) >= i2np.MaxVariableBuildRecords
	}
	if startInboundRejected {
		return 0, ErrBuildConfig
	}
	if err := validateShortBuildHops(build.Hops); err != nil {
		return 0, err
	}
	for index, hop := range build.Hops {
		if !validShortBuildOptions(hop.Options, index == 0) || !m.validHopStaticKey(hop) {
			return 0, ErrBuildConfig
		}
	}
	if build.Hops[len(build.Hops)-1].Router != build.Hops[0].Router {
		if ensurer, ok := m.sender.(SessionEnsurer); ok {
			replyPeer := build.Hops[len(build.Hops)-1].Router
			if err := ensurer.EnsureSession(ctx, replyPeer); err != nil {
				m.recordShortBuild(build.Hops, false, 0)
				if m.metrics != nil {
					m.metrics.IncTunnelBuilds()
					m.metrics.IncTunnelBuildFailures()
				}
				if m.logger != nil {
					m.logger.Warn("tunnel build reply session failed", "direction", "inbound", "peer", foundation.EncodeI2PBase64(replyPeer[:]), "error", err)
				}
				return 0, err
			}
			if m.logger != nil {
				m.logger.Debug("tunnel build reply session ready", "direction", "inbound", "peer", foundation.EncodeI2PBase64(replyPeer[:]))
			}
		}
	}
	var messageIDStorage [i2np.MaxVariableBuildRecords + 1]uint32
	messageIDs := messageIDStorage[:len(build.Hops)+1]
	for index := range messageIDs {
		id, err := m.uniqueMessageID(messageIDs[:index])
		if err != nil {
			return 0, err
		}
		messageIDs[index] = id
	}
	recordCount := max(4, len(build.Hops)+1)
	allPositions, err := m.randomPositions(len(build.Hops)+1, recordCount)
	if err != nil {
		return 0, err
	}
	positions := allPositions[:len(build.Hops)]
	fakePosition := allPositions[len(build.Hops)]
	payload := make([]byte, 1+recordCount*ShortBuildRecordSize)
	payload[0] = byte(recordCount)
	if _, err = io.ReadFull(m.random, payload[1:]); err != nil {
		return 0, err
	}
	fakeOffset := 1 + int(fakePosition)*ShortBuildRecordSize
	fakeRecord := payload[fakeOffset : fakeOffset+ShortBuildRecordSize]
	copy(fakeRecord[:shortBuildPeerSize], m.local[:shortBuildPeerSize])
	fakePrivate, err := ecdh.X25519().GenerateKey(m.random)
	if err != nil {
		return 0, err
	}
	copy(fakeRecord[shortBuildPeerSize:shortBuildCipherOffset], fakePrivate.PublicKey().Bytes())
	var originalFake [ShortBuildRecordSize]byte
	copy(originalFake[:], fakeRecord)
	fakeHash := sha256.Sum256(originalFake[:])
	keys := make([]ShortBuildKeys, len(build.Hops))
	for index, hop := range build.Hops {
		nextRouter, nextTunnel := m.local, build.CircuitID
		if index+1 < len(build.Hops) {
			nextRouter, nextTunnel = build.Hops[index+1].Router, build.Hops[index+1].ReceiveTunnelID
		}
		request := ShortBuildRequest{
			ReceiveTunnelID: hop.ReceiveTunnelID,
			NextTunnelID:    nextTunnel,
			NextRouter:      nextRouter,
			Gateway:         index == 0,
			RequestMinutes:  uint32(now / 60_000),
			LifetimeSeconds: shortBuildLifetime,
			NextMessageID:   messageIDs[index+1],
		}
		var plaintext [ShortBuildRequestPlainSize]byte
		options, optionsErr := marshalShortBuildOptions(hop.Options)
		if optionsErr != nil {
			clearBuildKeys(keys)
			return 0, optionsErr
		}
		if err = marshalShortBuildRequest(plaintext[:], request, options, m.random); err != nil {
			clearBuildKeys(keys)
			return 0, err
		}
		offset := 1 + int(positions[index])*ShortBuildRecordSize
		keys[index], err = encryptShortBuildRequest(payload[offset:offset+ShortBuildRecordSize], hop.Router, hop.StaticKey[:], plaintext[:], m.random)
		clear(plaintext[:])
		if err != nil {
			clearBuildKeys(keys)
			return 0, err
		}
	}
	if err = PreprocessShortBuildRecords(payload[1:], keys, positions); err != nil {
		clearBuildKeys(keys)
		return 0, err
	}
	for _, key := range keys[:len(keys)-1] {
		if err = TransformShortBuildRecord(fakeRecord, fakeRecord, key.ReplyKey, fakePosition); err != nil {
			clearBuildKeys(keys)
			return 0, err
		}
	}
	clear(originalFake[:])
	replyID := messageIDs[len(messageIDs)-1]
	pending := &pendingInboundBuild{
		build: cloneInboundBuild(build), keys: keys, positions: positions, replyID: replyID,
		recordCount: uint8(recordCount), fakePosition: fakePosition, fakeHash: fakeHash,
		startedAt: now, deadline: min(build.ExpiresAt, now+buildRequestTimeout),
	}
	m.mu.Lock()
	if len(m.pending)+len(m.pendingInbound)+len(m.pendingVariable) >= m.maxPending || m.pendingInbound[replyID] != nil || m.pending[replyID] != nil || m.pendingVariable[replyID] != nil {
		m.mu.Unlock()
		clearBuildKeys(keys)
		return 0, ErrBuildPending
	}
	m.pendingInbound[replyID] = pending
	m.mu.Unlock()
	if m.metrics != nil {
		m.metrics.IncTunnelBuilds()
	}
	if m.logger != nil {
		m.logger.Info("tunnel build send", "direction", "inbound", "reply_id", replyID, "hop_count", len(build.Hops), "peers", buildPeerDiagnostics(build.Hops), "carrier_tunnel_id", build.OutboundTunnelID)
	}
	message := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: messageIDs[0], Expiration: now + buildMessageLifetime}, Payload: payload}
	if build.OutboundTunnelID == 0 {
		if err = m.sender.Send(ctx, build.Hops[0].Router, message); err != nil {
			m.removeInboundPending(replyID)
			m.recordShortBuild(build.Hops, false, 0)
			if m.metrics != nil {
				m.metrics.IncTunnelBuildFailures()
			}
			if m.logger != nil {
				m.logger.Warn("tunnel build send failed", "direction", "inbound", "reply_id", replyID, "peer", foundation.EncodeI2PBase64(build.Hops[0].Router[:]), "error", err)
			}
			return 0, err
		}
		return replyID, nil
	}
	frameMessage := message
	if carrierEndpoint != build.Hops[0].Router {
		encrypted := make([]byte, 32+7+3+10+message.EncodedLen()+16)
		sealed, wrapErr := garlicecies.SealRouterMessage(encrypted, build.Hops[0].StaticKey[:], message, now, m.random)
		if wrapErr != nil {
			m.removeInboundPending(replyID)
			return 0, wrapErr
		}
		garlicPayload := make([]byte, 4+len(sealed))
		binary.BigEndian.PutUint32(garlicPayload[:4], uint32(len(sealed)))
		copy(garlicPayload[4:], sealed)
		frameMessage = i2np.Message{Header: i2np.Header{Type: i2np.Garlic, ID: messageIDs[0] ^ replyID, Expiration: now + buildMessageLifetime}, Payload: garlicPayload}
	}
	frame := make([]byte, frameMessage.EncodedLen())
	if _, err = frameMessage.MarshalTo(frame); err != nil {
		m.removeInboundPending(replyID)
		return 0, err
	}
	if err = m.runtime.SendBlock(ctx, build.OutboundTunnelID, Block{Delivery: DeliveryRouter, Gateway: build.Hops[0].Router, Last: true, Data: frame}); err != nil {
		m.removeInboundPending(replyID)
		m.recordShortBuild(build.Hops, false, 0)
		return 0, err
	}
	if m.logger != nil {
		m.logger.Debug("tunnel build sent", "direction", "inbound", "reply_id", replyID, "phase", "outbound_carrier")
	}
	return replyID, nil
}

// HandleInboundReply claims only a creator-side inbound short-build reply.
// ErrBuildPending means this manager does not own the reply ID; callers may
// safely continue to another destination manager or transit handling.
func (m *BuildManager) HandleInboundReply(message i2np.Message) error {
	if m == nil {
		return ErrBuildPending
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildPending
	}
	if message.Header.Type != i2np.ShortTunnelBuild || !m.hasInboundPending(message.Header.ID) {
		return ErrBuildPending
	}
	return m.handleInboundReply(message)
}

// HandleBuild accepts creator replies delivered through a local tunnel. Direct
// transport requests must use HandleBuildFrom so predecessor loops can be
// checked against the authenticated peer.
func (m *BuildManager) HandleBuild(message i2np.Message) error {
	return m.handleBuild(BuildSource{}, message)
}

// HandleBuildFrom processes a build received from an authenticated transport
// peer.
func (m *BuildManager) HandleBuildFrom(predecessor foundation.Hash, message i2np.Message) error {
	return m.handleBuild(BuildSource{Router: predecessor, Direct: true}, message)
}

func (m *BuildManager) handleBuild(source BuildSource, message i2np.Message) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildConfig
	}
	switch message.Header.Type {
	case i2np.ShortTunnelBuild:
		if m.hasInboundPending(message.Header.ID) {
			return m.handleInboundReply(message)
		}
		return m.handleTransit(source, message)
	case i2np.VariableTunnelBuild:
		return m.handleVariableTransit(message)
	default:
		return ErrBuildConfig
	}
}

func (m *BuildManager) handleInboundReply(message i2np.Message) error {
	pending := m.takeInboundPending(message.Header.ID)
	if pending == nil {
		return ErrBuildPending
	}
	success := false
	peerFailure := false
	defer func() {
		if success {
			return
		}
		if peerFailure {
			m.recordShortBuild(pending.build.Hops, false, 0)
		}
		if m.metrics != nil {
			m.metrics.IncTunnelBuildFailures()
		}
	}()
	defer clearBuildKeys(pending.keys)
	records, err := i2np.ParseBuildRecords(i2np.ShortTunnelBuild, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	if pending.deadline <= now || records.Count != pending.recordCount {
		return ErrBuildPending
	}
	fake := records.Records[int(pending.fakePosition)*ShortBuildRecordSize : (int(pending.fakePosition)+1)*ShortBuildRecordSize]
	var verifiedFake [ShortBuildRecordSize]byte
	copy(verifiedFake[:], fake)
	if err = TransformShortBuildRecord(verifiedFake[:], verifiedFake[:], pending.keys[len(pending.keys)-1].ReplyKey, pending.fakePosition); err != nil {
		clear(verifiedFake[:])
		return err
	}
	actualFakeHash := sha256.Sum256(verifiedFake[:])
	clear(verifiedFake[:])
	if subtle.ConstantTimeCompare(actualFakeHash[:], pending.fakeHash[:]) != 1 {
		return ErrBuildFakeRecord
	}
	replies := make([]byte, len(pending.keys)*ShortBuildReplyPlainSize)
	defer clear(replies)
	if err = OpenShortBuildReplies(records.Records, pending.keys, pending.positions, replies); err != nil {
		return err
	}
	for hop := range pending.keys {
		if replies[(hop+1)*ShortBuildReplyPlainSize-1] != 0 {
			peerFailure = true
			return ErrBuildRejected
		}
	}
	transforms := make([]LayerCipher, len(pending.keys))
	for hop := range pending.keys {
		key := pending.keys[len(pending.keys)-1-hop]
		transforms[hop], err = NewLayerDecryptor(key.LayerKey[:], key.IVKey[:])
		if err != nil {
			return err
		}
	}
	owner := foundation.Hash{}
	if m.pool != nil {
		owner = m.pool.Owner()
	}
	circuit := InboundCircuit{ID: pending.build.CircuitID, Owner: owner, Transforms: transforms, Endpoint: NewEndpoint(128, 0), Local: m.localDelivery, ExpiresAt: pending.build.ExpiresAt}
	entry := Entry{
		ID: circuit.ID, Direction: Inbound, Expires: circuit.ExpiresAt, Owner: owner,
		Gateway: pending.build.Hops[0].Router, GatewayTunnelID: pending.build.Hops[0].ReceiveTunnelID,
	}
	setEntryHops(&entry, pending.build.Hops)
	var retired Entry
	var replaced bool
	if m.pool != nil {
		retired, replaced, err = m.pool.Replace(entry, pending.build.retireID, now)
		if err != nil {
			return err
		}
	}
	if err = m.runtime.RegisterInbound(circuit); err != nil {
		if m.pool != nil {
			m.pool.RollbackReplace(entry, retired, replaced, m.now())
		}
		return err
	}
	if replaced {
		m.runtime.RemoveCircuit(retired.ID)
	}
	m.recordShortBuild(pending.build.Hops, true, now-pending.startedAt)
	success = true
	if m.metrics != nil {
		m.metrics.IncTunnelBuildSuccesses()
	}
	if m.logger != nil {
		m.logger.Info("tunnel build reply authenticated", "direction", "inbound", "reply_id", message.Header.ID, "latency_ms", now-pending.startedAt, "hop_count", len(pending.build.Hops))
	}
	return nil
}

func (m *BuildManager) hasInboundPending(id uint32) bool {
	m.mu.Lock()
	_, ok := m.pendingInbound[id]
	m.mu.Unlock()
	return ok
}

func (m *BuildManager) handleTransit(source BuildSource, message i2np.Message) error {
	if m.local == (foundation.Hash{}) || m.staticPrivateKey == nil {
		return ErrBuildConfig
	}
	records, err := i2np.ParseBuildRecords(i2np.ShortTunnelBuild, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	var plaintext [ShortBuildRequestPlainSize]byte
	defer clear(plaintext[:])
	slot := -1
	for index := range records.Count {
		offset := int(index) * ShortBuildRecordSize
		record := records.Records[offset : offset+ShortBuildRecordSize]
		if subtle.ConstantTimeCompare(record[:shortBuildPeerSize], m.local[:shortBuildPeerSize]) == 1 {
			if slot >= 0 {
				clear(plaintext[:])
				return ErrBuildTransit
			}
			slot = int(index)
		}
	}
	if slot < 0 {
		return ErrBuildTransit
	}
	record := records.Records[slot*ShortBuildRecordSize : (slot+1)*ShortBuildRecordSize]
	replayHash := sha256.Sum256(record)
	_, keys, err := decryptShortBuildRequestWithPrivate(plaintext[:], record, m.local, m.staticPrivateKey)
	if err != nil {
		clear(plaintext[:])
		return err
	}
	request, err := ParseShortBuildRequest(plaintext[:])
	if err != nil {
		return err
	}
	defer clearBuildKey(&keys)
	if !m.validTransitRequest(request, keys, now, source) {
		return ErrBuildRejected
	}
	if !m.reserveTransit(message.Header.ID, replayHash, now) {
		return ErrBuildTransit
	}
	if m.runtime.hasCircuit(request.ReceiveTunnelID) {
		m.releaseTransit(message.Header.ID, replayHash)
		return ErrBuildRejected
	}
	options := request.Bandwidth
	needsBandwidth := options.Minimum != 0 || options.Requested != 0
	available := uint32(0)
	if needsBandwidth && m.bandwidth != nil {
		available = m.bandwidth(request)
	}
	accept := !needsBandwidth || available != 0 && available >= options.Minimum
	if accept && m.admit != nil {
		accept = m.admit(request)
	}
	if accept {
		accept = m.installTransitCircuit(request, keys, now) == nil
	}
	replyCode := byte(30)
	if accept {
		replyCode = 0
	}
	if err = sealBuildReply(record, keys, uint8(slot), m.random, replyCode, available, accept && needsBandwidth); err != nil {
		return err
	}
	for index := range records.Count {
		if int(index) == slot {
			continue
		}
		offset := int(index) * ShortBuildRecordSize
		other := records.Records[offset : offset+ShortBuildRecordSize]
		if err = TransformShortBuildRecord(other, other, keys.ReplyKey, uint8(index)); err != nil {
			return err
		}
	}
	if request.Endpoint {
		// The ECIES wrapper requires derived garlic material only for a remote
		// reply gateway. Java I2P and i2pd both allow the matching local
		// gateway to receive the unwrapped reply through local Service.
		canReply := m.replySender != nil && request.NextRouter != (foundation.Hash{}) && request.NextTunnelID != 0 && (request.NextRouter == m.local || keys.HasGarlicKeys)
		if !canReply {
			if accept {
				m.runtime.RemoveCircuit(request.ReceiveTunnelID)
			}
			return ErrBuildRejected
		}
		reply := i2np.Message{Header: i2np.Header{Type: i2np.OutboundTunnelBuildReply, ID: request.NextMessageID, Expiration: now + buildMessageLifetime}, Payload: message.Payload}
		key := GarlicReplyKey{Key: keys.GarlicKey, Tag: keys.GarlicTag, ExpiresAt: now + buildMessageLifetime}
		if err = m.replySender.SendBuildReply(m.ctx, request.NextRouter, request.NextTunnelID, key, reply); err != nil {
			if accept {
				m.runtime.RemoveCircuit(request.ReceiveTunnelID)
			}
			return err
		}
		if !accept {
			return ErrBuildRejected
		}
		return nil
	}
	forward := i2np.Message{Header: i2np.Header{Type: i2np.ShortTunnelBuild, ID: request.NextMessageID, Expiration: now + buildMessageLifetime}, Payload: message.Payload}
	if err = m.sender.Send(m.ctx, request.NextRouter, forward); err != nil {
		if accept {
			m.runtime.RemoveCircuit(request.ReceiveTunnelID)
		}
		return err
	}
	if !accept {
		return ErrBuildRejected
	}
	return nil
}

func (m *BuildManager) validTransitRequest(request ShortBuildRequest, keys ShortBuildKeys, now uint64, source BuildSource) bool {
	requestTime := uint64(request.RequestMinutes) * 60_000
	roundedNow := now - now%60_000
	validTransitRequestRejected := !source.Direct || source.Router == (foundation.Hash{}) || source.Router == m.local
	if !validTransitRequestRejected {
		validTransitRequestRejected = !request.Gateway && !request.Endpoint && request.NextRouter == source.Router
	}
	if validTransitRequestRejected {
		return false
	}
	validTransitRequestRejected = request.LifetimeSeconds != shortBuildLifetime || request.ReceiveTunnelID == 0 || request.NextTunnelID == 0 || request.NextMessageID == 0 || request.NextRouter == (foundation.Hash{}) || !request.Endpoint && request.NextRouter == m.local
	if !validTransitRequestRejected {
		validTransitRequestRejected = request.ReceiveTunnelID == request.NextTunnelID
	}
	if validTransitRequestRejected {
		return false
	}
	if requestTime > roundedNow+shortBuildFutureSkew || requestTime+shortBuildPastSkew < roundedNow {
		return false
	}
	if !validShortBuildOptions(request.Bandwidth, request.Gateway) {
		return false
	}
	return !request.Endpoint || m.replySender != nil && m.localDelivery != nil && keys.HasGarlicKeys
}

func (m *BuildManager) installTransitCircuit(request ShortBuildRequest, keys ShortBuildKeys, now uint64) error {
	expiresAt := now + uint64(request.LifetimeSeconds)*1_000
	if expiresAt < now {
		return ErrBuildTransit
	}
	if request.Gateway {
		encryptor, err := NewLayerEncryptor(keys.LayerKey[:], keys.IVKey[:])
		if err != nil {
			return err
		}
		return m.runtime.RegisterOutbound(OutboundCircuit{
			ID: request.ReceiveTunnelID, FirstHop: request.NextRouter, NextTunnelID: request.NextTunnelID,
			Transforms: []LayerCipher{encryptor}, ExpiresAt: expiresAt,
		})
	}
	encryptor, err := NewLayerEncryptor(keys.LayerKey[:], keys.IVKey[:])
	if err != nil {
		return err
	}
	circuit := InboundCircuit{ID: request.ReceiveTunnelID, Transforms: []LayerCipher{encryptor}, ExpiresAt: expiresAt}
	if request.Endpoint {
		// OBEP terminates the outbound tunnel and delivers decrypted blocks.
		circuit.Endpoint = NewEndpoint(128, 0)
		circuit.Local = m.localDelivery
	} else {
		// Intermediate hops peel one layer and forward.
		circuit.Forward = &Forward{Peer: request.NextRouter, TunnelID: request.NextTunnelID}
	}
	return m.runtime.RegisterInbound(circuit)
}

func (m *BuildManager) reserveTransit(id uint32, recordHash [32]byte, now uint64) bool {
	if id == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for messageID, deadline := range m.transit {
		if deadline <= now {
			delete(m.transit, messageID)
		}
	}
	for hash, deadline := range m.transitRecords {
		if deadline <= now {
			delete(m.transitRecords, hash)
		}
	}
	if _, exists := m.transit[id]; exists {
		return false
	}
	if _, exists := m.transitRecords[recordHash]; exists || len(m.transitRecords) >= m.maxPending {
		return false
	}
	m.transit[id] = now + buildMessageLifetime
	m.transitRecords[recordHash] = now + shortBuildReplayLifetime
	return true
}
func (m *BuildManager) releaseTransit(id uint32, recordHash [32]byte) {
	m.mu.Lock()
	delete(m.transit, id)
	delete(m.transitRecords, recordHash)
	m.mu.Unlock()
}

func sealBuildReply(record []byte, keys ShortBuildKeys, slot uint8, random io.Reader, code byte, bandwidth uint32, includeBandwidth bool) error {
	var reply [ShortBuildReplyPlainSize]byte
	optionsLen := 2
	if includeBandwidth {
		var value [10]byte
		digits := strconv.AppendUint(value[:0], uint64(bandwidth), 10)
		n, err := foundation.MarshalMappingTo(reply[:], []foundation.MappingEntry{{Key: []byte("b"), Value: digits}})
		if err != nil {
			return err
		}
		optionsLen = n
	}
	if _, err := io.ReadFull(random, reply[optionsLen:len(reply)-1]); err != nil {
		return err
	}
	reply[len(reply)-1] = code
	_, err := SealShortBuildReply(record, reply[:], keys, slot)
	clear(reply[:])
	return err
}

// HandleReply authenticates all hop replies and installs the outbound circuit.
func (m *BuildManager) HandleReply(message i2np.Message) error {
	if message.Header.Type == i2np.VariableTunnelBuildReply {
		return m.HandleVariableReply(message)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildPending
	}
	if message.Header.Type != i2np.OutboundTunnelBuildReply {
		return ErrBuildConfig
	}
	pending := m.takePending(message.Header.ID)
	if pending == nil {
		return ErrBuildPending
	}
	m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
	defer clearBuildKeys(pending.keys)
	success := false
	peerFailure := false
	defer func() {
		if success {
			return
		}
		if peerFailure {
			m.recordShortBuild(pending.build.Hops, false, 0)
		}
		if m.metrics != nil {
			m.metrics.IncTunnelBuildFailures()
		}
	}()
	records, err := i2np.ParseBuildRecords(message.Header.Type, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	if pending.deadline <= now || records.Count != pending.recordCount {
		return ErrBuildPending
	}
	replies := make([]byte, len(pending.keys)*ShortBuildReplyPlainSize)
	// Outbound replies reach this method only after the one-time garlic reply
	// key authenticated the selected endpoint. A structurally valid response
	// that fails the per-record authenticator is therefore attributable to the
	// endpoint, while errors after records open are local installation errors.
	peerFailure = true
	if err = OpenShortBuildReplies(records.Records, pending.keys, pending.positions, replies); err != nil {
		return err
	}
	peerFailure = false
	for hop := range pending.keys {
		if replies[(hop+1)*ShortBuildReplyPlainSize-1] != 0 {
			peerFailure = true
			return ErrBuildRejected
		}
	}
	transforms := make([]LayerCipher, len(pending.keys))
	for hop := range pending.keys {
		key := pending.keys[len(pending.keys)-1-hop]
		transforms[hop], err = NewLayerDecryptor(key.LayerKey[:], key.IVKey[:])
		if err != nil {
			return err
		}
	}
	owner := foundation.Hash{}
	if m.pool != nil {
		owner = m.pool.Owner()
	}
	circuit := OutboundCircuit{
		ID: pending.build.CircuitID, Owner: owner, FirstHop: pending.build.Hops[0].Router,
		NextTunnelID: pending.build.Hops[0].ReceiveTunnelID, Transforms: transforms,
		ExpiresAt: pending.build.ExpiresAt,
	}
	entry := Entry{ID: circuit.ID, Direction: Outbound, Expires: circuit.ExpiresAt, Owner: owner}
	setEntryHops(&entry, pending.build.Hops)
	var retired Entry
	var replaced bool
	if m.pool != nil {
		retired, replaced, err = m.pool.Replace(entry, pending.build.retireID, now)
		if err != nil {
			return err
		}
	}
	if err = m.runtime.RegisterOutbound(circuit); err != nil {
		if m.pool != nil {
			m.pool.RollbackReplace(entry, retired, replaced, m.now())
		}
		return err
	}
	if replaced {
		m.runtime.RemoveCircuit(retired.ID)
	}
	m.recordShortBuild(pending.build.Hops, true, now-pending.startedAt)
	success = true
	if m.metrics != nil {
		m.metrics.IncTunnelBuildSuccesses()
	}
	if m.logger != nil {
		m.logger.Info("tunnel build reply authenticated", "direction", "outbound", "reply_id", message.Header.ID, "latency_ms", now-pending.startedAt, "hop_count", len(pending.build.Hops))
	}
	return nil
}

func (m *BuildManager) Expire(nowMillis uint64) int {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	m.mu.Lock()
	expired := make([]*pendingOutboundBuild, 0)
	expiredInbound := make([]*pendingInboundBuild, 0)
	expiredVariable := make([]*pendingVariableBuild, 0)
	for id, pending := range m.pending {
		if pending.deadline <= nowMillis {
			delete(m.pending, id)
			expired = append(expired, pending)
		}
	}
	for id, pending := range m.pendingInbound {
		if pending.deadline <= nowMillis {
			delete(m.pendingInbound, id)
			expiredInbound = append(expiredInbound, pending)
		}
	}
	for id, pending := range m.pendingVariable {
		if pending.deadline <= nowMillis {
			delete(m.pendingVariable, id)
			expiredVariable = append(expiredVariable, pending)
		}
	}
	for id, deadline := range m.transit {
		if deadline <= nowMillis {
			delete(m.transit, id)
		}
	}
	for hash, deadline := range m.transitRecords {
		if deadline <= nowMillis {
			delete(m.transitRecords, hash)
		}
	}
	m.mu.Unlock()
	expiredCount := len(expired) + len(expiredInbound) + len(expiredVariable)
	if expiredCount != 0 {
		if m.metrics != nil {
			for range expiredCount {
				m.metrics.IncTunnelBuildFailures()
			}
		}
		if m.logger != nil {
			m.logger.Warn("tunnel build reply timeout", "outbound", len(expired), "inbound", len(expiredInbound), "legacy", len(expiredVariable), "now_ms", nowMillis)
		}
	}
	for _, pending := range expired {
		m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		clearBuildKeys(pending.keys)
		m.recordShortBuild(pending.build.Hops, false, 0)
	}
	for _, pending := range expiredInbound {
		clearBuildKeys(pending.keys)
		m.recordShortBuild(pending.build.Hops, false, 0)
	}
	for _, pending := range expiredVariable {
		clearVariableBuildKeys(pending.keys)
	}
	return len(expired) + len(expiredInbound) + len(expiredVariable)
}

// Pending returns the bounded number of creator builds awaiting replies.
func (m *BuildManager) Pending() int {
	m.mu.Lock()
	count := len(m.pending) + len(m.pendingInbound) + len(m.pendingVariable)
	m.mu.Unlock()
	return count
}

// PendingDirection reports creator builds awaiting replies in one direction.
func (m *BuildManager) PendingDirection(direction Direction) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch direction {
	case Inbound:
		return len(m.pendingInbound)
	case Outbound:
		return len(m.pending) + len(m.pendingVariable)
	default:
		return 0
	}
}

// pendingRetirements reports the renewal candidates reserved by builds that
// still await a reply. Rotator uses it to avoid assigning one old tunnel to
// multiple replacements.
func (m *BuildManager) pendingRetirements() map[uint32]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	reserved := make(map[uint32]struct{}, len(m.pending)+len(m.pendingVariable))
	for _, pending := range m.pending {
		if pending.build.retireID != 0 {
			reserved[pending.build.retireID] = struct{}{}
		}
	}
	for _, pending := range m.pendingVariable {
		if pending.build.retireID != 0 {
			reserved[pending.build.retireID] = struct{}{}
		}
	}
	return reserved
}

func (m *BuildManager) randomPositions(hops, slots int) ([]uint8, error) {
	if hops < 1 || hops > slots || slots > i2np.MaxVariableBuildRecords {
		return nil, ErrBuildConfig
	}
	var shuffled [i2np.MaxVariableBuildRecords]uint8
	for index := range slots {
		shuffled[index] = uint8(index)
	}
	for index := slots - 1; index > 0; index-- {
		value, err := randomUint32(m.random)
		if err != nil {
			return nil, err
		}
		swap := int(value % uint32(index+1))
		shuffled[index], shuffled[swap] = shuffled[swap], shuffled[index]
	}
	positions := make([]uint8, hops)
	copy(positions, shuffled[:hops])
	return positions, nil
}

func (m *BuildManager) uniqueMessageID(existing []uint32) (uint32, error) {
	for range 16 {
		id, err := randomUint32(m.random)
		if err != nil {
			return 0, err
		}
		if id == 0 {
			continue
		}
		unique := !slices.Contains(existing, id)
		if unique {
			return id, nil
		}
	}
	return 0, ErrBuildConfig
}

func randomUint32(random io.Reader) (uint32, error) {
	var wire [4]byte
	if _, err := io.ReadFull(random, wire[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(wire[:]), nil
}

func validShortBuildOptions(options ShortBuildOptions, gateway bool) bool {
	if options.Limit != 0 && !gateway {
		return false
	}
	if options.Minimum != 0 && options.Requested != 0 && options.Minimum > options.Requested {
		return false
	}
	if options.Requested != 0 && options.Limit != 0 && options.Requested > options.Limit {
		return false
	}
	return options.Minimum == 0 || options.Limit == 0 || options.Minimum <= options.Limit
}

func marshalShortBuildOptions(options ShortBuildOptions) ([]byte, error) {
	if options == (ShortBuildOptions{}) {
		return nil, nil
	}
	entries := make([]foundation.MappingEntry, 0, 3)
	if options.Limit != 0 {
		entries = append(entries, foundation.MappingEntry{Key: []byte("l"), Value: []byte(strconv.FormatUint(uint64(options.Limit), 10))})
	}
	if options.Minimum != 0 {
		entries = append(entries, foundation.MappingEntry{Key: []byte("m"), Value: []byte(strconv.FormatUint(uint64(options.Minimum), 10))})
	}
	if options.Requested != 0 {
		entries = append(entries, foundation.MappingEntry{Key: []byte("r"), Value: []byte(strconv.FormatUint(uint64(options.Requested), 10))})
	}
	size, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		return nil, err
	}
	wire := make([]byte, size)
	if _, err = foundation.MarshalMappingTo(wire, entries); err != nil {
		return nil, err
	}
	return wire, nil
}

func parseShortBuildOptions(mapping foundation.Mapping, gateway bool) (ShortBuildOptions, bool) {
	var options ShortBuildOptions
	it := mapping.Iterator()
	for {
		key, value, ok, err := it.Next()
		if err != nil {
			return ShortBuildOptions{}, false
		}
		if !ok {
			break
		}
		var target *uint32
		switch string(key) {
		case "l":
			target = &options.Limit
		case "m":
			target = &options.Minimum
		case "r":
			target = &options.Requested
		default:
			continue
		}
		parsed, err := strconv.ParseUint(string(value), 10, 32)
		if err != nil || parsed == 0 {
			return ShortBuildOptions{}, false
		}
		*target = uint32(parsed)
	}
	return options, validShortBuildOptions(options, gateway)
}

func (m *BuildManager) validHopStaticKey(hop ShortBuildHop) bool {
	if m.staticKeyLookup == nil {
		return true
	}
	identityKey, ok := m.staticKeyLookup(hop.Router)
	return !ok || subtle.ConstantTimeCompare(identityKey[:], hop.StaticKey[:]) == 1
}

func cloneOutboundBuild(build OutboundBuild) OutboundBuild {
	clone := build
	clone.Hops = append([]ShortBuildHop(nil), build.Hops...)
	return clone
}

func cloneInboundBuild(build InboundBuild) InboundBuild {
	clone := build
	clone.Hops = append([]ShortBuildHop(nil), build.Hops...)
	return clone
}

func validateShortBuildHops(hops []ShortBuildHop) error {
	for index, hop := range hops {
		if hop.ReceiveTunnelID == 0 || hop.Router == (foundation.Hash{}) || hop.StaticKey == ([32]byte{}) {
			return ErrBuildConfig
		}
		for previous := range index {
			if hops[previous].Router == hop.Router || hops[previous].ReceiveTunnelID == hop.ReceiveTunnelID {
				return ErrBuildConfig
			}
		}
	}
	return nil
}

func (m *BuildManager) takePending(id uint32) *pendingOutboundBuild {
	m.mu.Lock()
	pending := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()
	return pending
}
func (m *BuildManager) removePending(id uint32) {
	m.mu.Lock()
	pending := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()
	if pending != nil {
		m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		clearBuildKeys(pending.keys)
	}
}

func (m *BuildManager) takeInboundPending(id uint32) *pendingInboundBuild {
	m.mu.Lock()
	pending := m.pendingInbound[id]
	delete(m.pendingInbound, id)
	m.mu.Unlock()
	return pending
}

func (m *BuildManager) removeInboundPending(id uint32) {
	pending := m.takeInboundPending(id)
	if pending != nil {
		clearBuildKeys(pending.keys)
	}
}

func (m *BuildManager) recordShortBuild(hops []ShortBuildHop, success bool, latency uint64) {
	if m.profiles == nil {
		return
	}
	now := m.now()
	for _, hop := range hops {
		m.profiles.Record(hop.Router, Observation{Kind: BuildObservation, Success: success, LatencyMillis: latency, AtMillis: now})
	}
}

func setEntryHops(entry *Entry, hops []ShortBuildHop) {
	entry.HopCount = uint8(min(len(hops), len(entry.Hops)))
	for index := range int(entry.HopCount) {
		entry.Hops[index] = hops[index].Router
	}
}

func clearBuildKeys(keys []ShortBuildKeys) {
	clear(keys)
}

func clearBuildKey(key *ShortBuildKeys) {
	if key != nil {
		*key = ShortBuildKeys{}
	}
}

func buildPeerDiagnostics(hops []ShortBuildHop) []string {
	peers := make([]string, len(hops))
	for index := range hops {
		peers[index] = foundation.EncodeI2PBase64(hops[index].Router[:])
	}
	return peers
}
