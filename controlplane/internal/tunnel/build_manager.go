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
	goruntime "runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/observability"
)

const (
	defaultMaxPendingBuilds   = 32 // default concurrent build limit per destination
	shortBuildPastSkew        = 8 * 60_000
	shortBuildFutureSkew      = 5 * 60_000
	shortBuildReplayLifetime  = 10 * 60_000
	buildMessageLifetime      = 60_000
	nextHopSendTimeout        = 25_000
	buildMessageFuzz          = 20_000
	normalBuildRequestTimeout = 5_000
	slowBuildRequestTimeout   = 10_000
	buildReplyGracePeriod     = 60_000 // Java BuildExecutor.GRACE_PERIOD
)

var (
	ErrBuildConfig     = errors.New("tunnel: invalid build configuration")
	ErrBuildPending    = errors.New("tunnel: build is not pending")
	ErrBuildRejected   = errors.New("tunnel: build rejected")
	ErrBuildTransit    = errors.New("tunnel: invalid transit build")
	ErrBuildFakeRecord = errors.New("tunnel: inbound creator fake record modified")
)

func buildRequestTimeout() uint64 {
	return buildRequestTimeoutForSystem(goruntime.GOOS, goruntime.GOARCH, goruntime.NumCPU())
}

func buildRequestTimeoutForSystem(goos, goarch string, cores int) uint64 {
	slowARM := goarch == "arm" || goarch == "arm64" && goos != "darwin" && cores < 5
	if goos == "android" || slowARM {
		return slowBuildRequestTimeout
	}
	return normalBuildRequestTimeout
}

func saturatingDeadline(now, delay uint64) uint64 {
	if ^uint64(0)-now < delay {
		return ^uint64(0)
	}
	return now + delay
}

// BuildReplyKeyCapacity returns the maximum active and grace-retained reply
// keys one manager can hold under the shortest Java request timeout.
func BuildReplyKeyCapacity(maxPending int) int {
	if maxPending <= 0 {
		maxPending = defaultMaxPendingBuilds
	}
	graceBatches := int((buildReplyGracePeriod + normalBuildRequestTimeout - 1) / normalBuildRequestTimeout)
	factor := graceBatches + 1
	maxInt := int(^uint(0) >> 1)
	if maxPending > maxInt/factor {
		return maxInt
	}
	return maxPending * factor
}

func randomizedBuildMessageDeadline(now uint64, random io.Reader) (uint64, error) {
	fuzz, err := randomUint32(random)
	if err != nil {
		return 0, err
	}
	return saturatingDeadline(now, buildMessageLifetime+uint64(fuzz%buildMessageFuzz)), nil
}

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
	attempt  *creatorAttempt
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
	attempt  *creatorAttempt
}

// BuildReplySender garlic-wraps the OBEP reply using the one-time key
// material derived from its endpoint build record and delivers it through the
// requested inbound tunnel. Implementations own the ECIES existing-session
// packet codec; BuildManager owns neither a garlic session nor packet buffers.
type BuildReplySender interface {
	SendBuildReply(context.Context, foundation.Hash, uint32, dataplane.GarlicReplyKey, foundation.I2NPMessage) error
}

// BuildAdmission decides whether a valid transit request may consume local
// tunnel capacity. It is invoked only after the request is authenticated and
// passes the protocol's time, lifetime, loop, and collision checks.
type BuildAdmission func(ShortBuildRequest) bool

// BuildBandwidth returns the KBps available to an authenticated transit build.
type BuildBandwidth func(ShortBuildRequest) uint32

// BuildStaticKeyLookup returns a retained RouterInfo identity encryption key.
type BuildStaticKeyLookup func(foundation.Hash) ([32]byte, bool)

// RouterInfoSeeder sends a RouterInfo to one tunnel endpoint before traffic
// that depends on the endpoint routing to that router.
type RouterInfoSeeder func(context.Context, foundation.Hash, foundation.Hash) error

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

// BuildScheduleFunc schedules one bounded build-deadline callback and returns
// an idempotent cancellation function. The callback must not run synchronously.
type BuildScheduleFunc func(time.Duration, func()) func()

// BuildManager creates and processes short-record and compatibility variable
// tunnel builds. Active creator and transit replay state is capacity-bounded;
// timed-out creator state is retained for Java's fixed late-reply grace period.
type BuildManager struct {
	runtime          dataplane.TunnelCircuitRuntime
	pool             *Pool
	sender           dataplane.TunnelSender
	replyKeys        dataplane.GarlicReplyKeyRegistryContract
	replySender      BuildReplySender
	local            foundation.Hash
	staticPrivateKey *ecdh.PrivateKey
	legacyPrivate    cryptography.ElGamalPrivateKey
	legacyEnabled    bool
	admit            BuildAdmission
	bandwidth        BuildBandwidth
	staticKeyLookup  BuildStaticKeyLookup
	localDelivery    func(foundation.I2NPMessage) error
	now              func() uint64
	random           io.Reader
	profiles         *PeerProfiles
	maxPending       int
	logger           *slog.Logger
	metrics          *observability.Registry
	onBuildEvent     func()
	schedule         BuildScheduleFunc
	creatorBudget    *CreatorBudget
	stats            *BuildStatistics
	creators         map[*creatorAttempt]struct{}
	claims           map[*creatorClaim]struct{}

	lifecycleMu     sync.RWMutex
	mu              sync.Mutex
	pending         map[uint32]*pendingOutboundBuild
	pendingInbound  map[uint32]*pendingInboundBuild
	pendingVariable map[uint32]*pendingVariableBuild
	recent          map[uint32]recentCreatorBuild
	transit         map[uint32]uint64
	transitRecords  map[[32]byte]uint64
	released        bool
	ctx             context.Context
	cancel          context.CancelFunc
}

type pendingOutboundBuild struct {
	build          OutboundBuild
	keys           []ShortBuildKeys
	positions      []uint8
	replyID        uint32
	replyTag       [8]byte
	recordCount    uint8
	startedAt      uint64
	deadline       uint64
	timedOut       bool
	cancelDeadline func()
}

type pendingInboundBuild struct {
	build          InboundBuild
	keys           []ShortBuildKeys
	positions      []uint8
	replyID        uint32
	recordCount    uint8
	fakePosition   uint8
	fakeHash       [32]byte
	startedAt      uint64
	deadline       uint64
	cancelDeadline func()
}

type pendingVariableBuild struct {
	build          VariableOutboundBuild
	keys           []VariableBuildKeys
	positions      []uint8
	replyID        uint32
	recordCount    uint8
	deadline       uint64
	cancelDeadline func()
}

type recentCreatorBuild struct {
	replyID  uint32
	deadline uint64
	outbound *pendingOutboundBuild
	inbound  *pendingInboundBuild
	variable *pendingVariableBuild
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
	attempt       *creatorAttempt
}

// BuildManagerConfig provides the network handoff and local ECIES or legacy
// ElGamal identity needed by short and compatibility build processing.
type BuildManagerConfig struct {
	Runtime         dataplane.TunnelCircuitRuntime
	Pool            *Pool
	Sender          dataplane.TunnelSender
	ReplyKeys       dataplane.GarlicReplyKeyRegistryContract
	ReplySender     BuildReplySender
	LocalRouter     foundation.Hash
	StaticPrivate   []byte
	LegacyPrivate   []byte
	Admission       BuildAdmission
	Bandwidth       BuildBandwidth
	StaticKeyLookup BuildStaticKeyLookup
	LocalDelivery   func(foundation.I2NPMessage) error
	Now             func() uint64
	Random          io.Reader
	// Profiles receives terminal authenticated build observations. It is
	// optional for compatibility-only runtimes without tunnel selection.
	Profiles   *PeerProfiles
	MaxPending int
	Logger     *slog.Logger
	Metrics    *observability.Registry
	// OnBuildEvent must enqueue maintenance without blocking or reentering build APIs.
	OnBuildEvent func()
	Schedule     BuildScheduleFunc
	// CreatorBudget is shared by router owners; nil gives this manager a private budget.
	CreatorBudget *CreatorBudget
	Stats         *BuildStatistics
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
	if config.Schedule == nil {
		config.Schedule = func(delay time.Duration, callback func()) func() {
			timer := time.AfterFunc(delay, callback)
			return func() { timer.Stop() }
		}
	}
	if config.CreatorBudget == nil {
		config.CreatorBudget = NewCreatorBudget(config.MaxPending, 1)
	}
	if config.Stats == nil {
		config.Stats = NewBuildStatistics()
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
		local:           config.LocalRouter,
		admit:           config.Admission,
		bandwidth:       config.Bandwidth,
		staticKeyLookup: config.StaticKeyLookup,
		localDelivery:   config.LocalDelivery,
		now:             config.Now,
		random:          &synchronizedReader{reader: config.Random},
		profiles:        config.Profiles,
		maxPending:      config.MaxPending, pending: make(map[uint32]*pendingOutboundBuild),
		pendingInbound: make(map[uint32]*pendingInboundBuild), pendingVariable: make(map[uint32]*pendingVariableBuild), recent: make(map[uint32]recentCreatorBuild),
		transit: make(map[uint32]uint64), transitRecords: make(map[[32]byte]uint64), staticPrivateKey: staticPrivateKey,
		logger: config.Logger, metrics: config.Metrics, onBuildEvent: config.OnBuildEvent, schedule: config.Schedule,
		ctx: lifecycle, cancel: cancel,
		creatorBudget: config.CreatorBudget, creators: make(map[*creatorAttempt]struct{}), claims: make(map[*creatorClaim]struct{}),
		stats: config.Stats,
	}
	if !manager.creatorBudget.register(manager) {
		cancel()
		return nil, ErrBuildConfig
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
	for attempt := range m.creators {
		attempt.finishLocked()
	}
	m.creatorBudget.unregister(m)
	clear(m.claims)
	for id, pending := range m.pending {
		if pending.replyTag != ([8]byte{}) {
			m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		}
		clear(pending.keys)
		clear(pending.positions)
		clear(pending.replyTag[:])
		cancelBuildDeadline(pending.cancelDeadline)
		delete(m.pending, id)
	}
	for id, recent := range m.recent {
		recent.finishLocked()
		m.clearRecentCreatorBuild(recent)
		delete(m.recent, id)
	}
	for id, pending := range m.pendingInbound {
		clear(pending.keys)
		clear(pending.positions)
		clear(pending.fakeHash[:])
		cancelBuildDeadline(pending.cancelDeadline)
		delete(m.pendingInbound, id)
	}
	for id, pending := range m.pendingVariable {
		clear(pending.keys)
		clear(pending.positions)
		cancelBuildDeadline(pending.cancelDeadline)
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

func (m *BuildManager) clearRecentCreatorBuild(recent recentCreatorBuild) {
	if pending := recent.outbound; pending != nil {
		if pending.replyTag != ([8]byte{}) {
			m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		}
		clearBuildKeys(pending.keys)
		clear(pending.positions)
		clear(pending.replyTag[:])
		cancelBuildDeadline(pending.cancelDeadline)
		return
	}
	if pending := recent.inbound; pending != nil {
		clearBuildKeys(pending.keys)
		clear(pending.positions)
		clear(pending.fakeHash[:])
		cancelBuildDeadline(pending.cancelDeadline)
		return
	}
	if pending := recent.variable; pending != nil {
		clearVariableBuildKeys(pending.keys)
		clear(pending.positions)
		cancelBuildDeadline(pending.cancelDeadline)
	}
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

func (recent recentCreatorBuild) direction() string {
	if recent.inbound != nil {
		return "inbound"
	}
	if recent.variable != nil {
		return "legacy"
	}
	return "outbound"
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
	if build.attempt == nil {
		var err error
		build.attempt, err = m.acquireCreator(Outbound, build.retireID)
		if err != nil {
			return 0, err
		}
	}
	transferred := false
	defer func() {
		if !transferred {
			build.attempt.failPreparation()
		}
	}()
	startOutboundRejected := build.CircuitID == 0 || len(build.Hops) < 1 || len(build.Hops) > foundation.I2NPMaxVariableBuildRecords || build.ReplyRouter == (foundation.Hash{}) || build.ReplyTunnelID == 0 || build.Hops[len(build.Hops)-1].Router == build.ReplyRouter
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
	if err := m.ensureBuildSession(ctx, build.Hops[0].Router, build.Hops, "outbound", "first_hop"); err != nil {
		return 0, err
	}

	var messageIDStorage [foundation.I2NPMaxVariableBuildRecords + 1]uint32
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
	messageDeadline, err := randomizedBuildMessageDeadline(now, m.random)
	if err != nil {
		clearBuildKeys(keys)
		return 0, err
	}

	replyID := messageIDs[len(messageIDs)-1]
	endpointKeys := keys[len(keys)-1]
	if !endpointKeys.HasGarlicKeys {
		clearBuildKeys(keys)
		return 0, ErrBuildConfig
	}
	pending := &pendingOutboundBuild{
		build: cloneOutboundBuild(build), keys: keys, positions: positions, replyID: replyID, replyTag: endpointKeys.GarlicTag,
		recordCount: uint8(recordCount), startedAt: now, deadline: build.ExpiresAt,
	}
	m.mu.Lock()
	if m.replyIDInUseLocked(replyID) {
		m.mu.Unlock()
		cancelBuildDeadline(pending.cancelDeadline)
		clearBuildKeys(keys)
		return 0, ErrBuildPending
	}
	m.pending[replyID] = pending
	transferred = true
	m.mu.Unlock()
	replyKeyExpiresAt := saturatingDeadline(now, 2*buildMessageLifetime)
	if err = m.replyKeys.RegisterGarlicReplyKey(dataplane.GarlicReplyKey{
		Key: endpointKeys.GarlicKey, Tag: endpointKeys.GarlicTag, ExpiresAt: replyKeyExpiresAt,
	}); err != nil {
		m.removePending(replyID)
		return 0, err
	}

	if m.metrics != nil {
		m.metrics.IncTunnelBuilds()
	}
	if m.logger != nil {
		ownerKind, owner := m.logOwner()
		m.logger.Info("tunnel build reply stage", "stage", "creator_registered", "owner_kind", ownerKind, "owner", owner, "direction", "outbound", "reply_id", replyID, "reply_router", foundation.EncodeI2PBase64(build.ReplyRouter[:]), "reply_tunnel_id", build.ReplyTunnelID, "hop_count", len(build.Hops), "peers", buildPeerDiagnostics(build.Hops))
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: messageIDs[0], Expiration: messageDeadline}, Payload: payload}
	if err = m.sender.Send(ctx, build.Hops[0].Router, message); err != nil {
		m.removePending(replyID)
		if m.stats != nil {
			m.stats.Record(Outbound, false)
		}
		if m.profiles != nil {
			m.profiles.RecordTransportFailure(build.Hops[0].Router, m.now())
		}
		if m.metrics != nil {
			m.metrics.IncTunnelBuildFailures()
		}
		if m.logger != nil {
			ownerKind, owner := m.logOwner()
			m.logger.Warn("tunnel build send failed", "owner_kind", ownerKind, "owner", owner, "direction", "outbound", "reply_id", replyID, "peer", foundation.EncodeI2PBase64(build.Hops[0].Router[:]), "error", err)
		}
		m.scheduleBuildRetry()
		return 0, err
	}
	m.armOutboundDeadline(replyID)
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
	if build.attempt == nil {
		var err error
		build.attempt, err = m.acquireCreator(Inbound, build.retireID)
		if err != nil {
			return 0, err
		}
	}
	transferred := false
	defer func() {
		if !transferred {
			build.attempt.failPreparation()
		}
	}()
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
		startInboundRejected = len(build.Hops) >= foundation.I2NPMaxVariableBuildRecords
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
	var carrier dataplane.TunnelCircuitInfo
	if build.OutboundTunnelID != 0 {
		var exists bool
		carrier, exists = m.runtime.InspectCircuit(build.OutboundTunnelID)
		if !exists {
			return 0, dataplane.TunnelErrCircuitNotFound
		}
		if m.pool != nil && carrier.Owner != m.pool.Owner() {
			return 0, ErrPoolOwner
		}
		if err := m.ensureBuildSession(ctx, carrier.FirstHop, build.Hops, "inbound", "carrier"); err != nil {
			return 0, err
		}
	}
	if build.OutboundTunnelID == 0 {
		if err := m.ensureBootstrapSessions(ctx, build.Hops); err != nil {
			return 0, err
		}
	}
	var messageIDStorage [foundation.I2NPMaxVariableBuildRecords + 1]uint32
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
		startedAt: now, deadline: build.ExpiresAt,
	}
	m.mu.Lock()
	if m.replyIDInUseLocked(replyID) {
		m.mu.Unlock()
		cancelBuildDeadline(pending.cancelDeadline)
		clearBuildKeys(keys)
		return 0, ErrBuildPending
	}
	m.pendingInbound[replyID] = pending
	transferred = true
	m.mu.Unlock()
	if m.metrics != nil {
		m.metrics.IncTunnelBuilds()
	}
	if m.logger != nil {
		ownerKind, owner := m.logOwner()
		m.logger.Info("tunnel build send", "owner_kind", ownerKind, "owner", owner, "direction", "inbound", "reply_id", replyID, "hop_count", len(build.Hops), "peers", buildPeerDiagnostics(build.Hops), "carrier_tunnel_id", build.OutboundTunnelID)
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: messageIDs[0], Expiration: now + buildMessageLifetime}, Payload: payload}
	if build.OutboundTunnelID == 0 {
		if err = m.sender.Send(ctx, build.Hops[0].Router, message); err != nil {
			m.removeInboundPending(replyID)
			if m.stats != nil {
				m.stats.Record(Inbound, false)
			}
			if m.profiles != nil {
				m.profiles.RecordTransportFailure(build.Hops[0].Router, m.now())
			}
			if m.metrics != nil {
				m.metrics.IncTunnelBuildFailures()
			}
			if m.logger != nil {
				ownerKind, owner := m.logOwner()
				m.logger.Warn("tunnel build send failed", "owner_kind", ownerKind, "owner", owner, "direction", "inbound", "reply_id", replyID, "peer", foundation.EncodeI2PBase64(build.Hops[0].Router[:]), "error", err)
			}
			m.scheduleBuildRetry()
			return 0, err
		}
		m.armInboundDeadline(replyID)
		return replyID, nil
	}
	frameMessage := message
	if carrierEndpoint != build.Hops[0].Router {
		encrypted := make([]byte, 32+7+3+10+message.EncodedLen()+16)
		sealed, wrapErr := dataplane.GarlicECIESSealRouterMessage(encrypted, build.Hops[0].StaticKey[:], message, now, m.random)
		if wrapErr != nil {
			m.removeInboundPending(replyID)
			return 0, wrapErr
		}
		garlicPayload := make([]byte, 4+len(sealed))
		binary.BigEndian.PutUint32(garlicPayload[:4], uint32(len(sealed)))
		copy(garlicPayload[4:], sealed)
		frameMessage = foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: messageIDs[0] ^ replyID, Expiration: now + buildMessageLifetime}, Payload: garlicPayload}
	}
	frame := make([]byte, frameMessage.EncodedLen())
	if _, err = frameMessage.MarshalTo(frame); err != nil {
		m.removeInboundPending(replyID)
		return 0, err
	}
	if err = m.runtime.SendBlockPrepared(ctx, carrier.Token, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryRouter, Gateway: build.Hops[0].Router, Last: true, Data: frame}); err != nil {
		m.removeInboundPending(replyID)
		if m.stats != nil {
			m.stats.Record(Inbound, false)
		}
		m.scheduleBuildRetry()
		return 0, err
	}
	if m.logger != nil {
		m.logger.Debug("tunnel build sent", "direction", "inbound", "reply_id", replyID, "phase", "outbound_carrier")
	}
	m.armInboundDeadline(replyID)
	return replyID, nil
}

// HandleInboundReply claims only a creator-side inbound short-build reply.
// ErrBuildPending means this manager does not own the reply ID; callers may
// safely continue to another destination manager or transit handling.
func (m *BuildManager) HandleInboundReply(message foundation.I2NPMessage) error {
	if m == nil {
		return ErrBuildPending
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildPending
	}
	if message.Header.Type != foundation.I2NPShortTunnelBuild || !m.hasInboundPending(message.Header.ID) {
		return ErrBuildPending
	}
	return m.handleInboundReply(message)
}

// SessionEnsurer ensures an authenticated session with a peer router.
type SessionEnsurer interface {
	EnsureSession(context.Context, foundation.Hash) error
}

// HandleBuildContext processes a creator reply or an authenticated transit
// request. A zero BuildSource denotes delivery through a local tunnel.
func (m *BuildManager) HandleBuildContext(ctx context.Context, source BuildSource, message foundation.I2NPMessage) error {
	if m == nil {
		return ErrBuildConfig
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildConfig
	}
	switch message.Header.Type {
	case foundation.I2NPShortTunnelBuild:
		if m.hasInboundPending(message.Header.ID) {
			return m.handleInboundReply(message)
		}
		return m.handleTransit(ctx, source, message)
	case foundation.I2NPVariableTunnelBuild:
		return m.handleVariableTransit(ctx, message)
	default:
		return ErrBuildConfig
	}
}

func (m *BuildManager) handleInboundReply(message foundation.I2NPMessage) error {
	pending := m.takeInboundPending(message.Header.ID)
	if pending == nil {
		return ErrBuildPending
	}
	defer m.notifyBuildEvent()
	defer pending.build.attempt.finish()
	success := false
	defer func() {
		if !success {
			if m.stats != nil {
				m.stats.Record(Inbound, false)
			}
			if m.metrics != nil {
				m.metrics.IncTunnelBuildFailures()
			}
		}
	}()
	defer clearBuildKeys(pending.keys)
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, message.Payload)
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
			m.recordBuildPeer(pending.build.Hops[hop].Router, false, 0, now)
			return ErrBuildRejected
		}
	}
	transforms := make([]dataplane.TunnelLayerCipher, len(pending.keys))
	for hop := range pending.keys {
		key := pending.keys[len(pending.keys)-1-hop]
		transforms[hop], err = dataplane.TunnelNewLayerDecryptor(key.LayerKey[:], key.IVKey[:])
		if err != nil {
			return err
		}
	}
	owner := foundation.Hash{}
	if m.pool != nil {
		owner = m.pool.Owner()
	}
	circuit := dataplane.TunnelInboundCircuit{ID: pending.build.CircuitID, Owner: owner, Transforms: transforms, Endpoint: dataplane.TunnelNewEndpoint(128, 0), Local: m.localDelivery, ExpiresAt: pending.build.ExpiresAt}
	entry := Entry{
		ID: circuit.ID, Direction: Inbound, Expires: circuit.ExpiresAt, Owner: owner,
		Gateway: pending.build.Hops[0].Router, GatewayTunnelID: pending.build.Hops[0].ReceiveTunnelID,
	}
	setEntryHops(&entry, pending.build.Hops)
	entry.Circuit, err = m.runtime.RegisterInbound(circuit)
	if err != nil {
		return err
	}
	if m.pool != nil {
		_, _, poolErr := m.installCreatorEntry(entry, pending.build.attempt, pending.build.retireID, now)
		if poolErr != nil {
			m.runtime.RemoveCircuit(entry.Circuit)
			return poolErr
		}
	}
	m.recordBuildSuccess(Inbound, pending.build.Hops, now-pending.startedAt)
	success = true
	if m.metrics != nil {
		m.metrics.IncTunnelBuildSuccesses()
		m.metrics.IncTunnelBuildSuccess(m.metricOwner(), observability.TunnelDirectionInbound)
	}
	if m.logger != nil {
		ownerKind, owner := m.logOwner()
		m.logger.Info("tunnel build reply authenticated", "owner_kind", ownerKind, "owner", owner, "direction", "inbound", "reply_id", message.Header.ID, "latency_ms", now-pending.startedAt, "hop_count", len(pending.build.Hops))
	}
	return nil
}

func (m *BuildManager) hasInboundPending(id uint32) bool {
	m.mu.Lock()
	_, active := m.pendingInbound[id]
	recent, late := m.recent[id]
	m.mu.Unlock()
	return active || late && recent.inbound != nil
}

func (m *BuildManager) handleTransit(ctx context.Context, source BuildSource, message foundation.I2NPMessage) (result error) {
	if m.local == (foundation.Hash{}) || m.staticPrivateKey == nil {
		return ErrBuildConfig
	}
	records, err := foundation.I2NPParseBuildRecords(foundation.I2NPShortTunnelBuild, message.Payload)
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
	if _, exists := m.runtime.InspectCircuit(request.ReceiveTunnelID); exists {
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
	var installed dataplane.TunnelCircuitToken
	defer func() {
		if result != nil {
			m.runtime.RemoveCircuit(installed)
		}
	}()
	if accept {
		installed, err = m.installTransitCircuit(request, keys, now)
		accept = err == nil
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
			return ErrBuildRejected
		}
		reply := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: request.NextMessageID, Expiration: saturatingDeadline(now, nextHopSendTimeout)}, Payload: message.Payload}
		key := dataplane.GarlicReplyKey{Key: keys.GarlicKey, Tag: keys.GarlicTag, ExpiresAt: saturatingDeadline(now, nextHopSendTimeout)}
		if err = m.replySender.SendBuildReply(ctx, request.NextRouter, request.NextTunnelID, key, reply); err != nil {
			return err
		}
		if !accept {
			return ErrBuildRejected
		}
		return nil
	}
	forward := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: request.NextMessageID, Expiration: saturatingDeadline(now, nextHopSendTimeout)}, Payload: message.Payload}
	if err = m.sender.Send(ctx, request.NextRouter, forward); err != nil {
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

func (m *BuildManager) installTransitCircuit(request ShortBuildRequest, keys ShortBuildKeys, now uint64) (dataplane.TunnelCircuitToken, error) {
	expiresAt := now + uint64(request.LifetimeSeconds)*1_000
	if expiresAt < now {
		return dataplane.TunnelCircuitToken{}, ErrBuildTransit
	}
	if request.Gateway {
		encryptor, err := dataplane.TunnelNewLayerEncryptor(keys.LayerKey[:], keys.IVKey[:])
		if err != nil {
			return dataplane.TunnelCircuitToken{}, err
		}
		return m.runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{
			ID: request.ReceiveTunnelID, FirstHop: request.NextRouter, NextTunnelID: request.NextTunnelID,
			Transforms: []dataplane.TunnelLayerCipher{encryptor}, ExpiresAt: expiresAt,
		})
	}
	encryptor, err := dataplane.TunnelNewLayerEncryptor(keys.LayerKey[:], keys.IVKey[:])
	if err != nil {
		return dataplane.TunnelCircuitToken{}, err
	}
	circuit := dataplane.TunnelInboundCircuit{ID: request.ReceiveTunnelID, Transforms: []dataplane.TunnelLayerCipher{encryptor}, ExpiresAt: expiresAt}
	if request.Endpoint {
		// OBEP terminates the outbound tunnel and delivers decrypted blocks.
		circuit.Endpoint = dataplane.TunnelNewEndpoint(128, 0)
		circuit.Local = m.localDelivery
	} else {
		// Intermediate hops peel one layer and forward.
		circuit.Forward = &dataplane.TunnelForward{Peer: request.NextRouter, TunnelID: request.NextTunnelID}
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
func (m *BuildManager) HandleReply(message foundation.I2NPMessage) error {
	if message.Header.Type == foundation.I2NPVariableTunnelBuildReply {
		return m.HandleVariableReply(message)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.isReleased() {
		return ErrBuildPending
	}
	if message.Header.Type != foundation.I2NPOutboundTunnelBuildReply {
		return ErrBuildConfig
	}
	pending := m.takePending(message.Header.ID)
	if pending == nil {
		return ErrBuildPending
	}
	if m.logger != nil {
		ownerKind, owner := m.logOwner()
		m.logger.Info("tunnel build reply stage", "stage", "creator_received", "owner_kind", ownerKind, "owner", owner, "direction", "outbound", "reply_id", message.Header.ID, "late", pending.timedOut)
	}
	defer m.notifyBuildEvent()
	defer pending.build.attempt.finish()
	m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
	defer clearBuildKeys(pending.keys)
	success := false
	defer func() {
		if !success {
			if m.stats != nil {
				m.stats.Record(Outbound, false)
			}
			if m.metrics != nil {
				m.metrics.IncTunnelBuildFailures()
			}
		}
	}()
	records, err := foundation.I2NPParseBuildRecords(message.Header.Type, message.Payload)
	if err != nil {
		return err
	}
	now := m.now()
	if pending.deadline <= now || records.Count != pending.recordCount {
		return ErrBuildPending
	}
	replies := make([]byte, len(pending.keys)*ShortBuildReplyPlainSize)
	defer clear(replies)
	if err = OpenShortBuildReplies(records.Records, pending.keys, pending.positions, replies); err != nil {
		return err
	}
	for hop := range pending.keys {
		if replies[(hop+1)*ShortBuildReplyPlainSize-1] != 0 {
			m.recordBuildPeer(pending.build.Hops[hop].Router, false, 0, now)
			return ErrBuildRejected
		}
	}
	transforms := make([]dataplane.TunnelLayerCipher, len(pending.keys))
	for hop := range pending.keys {
		key := pending.keys[len(pending.keys)-1-hop]
		transforms[hop], err = dataplane.TunnelNewLayerDecryptor(key.LayerKey[:], key.IVKey[:])
		if err != nil {
			return err
		}
	}
	owner := foundation.Hash{}
	if m.pool != nil {
		owner = m.pool.Owner()
	}
	circuit := dataplane.TunnelOutboundCircuit{
		ID: pending.build.CircuitID, Owner: owner, FirstHop: pending.build.Hops[0].Router,
		NextTunnelID: pending.build.Hops[0].ReceiveTunnelID, Transforms: transforms,
		ExpiresAt: pending.build.ExpiresAt,
	}
	entry := Entry{ID: circuit.ID, Direction: Outbound, Expires: circuit.ExpiresAt, Owner: owner}
	setEntryHops(&entry, pending.build.Hops)
	entry.Circuit, err = m.runtime.RegisterOutbound(circuit)
	if err != nil {
		return err
	}
	if m.pool != nil {
		_, _, poolErr := m.installCreatorEntry(entry, pending.build.attempt, pending.build.retireID, now)
		if poolErr != nil {
			m.runtime.RemoveCircuit(entry.Circuit)
			return poolErr
		}
	}
	m.recordBuildSuccess(Outbound, pending.build.Hops, now-pending.startedAt)
	success = true
	if m.metrics != nil {
		m.metrics.IncTunnelBuildSuccesses()
		m.metrics.IncTunnelBuildSuccess(m.metricOwner(), observability.TunnelDirectionOutbound)
	}
	if m.logger != nil {
		ownerKind, owner := m.logOwner()
		m.logger.Info("tunnel build reply stage", "stage", "creator_authenticated", "owner_kind", ownerKind, "owner", owner, "direction", "outbound", "reply_id", message.Header.ID, "late", pending.timedOut, "latency_ms", now-pending.startedAt, "hop_count", len(pending.build.Hops))
	}
	return nil
}

func (m *BuildManager) Expire(nowMillis uint64) int {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	m.mu.Lock()
	for claim := range m.claims {
		if claim.done && claim.retire.Expires <= nowMillis {
			delete(m.claims, claim)
		}
	}
	expiredOutbound := make([]*pendingOutboundBuild, 0)
	expiredInbound := make([]*pendingInboundBuild, 0)
	expiredVariable := make([]*pendingVariableBuild, 0)
	expiredRecent := make([]recentCreatorBuild, 0)
	for id, recent := range m.recent {
		if recent.deadline <= nowMillis {
			delete(m.recent, id)
			recent.finishLocked()
			expiredRecent = append(expiredRecent, recent)
		}
	}
	for id, pending := range m.pending {
		if pending.deadline <= nowMillis {
			delete(m.pending, id)
			pending.build.attempt.timeoutLocked()
			pending.timedOut = true
			graceDeadline := saturatingDeadline(pending.deadline, buildReplyGracePeriod)
			pending.deadline = graceDeadline
			cancelBuildDeadline(pending.cancelDeadline)
			recent := recentCreatorBuild{replyID: id, deadline: graceDeadline, outbound: pending}
			if graceDeadline <= nowMillis {
				recent.finishLocked()
				expiredRecent = append(expiredRecent, recent)
			} else {
				pending.cancelDeadline = m.scheduleBuildDeadline(nowMillis, graceDeadline)
				m.recent[id] = recent
			}
			expiredOutbound = append(expiredOutbound, pending)
		}
	}
	for id, pending := range m.pendingInbound {
		if pending.deadline <= nowMillis {
			delete(m.pendingInbound, id)
			pending.build.attempt.timeoutLocked()
			graceDeadline := saturatingDeadline(pending.deadline, buildReplyGracePeriod)
			pending.deadline = graceDeadline
			cancelBuildDeadline(pending.cancelDeadline)
			recent := recentCreatorBuild{replyID: id, deadline: graceDeadline, inbound: pending}
			if graceDeadline <= nowMillis {
				recent.finishLocked()
				expiredRecent = append(expiredRecent, recent)
			} else {
				pending.cancelDeadline = m.scheduleBuildDeadline(nowMillis, graceDeadline)
				m.recent[id] = recent
			}
			expiredInbound = append(expiredInbound, pending)
		}
	}
	for id, pending := range m.pendingVariable {
		if pending.deadline <= nowMillis {
			delete(m.pendingVariable, id)
			pending.build.attempt.timeoutLocked()
			graceDeadline := saturatingDeadline(pending.deadline, buildReplyGracePeriod)
			pending.deadline = graceDeadline
			cancelBuildDeadline(pending.cancelDeadline)
			recent := recentCreatorBuild{replyID: id, deadline: graceDeadline, variable: pending}
			if graceDeadline <= nowMillis {
				recent.finishLocked()
				expiredRecent = append(expiredRecent, recent)
			} else {
				pending.cancelDeadline = m.scheduleBuildDeadline(nowMillis, graceDeadline)
				m.recent[id] = recent
			}
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

	expiredCount := len(expiredOutbound) + len(expiredInbound) + len(expiredVariable)
	if expiredCount != 0 {
		if m.stats != nil {
			for range len(expiredOutbound) + len(expiredVariable) {
				m.stats.Record(Outbound, false)
			}
			for range len(expiredInbound) {
				m.stats.Record(Inbound, false)
			}
		}
		if m.metrics != nil {
			for range expiredCount {
				m.metrics.IncTunnelBuildFailures()
			}
			m.metrics.AddTunnelBuildTimeouts(m.metricOwner(), observability.TunnelDirectionOutbound, uint64(len(expiredOutbound)+len(expiredVariable)))
			m.metrics.AddTunnelBuildTimeouts(m.metricOwner(), observability.TunnelDirectionInbound, uint64(len(expiredInbound)))
		}
		if m.logger != nil {
			ownerKind, owner := m.logOwner()
			m.logger.Warn("tunnel build reply timeout", "owner_kind", ownerKind, "owner", owner, "outbound", len(expiredOutbound), "inbound", len(expiredInbound), "legacy", len(expiredVariable), "now_ms", nowMillis)
			for _, pending := range expiredOutbound {
				m.logger.Warn("tunnel build reply stage", "stage", "creator_timeout", "owner_kind", ownerKind, "owner", owner, "direction", "outbound", "reply_id", pending.replyID, "reply_router", foundation.EncodeI2PBase64(pending.build.ReplyRouter[:]), "reply_tunnel_id", pending.build.ReplyTunnelID)
			}
		}
	}
	for _, pending := range expiredOutbound {
		for _, hop := range pending.build.Hops {
			m.recordBuildPeer(hop.Router, false, 0, nowMillis)
		}
	}
	for _, pending := range expiredInbound {
		for _, hop := range pending.build.Hops {
			m.recordBuildPeer(hop.Router, false, 0, nowMillis)
		}
	}
	for _, pending := range expiredVariable {
		for _, hop := range pending.build.Hops {
			m.recordBuildPeer(hop.Router, false, 0, nowMillis)
		}
	}
	for _, recent := range expiredRecent {
		m.clearRecentCreatorBuild(recent)
		if m.logger != nil {
			ownerKind, owner := m.logOwner()
			m.logger.Warn("tunnel build reply stage", "stage", "creator_grace_expired", "owner_kind", ownerKind, "owner", owner, "direction", recent.direction(), "reply_id", recent.replyID)
		}
	}
	if expiredCount != 0 {
		m.scheduleBuildRetry()
	}
	return expiredCount
}

// Pending counts creators preparing requests or awaiting replies, excluding grace.
func (m *BuildManager) Pending() int {
	m.mu.Lock()
	count := m.pendingDirectionLocked(Inbound) + m.pendingDirectionLocked(Outbound)
	m.mu.Unlock()
	return count
}

// PendingDirection includes preflight and cryptographic preparation.
func (m *BuildManager) PendingDirection(direction Direction) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingDirectionLocked(direction)
}

func (m *BuildManager) pendingDirectionLocked(direction Direction) int {
	count := 0
	for attempt := range m.creators {
		if attempt.direction == direction {
			count++
		}
	}
	if direction == Inbound {
		for _, pending := range m.pendingInbound {
			if pending.build.attempt == nil {
				count++
			}
		}
	}
	if direction == Outbound {
		for _, pending := range m.pending {
			if pending.build.attempt == nil {
				count++
			}
		}
		for _, pending := range m.pendingVariable {
			if pending.build.attempt == nil {
				count++
			}
		}
	}
	return count
}

func (m *BuildManager) randomPositions(hops, slots int) ([]uint8, error) {
	if hops < 1 || hops > slots || slots > foundation.I2NPMaxVariableBuildRecords {
		return nil, ErrBuildConfig
	}
	var shuffled [foundation.I2NPMaxVariableBuildRecords]uint8
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

func (m *BuildManager) replyIDInUseLocked(id uint32) bool {
	if m.pending[id] != nil || m.pendingInbound[id] != nil || m.pendingVariable[id] != nil {
		return true
	}
	_, recent := m.recent[id]
	return recent
}

func (m *BuildManager) takePending(id uint32) *pendingOutboundBuild {
	m.mu.Lock()
	pending := m.pending[id]
	delete(m.pending, id)
	if pending == nil {
		if recent, ok := m.recent[id]; ok && recent.outbound != nil {
			pending = recent.outbound
			delete(m.recent, id)
		}
	}
	m.mu.Unlock()
	if pending != nil {
		cancelBuildDeadline(pending.cancelDeadline)
	}
	return pending
}
func (m *BuildManager) removePending(id uint32) {
	pending := m.takePending(id)
	if pending != nil {
		pending.build.attempt.failPreparation()
		m.replyKeys.RemoveGarlicReplyKey(pending.replyTag)
		clearBuildKeys(pending.keys)
	}
}

func (m *BuildManager) takeInboundPending(id uint32) *pendingInboundBuild {
	m.mu.Lock()
	pending := m.pendingInbound[id]
	delete(m.pendingInbound, id)
	if pending == nil {
		if recent, ok := m.recent[id]; ok && recent.inbound != nil {
			pending = recent.inbound
			delete(m.recent, id)
		}
	}
	m.mu.Unlock()
	if pending != nil {
		cancelBuildDeadline(pending.cancelDeadline)
	}
	return pending
}

func (m *BuildManager) removeInboundPending(id uint32) {
	pending := m.takeInboundPending(id)
	if pending != nil {
		pending.build.attempt.failPreparation()
		clearBuildKeys(pending.keys)
	}
}

func (m *BuildManager) recordBuildSuccess(direction Direction, hops []ShortBuildHop, latency uint64) {
	if m.stats != nil {
		m.stats.Record(direction, true)
	}
	if m.profiles == nil {
		return
	}
	now := m.now()
	for _, hop := range hops {
		m.recordBuildPeer(hop.Router, true, latency, now)
	}
}

// Statistics reports the atomic tunnel build statistics tracker.
func (m *BuildManager) Statistics() *BuildStatistics {
	if m == nil {
		return nil
	}
	return m.stats
}

// ParallelLimit calculates how many parallel builds to attempt given the needed
// deficit, taking into account empirical success rate and bounded by maxPending.
func (m *BuildManager) ParallelLimit(direction Direction, needed int) int {
	if m == nil {
		return needed
	}
	if m.stats == nil {
		if needed > m.maxPending {
			return m.maxPending
		}
		return needed
	}
	return m.stats.ParallelLimit(direction, needed, m.maxPending)
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

func (m *BuildManager) metricOwner() observability.TunnelOwner {
	if m.pool != nil && m.pool.Owner() != (foundation.Hash{}) {
		return observability.TunnelOwnerClient
	}
	return observability.TunnelOwnerExploratory
}

func (m *BuildManager) logOwner() (string, string) {
	if m.pool == nil {
		return "exploratory", "exploratory"
	}
	owner := m.pool.Owner()
	if owner == (foundation.Hash{}) {
		return "exploratory", "exploratory"
	}
	return "client", foundation.EncodeI2PBase64(owner[:])
}

func (m *BuildManager) ensureBuildSession(ctx context.Context, peer foundation.Hash, hops []ShortBuildHop, direction, role string) error {
	ensurer, ok := m.sender.(SessionEnsurer)
	if !ok {
		return nil
	}
	if err := ensurer.EnsureSession(ctx, peer); err != nil {
		if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return err
		}
		if m.profiles != nil {
			m.profiles.RecordTransportFailure(peer, m.now())
		}
		if m.logger != nil {
			ownerKind, owner := m.logOwner()
			m.logger.Warn("tunnel build session failed", "owner_kind", ownerKind, "owner", owner, "direction", direction, "role", role, "peer", foundation.EncodeI2PBase64(peer[:]), "error", err)
		}
		m.scheduleBuildRetry()
		return err
	}
	if m.profiles != nil {
		m.profiles.RecordTransportSuccess(peer, m.now())
	}
	return nil
}

func (m *BuildManager) ensureBootstrapSessions(ctx context.Context, hops []ShortBuildHop) error {
	first, last := hops[0].Router, hops[len(hops)-1].Router
	if first == last {
		return m.ensureBuildSession(ctx, first, hops, "inbound", "first_hop")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- m.ensureBuildSession(ctx, first, hops, "inbound", "first_hop") }()
	go func() { results <- m.ensureBuildSession(ctx, last, hops, "inbound", "reply_hop") }()
	firstErr := <-results
	if firstErr != nil {
		cancel()
	}
	secondErr := <-results
	if firstErr != nil && errors.Is(secondErr, context.Canceled) {
		return firstErr
	}
	return errors.Join(firstErr, secondErr)
}

func (m *BuildManager) recordBuildPeer(peer foundation.Hash, success bool, latency, now uint64) {
	if m.profiles == nil {
		return
	}
	m.profiles.Record(peer, Observation{Kind: BuildObservation, Success: success, LatencyMillis: latency, AtMillis: now})
}

func buildPeerDiagnostics(hops []ShortBuildHop) []string {
	peers := make([]string, len(hops))
	for index := range hops {
		peers[index] = foundation.EncodeI2PBase64(hops[index].Router[:])
	}
	return peers
}

func (m *BuildManager) armOutboundDeadline(replyID uint32) {
	now := m.now()
	m.mu.Lock()
	pending := m.pending[replyID]
	if pending != nil {
		pending.deadline = min(pending.build.ExpiresAt, saturatingDeadline(now, buildRequestTimeout()))
		pending.cancelDeadline = m.scheduleBuildDeadline(now, pending.deadline)
	}
	m.mu.Unlock()
}

func (m *BuildManager) armInboundDeadline(replyID uint32) {
	now := m.now()
	m.mu.Lock()
	pending := m.pendingInbound[replyID]
	if pending != nil {
		pending.deadline = min(pending.build.ExpiresAt, saturatingDeadline(now, buildRequestTimeout()))
		pending.cancelDeadline = m.scheduleBuildDeadline(now, pending.deadline)
	}
	m.mu.Unlock()
}

func (m *BuildManager) scheduleBuildDeadline(now, deadline uint64) func() {
	delay := time.Duration(0)
	if deadline > now {
		delay = time.Duration(deadline-now) * time.Millisecond
	}
	return m.schedule(delay, func() {
		m.Expire(m.now())
	})
}

func (m *BuildManager) scheduleBuildRetry() {
	if m.ctx == nil || m.ctx.Err() == nil {
		m.notifyBuildEvent()
	}
}

func (m *BuildManager) notifyBuildEvent() {
	if m != nil && m.onBuildEvent != nil {
		m.onBuildEvent()
	}
}

func cancelBuildDeadline(cancel func()) {
	if cancel != nil {
		cancel()
	}
}
