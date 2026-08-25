package router

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/ingress"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/networking/internal/transport/ssu2"
	"gosuda.org/ivnp/observability"
)

const (
	defaultSSU2NetworkID        = 2
	defaultSSU2HandshakeTimeout = 30 * time.Second
	defaultSSU2MaxSessions      = 256
	defaultSSU2MaxPending       = 64
	defaultSSU2MaxClockSkew     = 2 * time.Minute
	defaultSSU2TokenLifetime    = 10 * time.Minute
	ssu2RetransmitInterval      = 500 * time.Millisecond
	ssu2MaxRetransmits          = 5
	ssu2MaxTrackedPackets       = 256
	ssu2DefaultIdleTimeout      = 10 * time.Minute
	ssu2MaxFragmentedMessages   = 64
	ssu2FragmentLifetime        = 30 * time.Second

	ssu2ReceiveBatchCount = 4
	ssu2ReceiveBatchSize  = 32
	ssu2DispatchQueueSize = 64
	ssu2EgressSlots       = 32
	ssu2EgressMinTarget   = 16
	ssu2EgressFlush       = time.Millisecond
	ssu2MaxNewTokens      = 1024
	ssu2RelayTarget       = 3
	ssu2RelayPublishMin   = 100 * time.Millisecond
	ssu2RelayPublishMax   = 30 * time.Second
)

var (
	ErrSSU2ManagerConfig = errors.New("router: invalid SSU2 manager configuration")
	ErrSSU2Peer          = errors.New("router: invalid SSU2 peer RouterInfo")
	ErrSSU2Session       = errors.New("router: SSU2 session unavailable")
	ErrSSU2Introduction  = errors.New("router: SSU2 introduction unavailable")
)

// PeerTestOutcome is the protocol result for one address family. Symmetric
// NAT is published as firewalled because it still requires introducers.
type PeerTestOutcome uint8

const (
	PeerTestUnknown PeerTestOutcome = iota
	PeerTestOK
	PeerTestFirewalled
	PeerTestSymmetricNAT
)

// PeerTestResult records a completed, authenticated Peer Test evaluation.
type PeerTestResult struct {
	Nonce      uint32
	Outcome    PeerTestOutcome
	Diagnostic string
}

// SSU2ManagerConfig contains the private static X25519 key and public SSU2
// introduction key advertised in the local RouterInfo's SSU/SSU2 address.
type SSU2ManagerConfig struct {
	Database         *netdb.Database
	StaticPrivate    []byte
	IntroKey         []byte
	NetworkID        uint8
	HandshakeTimeout time.Duration
	MaxClockSkew     time.Duration
	TokenLifetime    time.Duration
	IdleTimeout      time.Duration
	MaxSessions      int
	MaxPending       int
	OnPeerTest       func(ssu2.PeerTestBlock, net.Addr)
	// OnPeerTestResult observes a completed authenticated Peer Test outcome.
	// LocalInfo is updated and signed before this callback is invoked.
	OnPeerTestResult func(PeerTestResult)
	PanicReporter    ingress.Reporter
	Metrics          *observability.Registry
	Logger           *slog.Logger
	// SignControl signs SSU2 relay control inputs. It is required when
	// LocalInfo does not expose the concrete local signing owner.
	SignControl func([]byte) ([]byte, error)
	// IntroductionEndpoint returns the observed or configured external UDP
	// endpoint used in Relay Responses and Requests for firewalled routers.
	IntroductionEndpoint func() (netip.AddrPort, error)
}

// SSU2Manager is the native UDP SSU2 transport manager. It performs the
// address-validation retry exchange, Noise XK setup, fragmented Session
// Confirmed reassembly, RouterInfo/static-key binding validation, and delivery
// of complete SSU2 I2NP blocks to Router's transport callback.
type SSU2Manager struct {
	database             *netdb.Database
	staticPrivate        []byte
	introKey             []byte
	tokenSecret          [sha256.Size]byte
	networkID            uint8
	timeout              time.Duration
	maxClockSkew         time.Duration
	tokenLifetime        time.Duration
	idleTimeout          time.Duration
	maxSessions          int
	maxPending           int
	onPeerTest           func(ssu2.PeerTestBlock, net.Addr)
	onPeerTestResult     func(PeerTestResult)
	signControl          func([]byte) ([]byte, error)
	introductionEndpoint func() (netip.AddrPort, error)
	limiter              rateLimiter
	mu                   sync.RWMutex
	started              bool
	conn                 *net.UDPConn
	batchConn            *ssu2.UDPBatchConn
	bindings             TransportBindings
	ctx                  context.Context
	cancel               context.CancelFunc
	err                  error
	done                 chan struct{}
	close                sync.Once
	wg                   sync.WaitGroup

	receiveFree    chan *ssu2ReceiveBatch
	authQueue      chan ssu2ReceiveJob
	dispatchQueues []chan *ssu2DispatchBatch
	dispatchFree   chan *ssu2DispatchBatch
	egressFree     chan *ssu2EgressSlot
	egressQueue    chan *ssu2EgressSlot
	ioStats        ssu2IOStats
	metrics        *observability.Registry
	logger         *slog.Logger
	kernelDrops    atomic.Uint64

	sessionsByPeer      map[foundation.Hash]*ssu2TransportSession
	sessionsByID        map[uint64]*ssu2TransportSession
	outbound            map[foundation.Hash]*ssu2OutboundPending
	outboundAddr        map[netip.AddrPort]*ssu2OutboundPending
	inbound             map[uint64]*ssu2InboundPending
	introducers         map[uint32]foundation.Hash
	relayGrants         map[foundation.Hash]ssu2RelayTagLease
	advertisedRelays    map[foundation.Hash]ssu2RelayTagLease
	relayTagPending     map[foundation.Hash]time.Time
	relayPublish        chan struct{}
	relayRevision       uint64
	publishedRevision   uint64
	relayPublishMu      sync.Mutex
	newTokens           map[string]ssu2NewTokenLease
	peerTests           map[uint32]*ssu2PeerTestState
	symmetricEvidence   map[string]ssu2PeerTestEvidence
	relayRequests       map[uint32]*ssu2RelayRequest
	relayForwards       map[uint32]ssu2RelayForward
	deferredRelayIntros map[uint32]ssu2DeferredRelayIntro
	relayStoreJobs      chan ssu2RelayStoreJob
	routerInfoStoresMu  sync.RWMutex
	routerInfoStores    map[foundation.Hash]ssu2RouterInfoStoreSnapshot
	reporter            ingress.Reporter
}

// IOStats is the single atomic source for SSU2 socket accounting.
type IOStats struct {
	DatagramsReceived uint64
	DatagramsSent     uint64
	BytesReceived     uint64
	BytesSent         uint64
	Dropped           uint64
}

type ssu2IOStats struct {
	datagramsReceived atomic.Uint64
	datagramsSent     atomic.Uint64
	bytesReceived     atomic.Uint64
	bytesSent         atomic.Uint64
	dropped           atomic.Uint64
}

func (s *ssu2IOStats) snapshot() IOStats {
	return IOStats{
		DatagramsReceived: s.datagramsReceived.Load(),
		DatagramsSent:     s.datagramsSent.Load(),
		BytesReceived:     s.bytesReceived.Load(),
		BytesSent:         s.bytesSent.Load(),
		Dropped:           s.dropped.Load(),
	}
}

type ssu2ReceiveBatch struct {
	batch     *ssu2.Batch
	remaining atomic.Int32
	addresses [ssu2ReceiveBatchSize]netip.AddrPort
}
type ssu2PacketAddr struct{ value netip.AddrPort }

func (a ssu2PacketAddr) Network() string          { return "udp" }
func (a ssu2PacketAddr) String() string           { return a.value.String() }
func (a ssu2PacketAddr) AddrPort() netip.AddrPort { return a.value }

type ssu2ReceiveJob struct {
	batch *ssu2ReceiveBatch
	index uint8
}

type ssu2DispatchItem struct {
	peer    foundation.Hash
	message i2np.Message
}

// ssu2DispatchBatch is leased to one authenticated receive batch until every
// borrowed I2NP view has been delivered synchronously.  Its fixed storage keeps
// the receive path allocation-free and makes buffer ownership explicit.
type ssu2DispatchBatch struct {
	items [ssu2ReceiveBatchSize * 8]ssu2DispatchItem
	count uint8
	done  chan error
}
type ssu2EgressSlot struct {
	data   [ssu2.MaxIPv4PacketLen]byte
	length int
	addr   netip.AddrPort
	zone   uint32
	relay  bool
	flow   uint64
	done   chan error
}

func (m *SSU2Manager) releaseSensitive() {
	clear(m.staticPrivate)
	clear(m.introKey)
	clear(m.tokenSecret[:])
	m.clearIOBuffers()
}

func (m *SSU2Manager) clearIOBuffers() {
	if m == nil {
		return
	}
	clearReceive := func(received *ssu2ReceiveBatch) {
		if received == nil || received.batch == nil {
			return
		}
		for index := range received.batch.Packets() {
			clear(received.batch.Packets()[index].Data)
			received.batch.Packets()[index].Len = 0
		}
	}
	clearSlot := func(slot *ssu2EgressSlot) {
		if slot != nil {
			clear(slot.data[:])
			slot.length = 0
		}
	}
	for {
		select {
		case received := <-m.receiveFree:
			clearReceive(received)
		case job := <-m.authQueue:
			clearReceive(job.batch)
		case slot := <-m.egressFree:
			clearSlot(slot)
		case slot := <-m.egressQueue:
			clearSlot(slot)
		default:
			return
		}
	}
}

type ssu2TransportSession struct {
	peer       foundation.Hash
	sendID     uint64
	receiveID  uint64
	remoteMu   sync.RWMutex
	remote     net.Addr
	send       *ssu2.DataCipher
	receive    *ssu2.DataCipher
	lifetimeMu sync.RWMutex

	sendMu     sync.Mutex
	receiveMu  sync.Mutex
	nextPacket uint32
	sendPacket [ssu2.MaxIPv4PacketLen]byte
	frameMu    sync.Mutex
	frame      [ssu2.MaxIPv4PacketLen]byte
	received   ssu2.ACKTracker
	sent       map[uint32]*ssu2SentPacket
	sentSlots  []ssu2SentPacket
	sentStore  []byte
	fragmentMu sync.Mutex
	ackMu      sync.Mutex
	ackPayload [3 + 5 + 2*ssu2.MaxACKRanges]byte
	fragments  map[uint32]*ssu2FragmentAssembly

	activityMu   sync.Mutex
	lastActivity time.Time
	pathMu       sync.Mutex
	candidate    *ssu2PathCandidate
	releaseOnce  sync.Once
}

type ssu2PathCandidate struct {
	remote    *net.UDPAddr
	challenge [8]byte
	expires   time.Time
}

func (s *ssu2TransportSession) ReleaseSensitive() {
	if s == nil {
		return
	}
	s.releaseOnce.Do(func() {
		// The lifetime barrier prevents authenticated receive processing from
		// repopulating fragments/path state after terminal cleanup. Cipher
		// users additionally serialize on their directional locks.
		s.lifetimeMu.Lock()
		defer s.lifetimeMu.Unlock()
		// Terminal release follows the only nested user order: framing, ACK,
		// receive, then send.
		s.frameMu.Lock()
		s.ackMu.Lock()
		s.receiveMu.Lock()
		s.sendMu.Lock()
		if s.send != nil {
			s.send.ReleaseSensitive()
			s.send = nil
		}
		if s.receive != nil {
			s.receive.ReleaseSensitive()
			s.receive = nil
		}
		clear(s.sendPacket[:])
		clear(s.frame[:])
		for index := range s.sentSlots {
			s.sentSlots[index].release()
		}
		for _, packet := range s.sent {
			packet.release()
		}
		clear(s.sent)
		clear(s.sentStore)
		s.sentSlots = nil
		s.sentStore = nil
		s.sendMu.Unlock()
		clear(s.ackPayload[:])
		s.receiveMu.Unlock()
		s.ackMu.Unlock()
		s.frameMu.Unlock()
		s.fragmentMu.Lock()
		for _, fragment := range s.fragments {
			clear(fragment.first)
			for _, data := range fragment.following {
				clear(data)
			}
			clear(fragment.following)
		}
		clear(s.fragments)
		s.fragmentMu.Unlock()
		s.pathMu.Lock()
		if s.candidate != nil {
			clear(s.candidate.challenge[:])
			s.candidate.remote = nil
			s.candidate = nil
		}
		s.pathMu.Unlock()
		s.remoteMu.Lock()
		s.remote = nil
		s.remoteMu.Unlock()
	})
}

func (s *ssu2TransportSession) remoteAddr() net.Addr {
	s.remoteMu.RLock()
	remote := s.remote
	s.remoteMu.RUnlock()
	return remote
}

func (s *ssu2TransportSession) setRemote(remote net.Addr) {
	s.remoteMu.Lock()
	s.remote = remote
	s.remoteMu.Unlock()
}

type ssu2SentPacket struct {
	payload  []byte
	sentAt   time.Time
	attempts uint8
	inUse    bool
}

func (s *ssu2TransportSession) initReliability() {
	s.sent = make(map[uint32]*ssu2SentPacket, ssu2MaxTrackedPackets)
	s.sentSlots = make([]ssu2SentPacket, ssu2MaxTrackedPackets)
	s.sentStore = make([]byte, ssu2MaxTrackedPackets*ssu2.MaxIPv4PacketLen)
	for index := range s.sentSlots {
		start := index * ssu2.MaxIPv4PacketLen
		s.sentSlots[index].payload = s.sentStore[start:start]
	}
}

func (s *ssu2TransportSession) retainPayload(payload []byte, now time.Time) *ssu2SentPacket {
	if len(payload) > ssu2.MaxIPv4PacketLen {
		return nil
	}
	for index := range s.sentSlots {
		slot := &s.sentSlots[index]
		if slot.inUse {
			continue
		}
		storage := s.sentStore[index*ssu2.MaxIPv4PacketLen : (index+1)*ssu2.MaxIPv4PacketLen]
		copy(storage, payload)
		slot.payload = storage[:len(payload)]
		slot.sentAt = now
		slot.attempts = 0
		slot.inUse = true
		return slot
	}
	return nil
}

func (p *ssu2SentPacket) release() {
	if p == nil {
		return
	}
	clear(p.payload)
	p.payload = p.payload[:0]
	p.sentAt = time.Time{}
	p.attempts = 0
	p.inUse = false
}

type ssu2FragmentAssembly struct {
	header    i2np.TransportHeader
	first     []byte
	following map[uint8][]byte
	last      uint8
	size      int
	updated   time.Time
}
type ssu2OutboundPending struct {
	peer          foundation.Hash
	remote        *net.UDPAddr
	address       ssu2PeerAddress
	initiator     *ssu2.Initiator
	destinationID uint64
	sourceID      uint64
	tokenSent     bool
	confirming    bool
	phase         string
	parseMu       sync.Mutex
	releaseOnExit atomic.Bool
	releaseOnce   sync.Once
	packet        [ssu2.MaxIPv4PacketLen]byte
	ready         chan struct{}
	err           error
	timer         *time.Timer
}

type ssu2InboundPending struct {
	reassemblyMu sync.Mutex
	remote       net.Addr
	sendID       uint64
	responder    *ssu2.Responder
	reassembly   *ssu2.ConfirmedReassembler
	timer        *time.Timer
}

type ssu2RelayRequest struct {
	target     foundation.Hash
	introducer foundation.Hash
	address    ssu2PeerAddress
	endpoint   netip.AddrPort
	ready      chan struct{}
	expires    time.Time
	timer      *time.Timer
	started    bool
	completed  bool
	err        error
}

type ssu2RelayForward struct {
	alice   *ssu2TransportSession
	charlie *ssu2TransportSession
	expires time.Time
}

type ssu2RelayTagLease struct {
	peer     foundation.Hash
	tag      uint32
	expires  time.Time
	renewing bool
}

type ssu2NewTokenLease struct {
	peer        foundation.Hash
	endpoint    string
	destination uint64
	token       uint64
	expires     time.Time
}

// ssu2PeerTestState records only authenticated observations. It is bounded by
type ssu2PeerTestState struct {
	nonce            uint32
	bob              foundation.Hash
	alice            foundation.Hash
	charlie          foundation.Hash
	message6Received bool
	endpoint         netip.AddrPort
	expires          time.Time
	message4         *ssu2.PeerTestBlock
	message5         *ssu2.PeerTestBlock
	message7         *ssu2.PeerTestBlock
	message5Peer     foundation.Hash
	message5Source   netip.AddrPort
	message7Source   netip.AddrPort
	message6Sent     bool
	timer            *time.Timer
	sixTimer         *time.Timer
	diagnostic       string
}

type ssu2PeerTestEvidence struct {
	endpoint netip.AddrPort
	observed netip.AddrPort
	count    uint8
}
type ssu2DeferredRelayIntro struct {
	bob     *ssu2TransportSession
	intro   ssu2.RelayIntro
	attempt uint8
	expires time.Time
}

// ssu2RelayStoreJob transfers a validated relay forward to the bounded
// control-plane queue. Dynamically sized workers keep RouterInfo compression
// out of the UDP receive loop.
type ssu2RelayStoreJob struct {
	nonce     uint32
	request   ssu2.RelayRequest
	alice     *ssu2TransportSession
	charlie   *ssu2TransportSession
	aliceInfo netdb.RouterInfo
	localHash foundation.Hash
}

// ssu2RouterInfoStoreSnapshot holds immutable RouterInfo-store bytes shared
// through SSU2Manager.routerInfoStores.
type ssu2RouterInfoStoreSnapshot struct {
	raw        []byte
	compressed []byte
	hash       foundation.Hash
}

type ssu2PeerAddress struct {
	host   string
	port   uint16
	static [32]byte
	intro  [32]byte
}

// NewSSU2Manager constructs an SSU2 manager without opening a UDP socket.
func NewSSU2Manager(config SSU2ManagerConfig) (*SSU2Manager, error) {
	if len(config.StaticPrivate) != 32 || len(config.IntroKey) != 32 {
		return nil, ErrSSU2ManagerConfig
	}
	if _, err := ecdh.X25519().NewPrivateKey(config.StaticPrivate); err != nil {
		return nil, ErrSSU2ManagerConfig
	}
	if config.NetworkID == 0 {
		config.NetworkID = defaultSSU2NetworkID
	}
	if config.NetworkID != defaultSSU2NetworkID {
		return nil, ErrSSU2ManagerConfig
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = defaultSSU2HandshakeTimeout
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = defaultSSU2MaxClockSkew
	}
	if config.TokenLifetime <= 0 {
		config.TokenLifetime = defaultSSU2TokenLifetime
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = ssu2DefaultIdleTimeout
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultSSU2MaxSessions
	}
	if config.MaxPending <= 0 {
		config.MaxPending = defaultSSU2MaxPending
	}
	var tokenSecret [sha256.Size]byte
	if _, err := rand.Read(tokenSecret[:]); err != nil {
		return nil, err
	}
	return &SSU2Manager{
		database:             config.Database,
		staticPrivate:        append([]byte(nil), config.StaticPrivate...),
		introKey:             append([]byte(nil), config.IntroKey...),
		tokenSecret:          tokenSecret,
		networkID:            config.NetworkID,
		timeout:              config.HandshakeTimeout,
		maxClockSkew:         config.MaxClockSkew,
		tokenLifetime:        config.TokenLifetime,
		idleTimeout:          config.IdleTimeout,
		maxSessions:          config.MaxSessions,
		maxPending:           config.MaxPending,
		signControl:          config.SignControl,
		introductionEndpoint: config.IntroductionEndpoint,
		onPeerTestResult:     config.OnPeerTestResult,
		onPeerTest:           config.OnPeerTest,
		reporter:             config.PanicReporter,
		metrics:              config.Metrics,
		logger:               config.Logger,
		done:                 make(chan struct{}),
		sessionsByPeer:       make(map[foundation.Hash]*ssu2TransportSession),
		sessionsByID:         make(map[uint64]*ssu2TransportSession),
		outbound:             make(map[foundation.Hash]*ssu2OutboundPending),
		outboundAddr:         make(map[netip.AddrPort]*ssu2OutboundPending),
		inbound:              make(map[uint64]*ssu2InboundPending),
		introducers:          make(map[uint32]foundation.Hash),
		relayGrants:          make(map[foundation.Hash]ssu2RelayTagLease),
		advertisedRelays:     make(map[foundation.Hash]ssu2RelayTagLease),
		relayTagPending:      make(map[foundation.Hash]time.Time),
		newTokens:            make(map[string]ssu2NewTokenLease),
		peerTests:            make(map[uint32]*ssu2PeerTestState),
		symmetricEvidence:    make(map[string]ssu2PeerTestEvidence),
		relayRequests:        make(map[uint32]*ssu2RelayRequest),
		relayForwards:        make(map[uint32]ssu2RelayForward),
		deferredRelayIntros:  make(map[uint32]ssu2DeferredRelayIntro),
		routerInfoStores:     make(map[foundation.Hash]ssu2RouterInfoStoreSnapshot),
	}, nil
}

// Start takes ownership of bindings.SSU2 and begins receiving authenticated
// UDP packets. A local signed SSU2 RouterInfo address must bind both configured
// key materials before the manager will process network traffic.
func (m *SSU2Manager) Start(parent context.Context, bindings TransportBindings) error {
	if bindings.SSU2 == nil || bindings.LocalInfo == nil ||
		bindings.HandleI2NPContext == nil || bindings.Clock == nil {
		return ErrSSU2ManagerConfig
	}
	staticPublic, err := ecdhPublic(m.staticPrivate)
	if err != nil || !hasSSU2Keys(bindings.LocalInfo.Snapshot(), staticPublic, m.introKey) {
		return ErrSSU2ManagerConfig
	}
	if parent ==
		nil {
		parent = context.Background()
	}

	if err := parent.Err(); err != nil {
		return err
	}
	batchConn, err := ssu2.NewUDPBatchConn(bindings.SSU2)
	if err != nil {
		return err
	}
	receiveFree := make(chan *ssu2ReceiveBatch, ssu2ReceiveBatchCount)
	for range ssu2ReceiveBatchCount {
		batch, err := ssu2.NewBatch(ssu2ReceiveBatchSize, ssu2.MaxIPv4PacketLen)
		if err != nil {
			return err
		}
		receiveFree <- &ssu2ReceiveBatch{batch: batch}
	}
	egressFree := make(chan *ssu2EgressSlot, ssu2EgressSlots)
	for range ssu2EgressSlots {
		egressFree <- &ssu2EgressSlot{done: make(chan error, 1)}
	}

	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ErrStarted
	}
	m.started = true
	m.conn = bindings.SSU2
	m.batchConn = batchConn
	m.bindings = bindings
	m.ctx, m.cancel = context.WithCancel(parent)
	m.relayStoreJobs = make(chan ssu2RelayStoreJob, m.maxPending)
	m.relayPublish = make(chan struct{}, 1)
	m.receiveFree = receiveFree
	m.authQueue = make(chan ssu2ReceiveJob, ssu2ReceiveBatchCount*ssu2ReceiveBatchSize)
	authWorkers := parallelism.Workers(cap(m.authQueue))
	dispatchWorkers := parallelism.Workers(ssu2DispatchQueueSize)
	relayWorkers := parallelism.Workers(m.maxPending)
	dispatchCapacity := max(1, (ssu2DispatchQueueSize+dispatchWorkers-1)/dispatchWorkers)
	m.dispatchQueues = make([]chan *ssu2DispatchBatch, dispatchWorkers)
	for index := range m.dispatchQueues {
		m.dispatchQueues[index] = make(chan *ssu2DispatchBatch, dispatchCapacity)
	}
	m.dispatchFree = make(chan *ssu2DispatchBatch, ssu2DispatchQueueSize)
	for range ssu2DispatchQueueSize {
		m.dispatchFree <- &ssu2DispatchBatch{done: make(chan error, 1)}
	}
	m.egressFree = egressFree
	m.egressQueue = make(chan *ssu2EgressSlot, ssu2EgressSlots)
	if m.metrics != nil {
		if batchConn.VectorIOEnabled() {
			m.metrics.SetSSU2VectorIOEnabled(1)
		}
		if batchConn.KernelDropAccounting() {
			m.metrics.SetSSU2KernelDropAccounting(1)
		}
	}
	m.mu.Unlock()

	m.wg.Add(4 + authWorkers + dispatchWorkers + relayWorkers)
	go m.readLoop()
	for range authWorkers {
		go m.authLoop()
	}
	for _, queue := range m.dispatchQueues {
		go m.dispatchLoop(queue)
	}
	go m.egressLoop()
	go m.retransmitLoop()
	for range relayWorkers {
		go m.relayStoreLoop()
	}
	go m.relayPublicationLoop()
	go func() {
		<-m.ctx.Done()
		_ = m.Close()
	}()
	go func() {
		m.wg.Wait()
		close(m.done)
	}()
	return nil
}

// Close unblocks UDP reception and releases all callers waiting for a pending
// retry or handshake result.
func (m *SSU2Manager) Close() error {
	var closeErr error
	m.close.Do(func() {
		sessions := make(map[*ssu2TransportSession]struct{})
		outbounds := make([]*ssu2OutboundPending, 0, len(m.outbound))
		m.mu.Lock()
		inbounds := make([]*ssu2InboundPending, 0, len(m.inbound))
		batchConn := m.batchConn
		conn := m.conn
		cancel := m.cancel
		for _, pending := range m.outbound {
			if m.finishOutboundLocked(pending, ErrSSU2Session) {
				outbounds = append(outbounds, pending)
			}
		}
		for id, pending := range m.inbound {
			if pending.timer != nil {
				pending.timer.Stop()
			}
			delete(m.inbound, id)
			inbounds = append(inbounds, pending)
		}
		for _, session := range m.sessionsByID {
			sessions[session] = struct{}{}
		}
		for nonce, relay := range m.relayRequests {
			m.finishRelayRequestLocked(nonce, relay, ErrSSU2Session)
		}
		clear(m.relayForwards)
		clear(m.deferredRelayIntros)
		clear(m.introducers)
		clear(m.relayGrants)
		clear(m.advertisedRelays)
		clear(m.relayTagPending)
		m.relayRevision++
		clear(m.newTokens)
		clear(m.symmetricEvidence)
		for _, state := range m.peerTests {
			if state.timer != nil {
				state.timer.Stop()
			}
			if state.sixTimer != nil {
				state.sixTimer.Stop()
			}
		}
		clear(m.peerTests)
		clear(m.sessionsByPeer)
		clear(m.sessionsByID)
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if batchConn != nil {
			closeErr = batchConn.Close()
		} else if conn != nil {
			closeErr = conn.Close()
		}
		for _, pending := range outbounds {
			pending.releaseSensitive()
		}
		for _, pending := range inbounds {
			pending.reassemblyMu.Lock()
			pending.responder.ReleaseSensitive()
			pending.reassembly.ReleaseSensitive()
			pending.reassemblyMu.Unlock()
		}
		m.syncRelayTagPublication()
		publishCtx, publishCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = m.publishRelaySnapshot(publishCtx)
		publishCancel()
		for session := range sessions {
			session.ReleaseSensitive()
		}
	})
	return closeErr
}

// Wait blocks until packet reception has stopped. After it returns, manager
// permanent key copies have been overwritten.
func (m *SSU2Manager) Wait() error {
	m.mu.RLock()
	started, done := m.started, m.done
	m.mu.RUnlock()
	if !started {
		m.releaseSensitive()
		return nil
	}
	<-done
	m.releaseSensitive()
	m.mu.RLock()
	err := m.err
	m.mu.RUnlock()
	return err
}

func (m *SSU2Manager) Status() TransportStatus {
	m.mu.RLock()
	status := TransportStatus{Running: m.started && m.ctx != nil && m.ctx.Err() == nil, Error: m.err}
	m.mu.RUnlock()
	return status
}

// EnsureSession authenticates a bidirectional SSU2 session without emitting an
// I2NP message.
func (m *SSU2Manager) EnsureSession(ctx context.Context, peer foundation.Hash) error {
	if ctx ==
		nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := m.establish(ctx, peer)
	if errors.Is(err, ErrSSU2Peer) {
		if err = m.introduceFromRouterInfo(ctx, peer); err == nil {
			_, err = m.establish(ctx, peer)
		}
	}
	if err != nil {
		m.recordOutboundFailure(peer, err)
	}
	return err
}

func (m *SSU2Manager) HasSession(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	session := m.sessionsByPeer[peer]
	m.mu.RUnlock()
	return session != nil
}

func (m *SSU2Manager) DropSession(peer foundation.Hash) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	session := m.sessionsByPeer[peer]
	if session != nil {
		m.removeSessionLocked(session)
	}
	m.mu.Unlock()
	if session == nil {
		return false
	}
	session.ReleaseSensitive()
	return true
}

// Send waits for a validated native SSU2 session and delivers one complete
// I2NP message, framing oversized payloads as reliable SSU2 fragments.
func (m *SSU2Manager) Send(ctx context.Context, peer foundation.Hash, message i2np.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(message.Payload) > i2np.I2PDMaxPayload {
		return i2np.ErrPayloadTooLarge
	}
	session, err := m.establish(ctx, peer)
	if err != nil {
		if !errors.Is(err, ErrSSU2Peer) {
			m.recordOutboundFailure(peer, err)
			return err
		}
		if err = m.introduceFromRouterInfo(ctx, peer); err != nil {
			m.recordOutboundFailure(peer, err)
			return err
		}
		session, err = m.establish(ctx, peer)
		if err != nil {
			m.recordOutboundFailure(peer, err)
			return err
		}
	}
	session.frameMu.Lock()
	defer session.frameMu.Unlock()
	return forEachSSU2I2NPFragment(session.frame[:], message, func(payload []byte) error {
		if err = m.sendData(session, payload); err == nil {
			return nil
		}
		if m.sessionActive(session) {
			return err
		}
		session, err = m.establish(ctx, peer)
		if err != nil {
			m.recordOutboundFailure(peer, err)
			return err
		}
		return m.sendData(session, payload)
	})
}

// SendPeerTest sends an authenticated out-of-session phase-5, -6, or -7 Peer
// Test packet to a verified SSU2 RouterInfo. Signature generation remains with
// the caller because its signing key is outside transport ownership.
func (m *SSU2Manager) SendPeerTest(ctx context.Context, peer foundation.Hash, test ssu2.PeerTestBlock) error {

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if test.Message < 5 || test.Message > 7 || m.database == nil {
		return ErrSSU2Peer
	}
	m.mu.RLock()
	running := m.runningLocked()
	m.mu.RUnlock()
	if !running {
		return ErrSSU2Session
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return ErrSSU2Peer
	}
	address, err := selectSSU2Address(ref.Info)
	if err != nil {
		return err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address.host, strconv.Itoa(int(address.port))))
	if err != nil {
		return ErrSSU2Peer
	}
	var payloadStorage [ssu2.MaxIPv4PacketLen]byte
	payload, err := ssu2DateTimeBlockTo(payloadStorage[:0], m.now())
	if err != nil {
		return err
	}
	payload, err = ssu2.MarshalPeerTestBlock(payload, test)
	if err != nil {
		return err
	}
	destinationID, sourceID := ssu2.PeerTestConnectionIDs(test.Nonce)
	if test.Message == 6 {
		destinationID, sourceID = sourceID, destinationID
	}
	packetNumber, err := randomPacketNumber()
	if err != nil {
		return err
	}

	var packetStorage [ssu2.MaxIPv4PacketLen]byte
	packet, err := ssu2.BuildPeerTest(packetStorage[:], address.intro[:], destinationID, sourceID, packetNumber, payload)
	if err != nil {
		return err
	}
	return m.writeRelayTo(packet, remote, uint64(test.Nonce))
}

// maybeStartPeerTest activates peer testing for newly established outbound
// sessions while retaining one bounded in-flight test per Bob.
func (m *SSU2Manager) maybeStartPeerTest(bob foundation.Hash) {
	m.mu.RLock()
	running := m.runningLocked()
	for _, state := range m.peerTests {
		if state.bob == bob {
			running = false
			break
		}
	}
	ctx := m.ctx
	m.mu.RUnlock()
	if running {
		go func() { _ = m.StartPeerTest(ctx, bob) }()
	}
}

// StartPeerTest begins the Alice side of the SSU2 Peer Test process over an
// existing authenticated session with Bob.
func (m *SSU2Manager) StartPeerTest(ctx context.Context, bob foundation.Hash) error {

	if ctx == nil {
		ctx = context.
			Background()
	}
	session, err := m.establish(ctx, bob)
	if err != nil {
		return err
	}
	endpoint, err := m.localSSU2Endpoint()
	if err != nil {
		return err
	}
	nonce, err := randomPacketNumber()
	if err != nil || nonce == 0 {
		return ErrSSU2Session
	}
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return ErrSSU2Session
	}
	test := ssu2.PeerTestBlock{Message: 1, Nonce: nonce, Timestamp: uint32(m.now().Unix()), Address: endpoint}
	input, err := ssu2.PeerTestSignatureInput(nil, bob[:], nil, test)
	if err != nil {
		return err
	}
	test.Signature, err = m.signSSU2Control(input)
	clear(input)
	if err != nil || len(test.Signature) == 0 {
		return ErrSSU2Session
	}
	var payloadStorage [ssu2.MaxIPv4PacketLen]byte
	payload, err := ssu2.MarshalPeerTestBlock(payloadStorage[:0], test)
	if err != nil {
		return err
	}
	state := &ssu2PeerTestState{
		nonce: nonce, bob: bob, alice: bindings.LocalInfo.Hash(), endpoint: endpoint,
		expires: m.now().Add(m.timeout),
	}
	m.mu.Lock()
	if !m.runningLocked() || len(m.peerTests) >= m.maxPending || m.peerTests[nonce] != nil {
		m.mu.Unlock()
		return ErrSSU2Session
	}
	m.peerTests[nonce] = state
	state.timer = time.AfterFunc(m.timeout, func() { m.expirePeerTest(nonce, state) })
	m.mu.Unlock()
	if err = m.sendSessionData(session, payload, true); err != nil {
		m.expirePeerTest(nonce, state)
		return err
	}
	return nil
}

// RegisterIntroducer registers this manager as Bob for relayTag. The selected
// Charlie must have a live native SSU2 session when a Relay Request arrives.
func (m *SSU2Manager) RegisterIntroducer(relayTag uint32, charlie foundation.Hash) error {
	if relayTag == 0 {
		return ErrSSU2Introduction
	}
	m.mu.Lock()
	m.introducers[relayTag] = charlie
	m.mu.Unlock()
	return nil
}

func (m *SSU2Manager) handleRelayTagRequest(session *ssu2TransportSession) {
	now := m.now()
	m.mu.Lock()
	lease, exists := m.relayGrants[session.peer]
	if exists && !lease.expires.After(now) {
		delete(m.relayGrants, session.peer)
		if m.introducers[lease.tag] == session.peer {
			delete(m.introducers, lease.tag)
		}
		exists = false
	}
	if !exists && len(m.relayGrants) >= m.maxPending {
		m.mu.Unlock()
		return
	}
	if !exists {
		for lease.tag == 0 {
			tag, err := randomPacketNumber()
			if err != nil {
				m.mu.Unlock()
				return
			}
			if _, collision := m.introducers[tag]; !collision {
				lease.tag = tag
			}
		}
	}
	lease.peer = session.peer
	lease.expires = now.Add(m.tokenLifetime)
	m.relayGrants[session.peer] = lease
	m.introducers[lease.tag] = session.peer
	m.mu.Unlock()

	var storage [32]byte
	block, err := ssu2.MarshalRelayTagBlock(storage[:0], ssu2.RelayTag{Tag: lease.tag, Expiration: uint32(lease.expires.Unix())})
	if err == nil {
		_ = m.sendSessionData(session, block, true)
	}
}

func (m *SSU2Manager) handleRelayTag(session *ssu2TransportSession, tag ssu2.RelayTag) {
	expires := time.Unix(int64(tag.Expiration), 0)
	now := m.now()
	if tag.Tag == 0 || !expires.After(now) || expires.Sub(now) > m.tokenLifetime {
		return
	}
	changed := false
	m.mu.Lock()
	existing, exists := m.advertisedRelays[session.peer]
	pendingUntil, requested := m.relayTagPending[session.peer]
	handleRelayTagSelected := m.runningLocked() && requested && pendingUntil.After(now)
	if handleRelayTagSelected {
		handleRelayTagSelected = (exists || len(m.advertisedRelays) < ssu2RelayTarget)
	}
	if handleRelayTagSelected {
		delete(m.relayTagPending, session.peer)
		m.advertisedRelays[session.peer] = ssu2RelayTagLease{peer: session.peer, tag: tag.Tag, expires: expires}
		changed = !exists || existing.tag != tag.Tag || !existing.expires.Equal(expires)
		if changed {
			m.relayRevision++
		}
	}
	m.mu.Unlock()
	if changed {
		m.syncRelayTagPublication()
	}
	m.maintainIntroducers()
}

// RequestRelayTag negotiates a renewable relay lease on a live SSU2 session.
func (m *SSU2Manager) RequestRelayTag(ctx context.Context, peer foundation.Hash) error {
	if ctx ==
		nil {
		ctx = context.Background()
	}

	session, err := m.establish(ctx, peer)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if !m.runningLocked() {
		m.mu.Unlock()
		return ErrSSU2Session
	}
	m.relayTagPending[peer] = m.nowLocked().Add(m.timeout)
	m.mu.Unlock()
	if err = m.requestRelayTagOnSession(session); err != nil {
		m.mu.Lock()
		delete(m.relayTagPending, peer)
		m.mu.Unlock()
	}
	return err
}

func (m *SSU2Manager) requestRelayTagOnSession(session *ssu2TransportSession) error {
	var storage [8]byte
	block, err := ssu2.MarshalRelayTagRequestBlock(storage[:0], ssu2.RelayTagRequest{})
	if err != nil {
		return err
	}
	return m.sendSessionData(session, block, true)
}

// RemoveIntroducer stops accepting new Relay Requests for relayTag.
func (m *SSU2Manager) RemoveIntroducer(relayTag uint32) {
	m.mu.Lock()
	peer, found := m.introducers[relayTag]
	delete(m.introducers, relayTag)
	if found {
		if lease, ok := m.relayGrants[peer]; ok && lease.tag == relayTag {
			delete(m.relayGrants, peer)
		}
	}
	m.mu.Unlock()
}

// ssu2IntroducerPublisher is implemented by the sole local RouterInfo owner.
type ssu2IntroducerPublisher interface {
	UpdateSSU2Introducers(context.Context, []SSU2Introducer) error
}

func (m *SSU2Manager) syncRelayTagPublication() {
	m.mu.RLock()
	queue := m.relayPublish
	m.mu.RUnlock()
	if queue == nil {
		return
	}
	select {
	case queue <- struct{}{}:
	default:
	}
}

func (m *SSU2Manager) relayPublicationSnapshot() (ssu2IntroducerPublisher, uint64, []SSU2Introducer) {
	m.mu.RLock()
	bindings := m.bindings
	revision := m.relayRevision
	now := m.nowLocked()
	leases := make([]SSU2Introducer, 0, ssu2RelayTarget)
	for _, lease := range m.advertisedRelays {
		if lease.expires.After(now) {
			leases = append(leases, SSU2Introducer{Peer: lease.peer, RelayTag: lease.tag, Expiration: lease.expires})
		}
	}
	m.mu.RUnlock()
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].Expiration.Equal(leases[j].Expiration) {
			return leases[i].RelayTag < leases[j].RelayTag
		}
		return leases[i].Expiration.Before(leases[j].Expiration)
	})
	if len(leases) > ssu2RelayTarget {
		leases = leases[:ssu2RelayTarget]
	}
	publisher, _ := bindings.LocalInfo.(ssu2IntroducerPublisher)
	return publisher, revision, leases
}

func (m *SSU2Manager) publishRelaySnapshot(ctx context.Context) (bool, error) {
	m.relayPublishMu.Lock()
	defer m.relayPublishMu.Unlock()
	publisher, revision, leases := m.relayPublicationSnapshot()
	if publisher == nil {
		return true, nil
	}
	if err := publisher.UpdateSSU2Introducers(ctx, leases); err != nil {
		return false, err
	}
	m.mu.Lock()
	m.publishedRevision = revision
	current := m.relayRevision
	m.mu.Unlock()
	return current == revision, nil
}

func (m *SSU2Manager) relayPublicationLoop() {
	defer m.wg.Done()
	backoff := ssu2RelayPublishMin
	for {
		select {
		case <-m.contextDone():
			return
		case <-m.relayPublish:
		}
		for {
			attemptTimeout := min(m.timeout, 5*time.Second)
			if attemptTimeout <= 0 {
				attemptTimeout = 5 * time.Second
			}
			attemptCtx, cancelAttempt := context.WithTimeout(m.ctx, attemptTimeout)
			converged, err := m.publishRelaySnapshot(attemptCtx)
			cancelAttempt()
			if err == nil {
				backoff = ssu2RelayPublishMin
				if converged {
					break
				}
				continue
			}
			if m.logger != nil && !errors.Is(err, context.Canceled) {
				m.logger.Warn("SSU2 introducer publication retry", "error", err, "backoff", backoff)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-m.contextDone():
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
			backoff = min(backoff*2, ssu2RelayPublishMax)
		}
	}
}
func (m *SSU2Manager) maintainIntroducers() {
	now := m.now()
	type candidate struct {
		peer    foundation.Hash
		session *ssu2TransportSession
	}
	var candidates []candidate
	changed := false
	m.mu.Lock()
	for peer, lease := range m.advertisedRelays {
		if !lease.expires.After(now) {
			delete(m.advertisedRelays, peer)
			changed = true
		}
	}
	for peer, until := range m.relayTagPending {
		if !until.After(now) {
			delete(m.relayTagPending, peer)
		}
	}
	if changed {
		m.relayRevision++
	}
	pendingNew := 0
	for peer := range m.relayTagPending {
		if _, advertised := m.advertisedRelays[peer]; !advertised {
			pendingNew++
		}
	}
	needed := ssu2RelayTarget - len(m.advertisedRelays) - pendingNew
	if needed > 0 {
		for peer, session := range m.sessionsByPeer {
			if _, exists := m.advertisedRelays[peer]; exists {
				continue
			}
			if _, pending := m.relayTagPending[peer]; pending {
				continue
			}
			candidates = append(candidates, candidate{peer: peer, session: session})
		}
		sort.Slice(candidates, func(i, j int) bool {
			return bytes.Compare(candidates[i].peer[:], candidates[j].peer[:]) < 0
		})
		if len(candidates) > needed {
			candidates = candidates[:needed]
		}
		for _, selected := range candidates {
			m.relayTagPending[selected.peer] = now.Add(m.timeout)
		}
	}
	m.mu.Unlock()
	if changed {
		m.syncRelayTagPublication()
	}
	for _, selected := range candidates {
		if err := m.requestRelayTagOnSession(selected.session); err != nil {
			m.mu.Lock()
			delete(m.relayTagPending, selected.peer)
			m.mu.Unlock()
		}
	}
}

// Introduce establishes target through an existing or newly-created session
// with introducer. endpoint is Alice's reachable UDP endpoint advertised in
// the signed Relay Request. relayTag is the tag target delegated to introducer
// in target's RouterInfo.
func (m *SSU2Manager) Introduce(ctx context.Context, introducer, target foundation.Hash, relayTag uint32, endpoint netip.AddrPort) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if relayTag == 0 || !validSSU2Endpoint(endpoint) || m.database == nil {
		return ErrSSU2Introduction
	}
	address, err := m.ssu2KeysForPeer(target)
	if err != nil {
		return err
	}
	introducerSession, err := m.establish(ctx, introducer)
	if err != nil {
		return err
	}
	nonce, err := randomRelayNonce()
	if err != nil {
		return err
	}
	request := ssu2.RelayRequest{
		Nonce:     nonce,
		RelayTag:  relayTag,
		Timestamp: uint32(m.now().Unix()),
		Endpoint:  endpoint,
	}
	unsigned, err := ssu2.RelayRequestSignatureInput(nil, introducer[:], target[:], request)
	if err != nil {
		return err
	}
	request.Signature, err = m.signSSU2Control(unsigned)
	clear(unsigned)
	if err != nil || len(request.Signature) == 0 {
		return ErrSSU2Introduction
	}
	payload, err := ssu2.MarshalRelayRequestBlock(nil, request)
	if err != nil {
		return err
	}
	relay := &ssu2RelayRequest{
		target:     target,
		introducer: introducer,
		address:    address,
		endpoint:   endpoint,
		ready:      make(chan struct{}),
		expires:    m.now().Add(m.timeout),
	}
	m.mu.Lock()
	if !m.runningLocked() || len(m.relayRequests) >= m.maxPending {
		m.mu.Unlock()
		return ErrSSU2Introduction
	}
	if m.relayRequests[nonce] != nil {
		m.mu.Unlock()
		return ErrSSU2Introduction
	}
	m.relayRequests[nonce] = relay
	relay.timer = time.AfterFunc(m.timeout, func() {
		m.mu.Lock()
		m.finishRelayRequestLocked(nonce, relay, ErrSSU2Introduction)
		m.mu.Unlock()
	})
	m.mu.Unlock()
	if err = m.sendData(introducerSession, payload); err != nil {
		m.mu.Lock()
		m.finishRelayRequestLocked(nonce, relay, err)
		m.mu.Unlock()
		return err
	}
	select {
	case <-relay.ready:
		if relay.err != nil {
			return relay.err
		}
		returnErr := error(nil)
		_, returnErr = m.establish(ctx, target)
		return returnErr
	case <-ctx.Done():
		m.mu.Lock()
		m.finishRelayRequestLocked(nonce, relay, ctx.Err())
		m.mu.Unlock()
		return ctx.Err()
	case <-m.contextDone():
		return ErrSSU2Session
	}
}
func (m *SSU2Manager) establish(ctx context.Context, peer foundation.Hash) (*ssu2TransportSession, error) {
	var stale *ssu2TransportSession
	m.mu.Lock()
	if !m.runningLocked() {
		m.mu.Unlock()
		return nil, ErrSSU2Session
	}
	if session := m.sessionsByPeer[peer]; session != nil {
		if !session.idle(m.nowLocked(), m.idleTimeout) {
			m.mu.Unlock()
			return session, nil
		}
		m.removeSessionLocked(session)
		stale = session
	}
	pending := m.outbound[peer]
	if pending == nil {
		var err error
		pending, err = m.newOutboundLocked(peer)
		if err != nil {
			m.mu.Unlock()
			if stale != nil {
				stale.ReleaseSensitive()
			}
			return nil, err
		}
	}
	cachedToken := m.cachedNewTokenLocked(peer, pending.remote, pending.destinationID)
	sendToken := !pending.tokenSent
	if sendToken {
		pending.tokenSent = true
	}
	ready := pending.ready
	m.mu.Unlock()
	if stale != nil {
		stale.ReleaseSensitive()
	}

	if sendToken {
		if cachedToken != 0 {
			m.sendSessionRequest(pending, cachedToken)
		} else if err := m.sendTokenRequest(pending); err != nil {
			m.failOutbound(pending, err)
		}
	}
	select {
	case <-ready:
		m.mu.RLock()
		err := pending.err
		session := m.sessionsByPeer[peer]
		m.mu.RUnlock()
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, ErrSSU2Session
		}
		return session, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.contextDone():
		return nil, ErrSSU2Session
	}
}

func (m *SSU2Manager) newOutboundLocked(peer foundation.Hash) (*ssu2OutboundPending, error) {
	if m.database == nil {
		return nil, ErrSSU2Session
	}
	ref, ok := m.database.Routers().Get(peer)
	if !ok {
		return nil, ErrSSU2Peer
	}
	if err := netdb.ReseedRouterInfoFresh(ref.Info, uint64(m.nowLocked().UnixMilli())); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSU2Peer, err)
	}
	address, err := selectSSU2Address(ref.Info)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address.host, strconv.Itoa(int(address.port))))
	if err != nil {
		return nil, ErrSSU2Peer
	}
	destinationID := m.cachedNewTokenDestinationLocked(peer, remote)
	if destinationID == 0 {
		destinationID, _, err = randomConnectionIDs()
		if err != nil {
			return nil, err
		}
	}
	_, sourceID, err := randomConnectionIDs()
	if err != nil {
		return nil, err
	}
	if m.logger != nil {
		m.logger.Info("public transport peer selected", "transport", "SSU2", "peer", routerHashDiagnostic(peer), "endpoint", remote.String(), "phase", "token_request")
	}
	return m.newOutboundToLocked(peer, address, remote, destinationID, sourceID)
}

func (m *SSU2Manager) newIntroducedOutboundLocked(peer foundation.Hash, address ssu2PeerAddress, endpoint netip.AddrPort, destinationID, sourceID uint64) (*ssu2OutboundPending, error) {
	if !validSSU2Endpoint(endpoint) {
		return nil, ErrSSU2Introduction
	}
	remote := &net.UDPAddr{IP: endpoint.Addr().AsSlice(), Port: int(endpoint.Port())}
	return m.newOutboundToLocked(peer, address, remote, destinationID, sourceID)
}

func (m *SSU2Manager) newOutboundToLocked(peer foundation.Hash, address ssu2PeerAddress, remote *net.UDPAddr, destinationID, sourceID uint64) (*ssu2OutboundPending, error) {
	if len(m.outbound)+len(m.inbound) >= m.maxPending || m.outbound[peer] != nil || remote == nil || remote.Port <= 0 {
		return nil, ErrSSU2Session
	}
	pending := &ssu2OutboundPending{
		peer:          peer,
		remote:        remote,
		address:       address,
		destinationID: destinationID,
		sourceID:      sourceID,
		ready:         make(chan struct{}),
		phase:         "token_request",
	}
	pending.timer = time.AfterFunc(m.timeout, func() {
		m.mu.Lock()
		finished := false
		if m.outbound[peer] == pending {
			finished = m.finishOutboundLocked(pending, ssu2HandshakeError{phase: pending.phase})
		}
		m.mu.Unlock()
		if finished {
			pending.releaseSensitive()
		}
	})
	m.outbound[peer] = pending
	endpoint, _ := addrPortKey(pending.remote)
	m.outboundAddr[endpoint] = pending
	return pending, nil
}

func (m *SSU2Manager) sendTokenRequest(pending *ssu2OutboundPending) error {
	packetNumber, err := randomPacketNumber()
	if err != nil {
		return err
	}
	payload, err := ssu2DateTimePayload(m.now())
	if err != nil {
		return err
	}
	packet, err := ssu2.BuildTokenRequest(make([]byte, ssu2.MaxIPv4PacketLen), pending.address.intro[:], pending.destinationID, pending.sourceID, packetNumber, payload)
	if err != nil {
		return err
	}
	if err = m.writeTo(packet, pending.remote); err != nil {
		return err
	}
	if m.logger != nil {
		m.logger.Debug("public transport handshake phase", "transport", "SSU2", "peer", routerHashDiagnostic(pending.peer), "endpoint", pending.remote.String(), "phase", "token_request_sent")
	}
	return nil
}

func (m *SSU2Manager) readLoop() {
	defer m.wg.Done()
	for {
		select {
		case received := <-m.receiveFree:
			if m.readBatch(received) {
				return
			}
		case <-m.contextDone():
			return
		}
	}
}

func (m *SSU2Manager) readBatch(received *ssu2ReceiveBatch) bool {
	n, err := m.batchConn.ReadBatch(received.batch)
	if n > 0 {
		m.processReceivedBatch(received, n)
	} else {
		select {
		case m.receiveFree <- received:
		case <-m.contextDone():
			return true
		}
	}
	if err == nil {
		return false
	}
	if errors.Is(err, ssu2.ErrDatagramTruncated) {
		m.ioStats.dropped.Add(1)
		return false
	}
	if m.contextErr() == nil && !errors.Is(err, net.ErrClosed) {
		m.recordSSU2Error(err)
		_ = m.Close()
	}
	return true
}

func (m *SSU2Manager) processReceivedBatch(received *ssu2ReceiveBatch, count int) {
	m.ioStats.datagramsReceived.Add(uint64(count))
	m.recordReceivedBatchMetrics(count)
	packets := received.batch.Packets()
	received.remaining.Store(int32(count))
	for index := range count {
		m.enqueueReceivedPacket(received, index, packets[index])
	}
}

func (m *SSU2Manager) recordReceivedBatchMetrics(count int) {
	if m.metrics == nil {
		return
	}
	m.metrics.AddSSU2ReceivedDatagrams(uint64(count))
	if count > 1 {
		m.metrics.IncSSU2ReceiveMultiBatches()
	}
	kernelDrops := m.batchConn.KernelDrops()
	previousDrops := m.kernelDrops.Swap(kernelDrops)
	if kernelDrops > previousDrops {
		m.metrics.AddSSU2KernelDrops(kernelDrops - previousDrops)
	}
}

func (m *SSU2Manager) enqueueReceivedPacket(received *ssu2ReceiveBatch, index int, packet ssu2.Datagram) {
	m.ioStats.bytesReceived.Add(uint64(packet.Len))
	if m.metrics != nil {
		m.metrics.AddTransportReceivedBytes(uint64(packet.Len))
	}
	if packet.Len < ssu2.MinPacketLen || packet.Len > len(packet.Data) || !packet.Addr.IsValid() {
		m.ioStats.dropped.Add(1)
		if m.metrics != nil {
			m.metrics.AddSSU2EnqueuedDatagrams(1)
			m.metrics.AddSSU2ProcessedDatagrams(1)
		}
		m.receiveComplete(received)
		return
	}
	received.addresses[index] = packet.Addr
	select {
	case m.authQueue <- ssu2ReceiveJob{batch: received, index: uint8(index)}:
		if m.metrics != nil {
			m.metrics.AddSSU2EnqueuedDatagrams(1)
			m.metrics.IncSSU2IngressQueueDepth()
		}
	default:
		m.ioStats.dropped.Add(1)
		if m.metrics != nil {
			m.metrics.AddSSU2ReceiveQueueDrops(1)
		}
		m.receiveComplete(received)
	}
}

func (m *SSU2Manager) authLoop() {
	defer m.wg.Done()
	for {
		select {
		case job := <-m.authQueue:
			packet := job.batch.batch.Packets()[job.index]
			if err := m.handlePacketRecovered(packet.Data[:packet.Len], job.batch.addresses[job.index]); err != nil && m.logger != nil {
				// ingress.Report already records the recovered panic. The
				// authenticated worker must drop only this datagram; closing the
				// manager here would turn one hostile packet into router-wide
				// loss of every SSU2 session.
				m.logger.Warn("dropped SSU2 datagram after recovered panic", "remote", job.batch.addresses[job.index], "error", err)
			}
			if m.metrics != nil {
				m.metrics.AddSSU2ProcessedDatagrams(1)
				m.metrics.DecSSU2IngressQueueDepth()
			}
			m.receiveComplete(job.batch)
		case <-m.contextDone():
			return
		}
	}
}

func (m *SSU2Manager) receiveComplete(received *ssu2ReceiveBatch) {
	if received.remaining.Add(-1) != 0 {
		return
	}
	select {
	case m.receiveFree <- received:
	case <-m.contextDone():
	}
}

func (m *SSU2Manager) handlePacketRecovered(packet []byte, remote netip.AddrPort) (err error) {
	defer recoverSSU2Packet(&err, m, remote)
	m.handlePacket(packet, remote)
	return nil
}

func recoverSSU2Packet(errp *error, manager *SSU2Manager, remote netip.AddrPort) {
	recovered := recover()
	if recovered == nil {
		return
	}
	*errp = ingress.Report(recovered, manager.reporter, ingress.BoundarySSU2Packet, ssu2PacketAddr{value: remote})
}

func (m *SSU2Manager) retransmitLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(ssu2RetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.contextDone():
			return
		case now := <-ticker.C:
			m.mu.RLock()
			sessions := make([]*ssu2TransportSession, 0, len(m.sessionsByID))
			for _, session := range m.sessionsByID {
				sessions = append(sessions, session)
			}
			m.mu.RUnlock()
			for _, session := range sessions {
				if session.idle(now, m.idleTimeout) || m.retransmitOne(session, now) {
					m.removeSession(session)
					continue
				}
				session.expireFragments(now)
				session.expirePath(now)
			}
			m.expireIntroductions(now)
			m.expireExtensions(now)
		}
	}
}

func (m *SSU2Manager) retransmitOne(session *ssu2TransportSession, now time.Time) bool {
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	var target *ssu2SentPacket
	for _, sent := range session.sent {
		if now.Sub(sent.sentAt) >= ssu2RetransmitInterval {
			target = sent
			break
		}
	}
	if target == nil {
		return false
	}
	if target.attempts >= ssu2MaxRetransmits {
		return true
	}
	if session.send == nil {
		return false
	}
	packetNumber := session.nextPacket
	if packetNumber == 0 {
		return true
	}
	packet, err := session.send.SealDataTo(session.sendPacket[:], ssu2.ShortHeader{DestinationID: session.sendID, PacketNumber: packetNumber, Type: ssu2.Data}, target.payload)
	if err != nil {
		return false
	}
	if m.writeTo(packet, session.remoteAddr()) != nil {
		return true
	}
	session.nextPacket++
	target.sentAt = now
	target.attempts++
	session.sent[packetNumber] = target
	session.touch(now)
	return false
}

func (m *SSU2Manager) handlePacket(packet []byte, remote netip.AddrPort) {
	// A retry or SessionCreated is address-bound to a single local pending
	// connection and is the only inbound class whose first header key is remote.
	endpoint := netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	m.mu.RLock()
	outbound := m.outboundAddr[endpoint]
	m.mu.RUnlock()
	if outbound != nil {
		if m.handleOutbound(packet, outbound) {
			return
		}
	}

	if header, err := ssu2.PeekSessionRequest(packet, m.introKey); err == nil {
		m.handleSessionRequest(packet, ssu2PacketAddr{value: remote}, header)
		return
	}
	if destinationID, err := ssu2.PeekDestinationID(packet, m.introKey); err == nil {
		m.mu.RLock()
		known := m.inbound[destinationID] != nil || m.sessionsByID[destinationID] != nil
		m.mu.RUnlock()
		if known {
			m.handleSessionPacket(packet, remote)
			return
		}
	}
	header, payload, err := ssu2.ParseOutOfSession(packet, m.introKey)
	if err != nil || !m.timestampValid(payload) {
		return
	}
	remoteAddr := ssu2PacketAddr{value: remote}
	switch header.Type {
	case ssu2.TokenRequest:
		m.handleTokenRequest(header, remoteAddr)
	case ssu2.PeerTest:
		m.handlePeerTest(header, payload, remoteAddr)
	case ssu2.HolePunch:
		m.handleHolePunch(header, payload, remoteAddr)
	}
}

func (m *SSU2Manager) handleOutbound(packet []byte, pending *ssu2OutboundPending) bool {
	if len(packet) > len(pending.packet) {
		return true
	}
	pending.parseMu.Lock()
	defer func() {
		pending.parseMu.Unlock()
		if pending.releaseOnExit.Load() {
			pending.releaseSensitive()
		}
	}()
	scratch := pending.packet[:len(packet)]
	copy(scratch, packet)
	if header, payload, err := ssu2.ParseRetry(scratch, pending.address.intro[:]); err == nil {
		if header.DestinationID != pending.sourceID || header.SourceID != pending.destinationID || header.Token == 0 || !m.timestampValid(payload) {
			return true
		}
		m.mu.Lock()
		if m.outbound[pending.peer] == pending {
			pending.phase = "session_request"
		}
		m.mu.Unlock()
		m.sendSessionRequestLocked(pending, header.Token)
		if m.logger != nil {
			m.logger.Debug("public transport handshake phase", "transport", "SSU2", "peer", routerHashDiagnostic(pending.peer), "endpoint", pending.remote.String(), "phase", "retry_authenticated")
		}
		return true
	}
	if pending.initiator == nil {
		return false
	}
	copy(scratch, packet)
	if header, payload, err := pending.initiator.ParseSessionCreated(scratch); err == nil {
		if header.DestinationID != pending.sourceID || header.SourceID != pending.destinationID || !m.timestampValid(payload) {
			m.markOutboundFailed(pending, ErrSSU2Session)
			return true
		}
		m.mu.Lock()
		if m.outbound[pending.peer] != pending || pending.confirming {
			m.mu.Unlock()
			return true
		}
		pending.confirming = true
		pending.phase = "session_confirmed"
		m.mu.Unlock()
		m.sendSessionConfirmed(pending)
		if m.logger != nil {
			m.logger.Debug("public transport handshake phase", "transport", "SSU2", "peer", routerHashDiagnostic(pending.peer), "endpoint", pending.remote.String(), "phase", "session_created_authenticated")
		}
		return true
	}
	return false
}

func (m *SSU2Manager) handlePeerTest(header ssu2.LongHeader, payload []byte, remote net.Addr) {
	if header.Token != 0 {
		return
	}
	iterator := ssu2.NewBlockIterator(payload)
	for {
		block, ok, err := iterator.Next()
		if err != nil || !ok {
			return
		}
		if block.Type != ssu2.BlockPeerTest {
			continue
		}
		test, err := ssu2.ParsePeerTestBlock(block.Data)
		if err != nil || test.Message < 5 || test.Message > 7 || !m.relayTimestampValid(test.Timestamp) {
			return
		}
		destinationID, sourceID := ssu2.PeerTestConnectionIDs(test.Nonce)
		if test.Message == 6 {
			destinationID, sourceID = sourceID, destinationID
		}
		if header.DestinationID != destinationID || header.SourceID != sourceID {
			return
		}
		if m.handleOutOfSessionPeerTest(test, remote) {
			m.mu.RLock()
			handler := m.onPeerTest
			m.mu.RUnlock()
			if handler != nil {
				handler(test, remote)
			}
		}
		return
	}
}
func (m *SSU2Manager) handleSessionPeerTest(session *ssu2TransportSession, test ssu2.PeerTestBlock) {
	if test.Message < 1 || test.Message > 4 || !m.relayTimestampValid(test.Timestamp) {
		return
	}
	switch test.Message {
	case 1:
		m.handlePeerTestOne(session, test)
	case 2:
		m.handlePeerTestTwo(session, test)
	case 3:
		m.handlePeerTestThree(session, test)
	case 4:
		m.handlePeerTestFour(session, test)
	}
}

func (m *SSU2Manager) handlePeerTestOne(alice *ssu2TransportSession, test ssu2.PeerTestBlock) {
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil || !peerTestEndpointMatches(alice.remoteAddr(), test.Address) ||
		!m.verifyPeerTest(alice.peer, bindings.LocalInfo.Hash(), foundation.Hash{}, test) {
		m.sendPeerTestReject(alice, test, 5)
		return
	}
	charlie := m.peerTestCharlie(alice, test.Address.Addr().Is4())
	if charlie == nil {
		m.sendPeerTestReject(alice, test, 2)
		return
	}
	state := &ssu2PeerTestState{
		nonce: test.Nonce, bob: bindings.LocalInfo.Hash(), alice: alice.peer,
		charlie: charlie.peer, endpoint: test.Address, expires: m.now().Add(m.timeout),
	}
	m.mu.Lock()
	if !m.runningLocked() || len(m.peerTests) >= m.maxPending || m.peerTests[test.Nonce] != nil {
		m.mu.Unlock()
		m.sendPeerTestReject(alice, test, 3)
		return
	}
	m.peerTests[test.Nonce] = state
	state.timer = time.AfterFunc(m.timeout, func() { m.expirePeerTest(test.Nonce, state) })
	m.mu.Unlock()
	forward := test
	forward.Message, forward.HasHash, forward.Hash = 2, true, alice.peer
	if err := m.sendPeerTestBlock(charlie, forward); err != nil {
		m.expirePeerTest(test.Nonce, state)
		m.sendPeerTestReject(alice, test, 2)
	}
}

func (m *SSU2Manager) handlePeerTestTwo(bob *ssu2TransportSession, test ssu2.PeerTestBlock) {
	if !test.HasHash || !m.verifyPeerTest(test.Hash, bob.peer, foundation.Hash{}, test) {
		return
	}
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return
	}
	response := ssu2.PeerTestBlock{Message: 3, Nonce: test.Nonce, Timestamp: uint32(m.now().Unix()), Address: test.Address}
	input, err := ssu2.PeerTestSignatureInput(nil, bob.peer[:], test.Hash[:], response)
	if err != nil {
		return
	}
	response.Signature, err = m.signSSU2Control(input)
	clear(input)
	if err != nil || len(response.Signature) == 0 {
		return
	}
	state := &ssu2PeerTestState{
		nonce: test.Nonce, bob: bob.peer, alice: test.Hash, charlie: bindings.LocalInfo.Hash(),
		endpoint: test.Address, expires: m.now().Add(m.timeout),
	}
	m.mu.Lock()
	if !m.runningLocked() || len(m.peerTests) >= m.maxPending || m.peerTests[test.Nonce] != nil {
		m.mu.Unlock()
		return
	}
	m.peerTests[test.Nonce] = state
	state.timer = time.AfterFunc(m.timeout, func() { m.expirePeerTest(test.Nonce, state) })
	m.mu.Unlock()
	if m.sendPeerTestBlock(bob, response) != nil {
		m.expirePeerTest(test.Nonce, state)
		return
	}
	// Message 5 is out-of-session and may arrive before Bob forwards message 4.
	phase5 := response
	phase5.Message = 5
	_ = m.SendPeerTest(m.ctx, test.Hash, phase5)
}

func (m *SSU2Manager) handlePeerTestThree(charlie *ssu2TransportSession, test ssu2.PeerTestBlock) {
	m.mu.RLock()
	state := m.peerTests[test.Nonce]
	bindings := m.bindings
	m.mu.RUnlock()
	if state == nil || bindings.LocalInfo == nil || state.charlie != charlie.peer ||
		!m.verifyPeerTest(charlie.peer, bindings.LocalInfo.Hash(), state.alice, test) {
		return
	}
	m.mu.RLock()
	alice := m.sessionsByPeer[state.alice]
	m.mu.RUnlock()
	if alice == nil {
		return
	}
	forward := test
	forward.Message, forward.HasHash, forward.Hash = 4, true, charlie.peer
	if m.sendPeerTestBlock(alice, forward) == nil {
		m.expirePeerTest(test.Nonce, state)
	}
}
func (m *SSU2Manager) handlePeerTestFour(bob *ssu2TransportSession, test ssu2.PeerTestBlock) {
	m.mu.RLock()
	state := m.peerTests[test.Nonce]
	if state == nil || state.bob != bob.peer || !test.HasHash {
		m.mu.RUnlock()
		return
	}
	alice := state.alice
	m.mu.RUnlock()
	if !m.verifyPeerTest(test.Hash, state.bob, alice, test) {
		return
	}
	if test.Code != 0 {
		m.completePeerTest(state, PeerTestResult{Nonce: test.Nonce, Outcome: PeerTestFirewalled, Diagnostic: "peer test rejected"})
		return
	}
	test.Signature = nil
	copy := test
	m.mu.Lock()
	if m.peerTests[test.Nonce] == state {
		state.charlie = test.Hash
		state.message4 = &copy
		if state.message5 != nil && state.message5Peer != test.Hash {
			state.message5 = nil
			state.message5Source = netip.AddrPort{}
			state.message5Peer = foundation.Hash{}
		}
	}
	result, done := m.peerTestResultLocked(state, false)
	m.mu.Unlock()
	if done {
		m.completePeerTest(state, result)
		return
	}
	m.schedulePeerTestSix(state)
}

func (m *SSU2Manager) handleOutOfSessionPeerTest(test ssu2.PeerTestBlock, remote net.Addr) bool {
	source, sourceOK := peerTestSource(remote)
	if !sourceOK {
		return false
	}
	m.mu.RLock()
	state := m.peerTests[test.Nonce]
	if state == nil || !state.expires.After(m.nowLocked()) || m.bindings.LocalInfo == nil {
		m.mu.RUnlock()
		return false
	}
	local := m.bindings.LocalInfo.Hash()
	var expected foundation.Hash
	switch test.Message {
	case 5:
		if state.alice != local {
			m.mu.RUnlock()
			return false
		}
		expected = state.charlie
	case 7:
		if state.alice != local || state.charlie == (foundation.Hash{}) {
			m.mu.RUnlock()
			return false
		}
		expected = state.charlie
	case 6:
		if state.charlie != local || state.alice == (foundation.Hash{}) {
			m.mu.RUnlock()
			return false
		}
		expected = state.alice
	default:
		m.mu.RUnlock()
		return false
	}
	m.mu.RUnlock()
	if expected == (foundation.Hash{}) {
		var found bool
		expected, found = m.peerTestPeerAtEndpoint(source)
		if !found {
			return false
		}
	} else if !m.peerTestEndpointApproved(expected, source) {
		return false
	}

	test.Signature = nil
	copy := test
	m.mu.Lock()
	if m.peerTests[test.Nonce] != state || !state.expires.After(m.nowLocked()) {
		m.mu.Unlock()
		return false
	}
	switch test.Message {
	case 5:
		if state.message5 != nil || (state.charlie != (foundation.Hash{}) && state.charlie != expected) {
			m.mu.Unlock()
			return false
		}
		state.message5, state.message5Source, state.message5Peer = &copy, source, expected
	case 6:
		if state.message6Received {
			m.mu.Unlock()
			return false
		}
		state.message6Received = true
		alice := state.alice
		m.mu.Unlock()
		response := test
		response.Message = 7
		_ = m.SendPeerTest(m.ctx, alice, response)
		return true
	case 7:
		if state.message7 != nil {
			m.mu.Unlock()
			return false
		}
		state.message7, state.message7Source = &copy, source
	}
	result, done := m.peerTestResultLocked(state, false)
	m.mu.Unlock()
	if done {
		m.completePeerTest(state, result)
	}
	return true
}

func (m *SSU2Manager) sendPeerTestBlock(session *ssu2TransportSession, test ssu2.PeerTestBlock) error {
	var storage [ssu2.MaxIPv4PacketLen]byte
	payload, err := ssu2.MarshalPeerTestBlock(storage[:0], test)
	if err != nil {
		return err
	}
	return m.sendSessionData(session, payload, true)
}
func (m *SSU2Manager) sendPeerTestReject(alice *ssu2TransportSession, request ssu2.PeerTestBlock, code uint8) {
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return
	}
	reject := ssu2.PeerTestBlock{Message: 4, Code: code, Nonce: request.Nonce, Timestamp: uint32(m.now().Unix()), Address: request.Address, HasHash: true}
	bobHash := bindings.LocalInfo.Hash()
	input, err := ssu2.PeerTestSignatureInput(nil, bobHash[:], alice.peer[:], reject)
	if err != nil {
		return
	}
	reject.Signature, err = m.signSSU2Control(input)
	clear(input)
	if err == nil {
		_ = m.sendPeerTestBlock(alice, reject)
	}
}

func (m *SSU2Manager) verifyPeerTest(peer, bob, alice foundation.Hash, test ssu2.PeerTestBlock) bool {
	info, known := m.routerInfo(peer)
	if !known {
		return false
	}
	input, err := ssu2.PeerTestSignatureInput(nil, bob[:], alice[:], test)
	if err != nil {
		return false
	}
	valid, verifyErr := info.Identity.Verify(input, test.Signature)
	clear(input)
	return verifyErr == nil && valid
}

func (m *SSU2Manager) peerTestEndpointApproved(peer foundation.Hash, source netip.AddrPort) bool {
	info, ok := m.routerInfo(peer)
	return ok && peerTestInfoEndpointApproved(info, source)
}

func peerTestInfoEndpointApproved(info netdb.RouterInfo, source netip.AddrPort) bool {
	if !source.IsValid() {
		return false
	}
	address, err := selectSSU2Address(info)
	if err != nil {
		return false
	}
	host, err := netip.ParseAddr(address.host)
	if err != nil {
		return false
	}
	expected := netip.AddrPortFrom(host.Unmap(), address.port)
	return expected == netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
}

func (m *SSU2Manager) peerTestPeerAtEndpoint(source netip.AddrPort) (foundation.Hash, bool) {
	if m.database == nil || !source.IsValid() {
		return foundation.Hash{}, false
	}
	_, peers := m.database.Routers().Snapshot()
	var matched foundation.Hash
	found := false
	for _, peer := range peers {
		if !peerTestInfoEndpointApproved(peer.Info, source) {
			continue
		}
		if found && matched != peer.Hash {
			return foundation.Hash{}, false
		}
		matched, found = peer.Hash, true
	}
	return matched, found
}

func (m *SSU2Manager) peerTestCharlie(alice *ssu2TransportSession, ipv4 bool) *ssu2TransportSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, session := range m.sessionsByPeer {
		if session == alice || !m.sessionActive(session) {
			continue
		}
		remote, ok := session.remoteAddr().(*net.UDPAddr)
		if ok && remote.IP.To4() != nil == ipv4 {
			return session
		}
	}
	return nil
}

func peerTestEndpointMatches(remote net.Addr, endpoint netip.AddrPort) bool {
	source, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok || endpoint.Port() < 1024 {
		return false
	}
	address := source.AddrPort().Addr()
	if !address.IsValid() || address.Is4In6() || address.Is4() != endpoint.Addr().Is4() {
		return false
	}
	if address.Is4() {
		return address == endpoint.Addr()
	}
	address16, endpoint16 := address.As16(), endpoint.Addr().As16()
	return bytes.Equal(address16[:8], endpoint16[:8])
}

// peerTestSourceMatches accepts out-of-session phases only from the Charlie
// endpoint currently authenticated in RouterInfo; the PeerTest address is
// Alice's observed endpoint and is not a substitute for the UDP source.
func peerTestSource(remote net.Addr) (netip.AddrPort, bool) {
	source, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return netip.AddrPort{}, false
	}
	endpoint := source.AddrPort()
	return endpoint, endpoint.IsValid()
}
func (m *SSU2Manager) schedulePeerTestSix(state *ssu2PeerTestState) {
	delay := min(max(m.timeout/4, 500*time.Millisecond), 3*time.Second)
	m.mu.Lock()
	if m.peerTests[state.nonce] != state || state.message6Sent || state.sixTimer != nil {
		m.mu.Unlock()
		return
	}
	state.sixTimer = time.AfterFunc(delay, func() {
		m.mu.Lock()
		if m.peerTests[state.nonce] != state || state.message6Sent || state.message4 == nil {
			m.mu.Unlock()
			return
		}
		state.message6Sent = true
		charlie, phase4 := state.charlie, *state.message4
		m.mu.Unlock()
		phase4.Message, phase4.HasHash, phase4.Signature = 6, false, nil
		_ = m.SendPeerTest(m.ctx, charlie, phase4)
	})
	m.mu.Unlock()
}

func (m *SSU2Manager) expirePeerTest(nonce uint32, state *ssu2PeerTestState) {
	m.mu.Lock()
	if m.peerTests[nonce] != state {
		m.mu.Unlock()
		return
	}
	result, done := m.peerTestResultLocked(state, true)
	if !done {
		result, done = PeerTestResult{Nonce: nonce, Outcome: PeerTestUnknown, Diagnostic: "peer test timed out"}, true
	}
	m.mu.Unlock()
	if done {
		m.completePeerTest(state, result)
	}
}

func (m *SSU2Manager) peerTestResultLocked(state *ssu2PeerTestState, final bool) (PeerTestResult, bool) {
	if state.message4 == nil {
		if final {
			return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestUnknown, Diagnostic: "missing message 4"}, true
		}
		return PeerTestResult{}, false
	}
	if state.message4.Code != 0 {
		return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestFirewalled, Diagnostic: "peer test rejected"}, true
	}
	if state.message5 != nil && len(state.message5.Signature) != 0 {
		phase3 := *state.message5
		phase3.Message = 3
		if !m.verifyPeerTest(state.charlie, state.bob, state.alice, phase3) {
			state.diagnostic = "invalid message 5 signature"
			state.message5 = nil
		}
	}
	if state.message7 != nil && len(state.message7.Signature) != 0 {
		phase4 := *state.message7
		phase4.Message, phase4.HasHash, phase4.Hash = 4, true, state.charlie
		if !m.verifyPeerTest(state.charlie, state.bob, state.alice, phase4) {
			state.diagnostic = "invalid message 7 signature"
			state.message7 = nil
		}
	}
	if state.message5 != nil && state.message7 != nil {
		diagnostic := ""
		if state.message4.Address != state.message7.Address {
			diagnostic = "Charlie observed a different endpoint"
		}
		return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestOK, Diagnostic: diagnostic}, true
	}
	if state.message5 == nil && state.message7 != nil {
		expected, observed := state.message4.Address, state.message7.Address
		if expected == observed {
			return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestFirewalled, Diagnostic: "messages 4 and 7 match; message 5 absent"}, true
		}
		if expected.Addr() == observed.Addr() {
			key := expected.Addr().String()
			evidence := m.symmetricEvidence[key]
			if evidence.endpoint == expected && evidence.observed == observed {
				evidence.count++
			} else {
				evidence = ssu2PeerTestEvidence{endpoint: expected, observed: observed, count: 1}
			}
			m.symmetricEvidence[key] = evidence
			if evidence.count >= 2 {
				return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestSymmetricNAT, Diagnostic: "confirmed symmetric NAT endpoint translation"}, true
			}
			return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestFirewalled, Diagnostic: "possible symmetric NAT; confirmation required"}, true
		}
		return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestFirewalled, Diagnostic: "message 7 IP differs from message 4"}, true
	}
	if final {
		return PeerTestResult{Nonce: state.nonce, Outcome: PeerTestUnknown, Diagnostic: "peer test timed out before message 7"}, true
	}
	return PeerTestResult{}, false
}

func (m *SSU2Manager) completePeerTest(state *ssu2PeerTestState, result PeerTestResult) {
	m.mu.Lock()
	if m.peerTests[state.nonce] == state {
		delete(m.peerTests, state.nonce)
	}
	if state.timer != nil {
		state.timer.Stop()
	}
	if state.sixTimer != nil {
		state.sixTimer.Stop()
	}
	bindings, handler := m.bindings, m.onPeerTestResult
	m.mu.Unlock()
	if bindings.LocalInfo != nil {
		switch result.Outcome {
		case PeerTestOK:
			bindings.LocalInfo.SetReachability(ReachabilityReachable)
			_ = bindings.LocalInfo.Publish(m.ctx)
		case PeerTestFirewalled, PeerTestSymmetricNAT:
			bindings.LocalInfo.SetReachability(ReachabilityFirewalled)
			_ = bindings.LocalInfo.Publish(m.ctx)
		}
	}
	if result.Outcome == PeerTestFirewalled || result.Outcome == PeerTestSymmetricNAT {
		m.maintainIntroducers()
	}
	if handler != nil {
		handler(result)
	}
}

func (m *SSU2Manager) sendSessionRequest(pending *ssu2OutboundPending, token uint64) {
	pending.parseMu.Lock()
	m.sendSessionRequestLocked(pending, token)
	pending.parseMu.Unlock()
	if pending.releaseOnExit.Load() {
		pending.releaseSensitive()
	}
}

func (m *SSU2Manager) sendSessionRequestLocked(pending *ssu2OutboundPending, token uint64) {
	m.mu.RLock()
	active := m.outbound[pending.peer] == pending && !pending.confirming
	m.mu.RUnlock()
	if !active || pending.initiator != nil {
		return
	}
	initiator, err := ssu2.NewInitiator(pending.address.static[:], pending.address.intro[:], pending.destinationID, pending.sourceID)
	if err != nil {
		m.markOutboundFailed(pending, err)
		return
	}
	pending.initiator = initiator
	m.mu.Lock()
	if m.outbound[pending.peer] != pending || pending.confirming {
		m.mu.Unlock()
		m.markOutboundFailed(pending, ErrSSU2Session)
		return
	}
	pending.phase = "session_request"
	m.mu.Unlock()
	packetNumber, err := randomPacketNumber()
	if err == nil {
		var payload []byte
		payload, err = ssu2DateTimePayload(m.now())
		if err == nil {
			var packetBuffer [ssu2.MaxIPv4PacketLen]byte
			packet, buildErr := initiator.BuildSessionRequest(packetBuffer[:], payload, packetNumber, token)
			if buildErr != nil {
				err = buildErr
			} else {
				err = m.writeTo(packet, pending.remote)
			}
			if err == nil && m.logger != nil {
				m.logger.Debug("public transport handshake phase", "transport", "SSU2", "peer", routerHashDiagnostic(pending.peer), "endpoint", pending.remote.String(), "phase", "session_request_sent")
			}
		}
	}
	if err != nil {
		m.markOutboundFailed(pending, err)
	}
}

func (m *SSU2Manager) sendSessionConfirmed(pending *ssu2OutboundPending) {
	payload, err := m.localConfirmedPayload()
	if err != nil {
		m.markOutboundFailed(pending, err)
		return
	}
	packets, err := pending.initiator.BuildSessionConfirmedFragments(m.staticPrivate, payload, ssu2.MaxIPv4PacketLen)
	if err != nil {
		m.markOutboundFailed(pending, err)
		return
	}
	send, receive, err := pending.initiator.DataCiphers(m.introKey)
	if err != nil {
		m.markOutboundFailed(pending, err)
		return
	}
	session := &ssu2TransportSession{peer: pending.peer, sendID: pending.destinationID, receiveID: pending.sourceID, remote: pending.remote, send: send, receive: receive, nextPacket: 1, fragments: make(map[uint32]*ssu2FragmentAssembly), lastActivity: m.now()}
	session.initReliability()
	installed := false
	defer func() {
		if !installed {
			session.ReleaseSensitive()
		}
	}()
	for _, packet := range packets {
		if err = m.writeTo(packet, pending.remote); err != nil {
			m.markOutboundFailed(pending, err)
			return
		}
	}
	m.mu.Lock()
	if m.outbound[pending.peer] != pending || !m.installSessionLocked(session) {
		m.mu.Unlock()
		m.markOutboundFailed(pending, ErrSSU2Session)
		return
	}
	m.finishOutboundLocked(pending, nil)
	sessionCount := len(m.sessionsByPeer)
	m.mu.Unlock()
	installed = true
	if m.metrics != nil {
		m.metrics.IncTransportConnections()
		m.metrics.SetTransportSSU2Sessions(uint64(sessionCount))
	}
	if m.logger != nil {
		m.logger.Info("authenticated public transport session established", "transport", "SSU2", "peer", routerHashDiagnostic(pending.peer), "endpoint", pending.remote.String())
	}
	_ = m.sendNewToken(session)
	m.maybeStartPeerTest(session.peer)
}

func (m *SSU2Manager) handleTokenRequest(header ssu2.LongHeader, remote net.Addr) {
	if ssu2.SameConnectionID(header.DestinationID, header.SourceID) {
		return
	}
	if key, ok := rateKeyFromAddr(remote); !ok || !m.limiter.allow(rateSSU2Control, key, uint64(m.now().UnixMilli())) {
		return
	}
	m.mu.Lock()
	if !m.runningLocked() {
		m.mu.Unlock()
		return
	}
	token, err := m.newTokenLocked(remote, header.DestinationID, header.SourceID)
	m.mu.Unlock()
	if err != nil {
		return
	}
	m.sendRetry(remote, header, token)
}

func (m *SSU2Manager) handleSessionRequest(packet []byte, remote net.Addr, header ssu2.LongHeader) {
	m.mu.Lock()
	if !m.runningLocked() || m.sessionsByID[header.DestinationID] != nil || m.inbound[header.DestinationID] != nil {
		m.mu.Unlock()
		return
	}
	if !m.consumeTokenLocked(header.Token, remote, header.DestinationID, header.SourceID) &&
		!m.consumeNewTokenLocked(header.Token, remote) {
		token, err := m.newTokenLocked(remote, header.DestinationID, header.SourceID)
		m.mu.Unlock()
		if err == nil {
			m.sendRetry(remote, header, token)
		}
		return
	}
	if len(m.inbound)+len(m.outbound) >= m.maxPending {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	if key, ok := rateKeyFromAddr(remote); !ok || !m.limiter.allow(rateSSU2Control, key, uint64(m.now().UnixMilli())) {
		return
	}
	responder, requestHeader, payload, err := ssu2.ParseSessionRequest(packet, m.staticPrivate, m.introKey)
	if err != nil || requestHeader != header || !m.timestampValid(payload) {
		return
	}
	retained := false
	defer func() {
		if !retained {
			responder.ReleaseSensitive()
		}
	}()
	createdPayload, err := ssu2SessionCreatedPayload(remote, m.now())
	if err != nil {
		return
	}
	packetNumber, err := randomPacketNumber()
	if err != nil {
		return
	}
	created, err := responder.BuildSessionCreated(make([]byte, ssu2.MaxIPv4PacketLen), createdPayload, packetNumber)
	if err != nil {
		return
	}
	pending := &ssu2InboundPending{remote: cloneUDPAddress(remote), sendID: header.SourceID, responder: responder}
	pending.reassembly = ssu2.NewConfirmedReassembler(responder)
	pending.timer = time.AfterFunc(m.timeout, func() {
		m.mu.Lock()
		if m.inbound[header.DestinationID] != pending {
			m.mu.Unlock()
			return
		}
		delete(m.inbound, header.DestinationID)
		m.mu.Unlock()
		pending.reassemblyMu.Lock()
		pending.responder.ReleaseSensitive()
		pending.reassembly.ReleaseSensitive()
		pending.reassemblyMu.Unlock()
	})
	m.mu.Lock()
	if !m.runningLocked() || m.sessionsByID[header.DestinationID] != nil || m.inbound[header.DestinationID] != nil {
		m.mu.Unlock()
		pending.timer.Stop()
		pending.reassemblyMu.Lock()
		pending.reassembly.ReleaseSensitive()
		pending.reassemblyMu.Unlock()
		return
	}
	m.inbound[header.DestinationID] = pending
	retained = true
	m.mu.Unlock()
	if err = m.writeTo(created, remote); err != nil {
		m.removeInbound(header.DestinationID, pending)
	}
}

func (m *SSU2Manager) handleSessionPacket(packet []byte, remote netip.AddrPort) {
	destinationID, err := ssu2.PeekDestinationID(packet, m.introKey)
	if err != nil {
		return
	}
	m.mu.RLock()
	pending := m.inbound[destinationID]
	session := m.sessionsByID[destinationID]
	m.mu.RUnlock()
	if pending != nil {
		m.handleSessionConfirmed(packet, pending, destinationID, ssu2PacketAddr{value: remote})
		return
	}
	if session != nil {
		m.handleDataFrom(session, packet, remote)
	}
}
func (m *SSU2Manager) handleSessionConfirmed(packet []byte, pending *ssu2InboundPending, destinationID uint64, remote net.Addr) {
	pending.reassemblyMu.Lock()
	defer pending.reassemblyMu.Unlock()
	if !sameUDPAddress(pending.remote, remote) {
		return
	}
	m.mu.RLock()
	active := m.inbound[destinationID] == pending
	m.mu.RUnlock()
	if !active {
		return
	}
	if key, ok := rateKeyFromAddr(remote); !ok || !m.limiter.allow(rateSSU2Control, key, uint64(m.now().UnixMilli())) {
		return
	}
	static, payload, complete, err := pending.reassembly.Add(packet)
	if err != nil || !complete {
		return
	}
	peer, peerIntro, err := validateSSU2ConfirmedPayload(payload, static)
	if err != nil || peer.Hash() == m.currentBindings().LocalInfo.Hash() || !m.admitSSU2Peer(peer, static, m.now()) {
		m.removeInboundHeld(destinationID, pending)
		return
	}
	send, receive, err := pending.responder.DataCiphers(peerIntro)
	if err != nil {
		m.removeInboundHeld(destinationID, pending)
		return
	}
	session := &ssu2TransportSession{peer: peer.Hash(), sendID: pending.sendID, receiveID: destinationID, remote: cloneUDPAddress(remote), send: send, receive: receive, nextPacket: 1, fragments: make(map[uint32]*ssu2FragmentAssembly), lastActivity: m.now()}
	session.initReliability()
	m.mu.Lock()
	if m.inbound[destinationID] != pending || !m.installSessionLocked(session) {
		m.mu.Unlock()
		m.removeInboundHeld(destinationID, pending)
		session.ReleaseSensitive()
		return
	}
	delete(m.inbound, destinationID)
	m.mu.Unlock()
	pending.timer.Stop()
	pending.responder.ReleaseSensitive()
	pending.reassembly.ReleaseSensitive()
	session.received.Observe(0)
	_ = m.sendACK(session)
	_ = m.sendNewToken(session)
}

func (m *SSU2Manager) removeSession(session *ssu2TransportSession) {
	m.mu.Lock()
	m.removeSessionLocked(session)
	m.mu.Unlock()
	session.ReleaseSensitive()
}

func (m *SSU2Manager) removeSessionLocked(session *ssu2TransportSession) {
	removed := false
	if m.sessionsByID[session.receiveID] == session {
		delete(m.sessionsByID, session.receiveID)
	}
	if m.sessionsByPeer[session.peer] == session {
		delete(m.sessionsByPeer, session.peer)
		removed = true
	}
	if removed && m.metrics != nil {
		m.metrics.IncTransportDisconnections()
		m.metrics.SetTransportSSU2Sessions(uint64(len(m.sessionsByPeer)))
	}
}

func (m *SSU2Manager) handleData(session *ssu2TransportSession, packet []byte) {
	remote, _ := addrPortKey(session.remoteAddr())
	m.handleDataFrom(session, packet, remote)
}

func (m *SSU2Manager) handleDataFrom(session *ssu2TransportSession, packet []byte, remote netip.AddrPort) {
	session.lifetimeMu.RLock()
	lifetimeHeld := true
	defer func() {
		if lifetimeHeld {
			session.lifetimeMu.RUnlock()
		}
	}()
	session.receiveMu.Lock()
	if session.receive == nil {
		session.receiveMu.Unlock()
		return
	}
	// The receive loop owns packet until this call returns. Open in place so
	// authenticated payloads do not require a second datagram-sized buffer.
	plaintext := packet[ssu2.ShortHeaderLen : len(packet)-ssu2.PacketTagLen]
	header, payload, err := session.receive.OpenDataTo(plaintext, packet)
	if err != nil || header.Type != ssu2.Data || header.DestinationID != session.receiveID {
		session.receiveMu.Unlock()
		return
	}
	if remote.IsValid() {
		expected, expectedOK := addrPortKey(session.remoteAddr())
		canonicalRemote := netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		if !expectedOK || expected != canonicalRemote {
			session.receiveMu.Unlock()
			m.handleCandidatePath(session, payload, net.UDPAddrFromAddrPort(canonicalRemote))
			return
		}
	}
	newPacket := session.received.ObserveNew(header.PacketNumber)
	session.receiveMu.Unlock()
	session.touch(m.now())
	terminated := false
	ackEliciting := false
	var dispatch *ssu2DispatchBatch
	defer func() {
		if dispatch != nil {
			m.releaseDispatchBatch(dispatch)
		}
	}()
	iterator := ssu2.NewBlockIterator(payload)
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return
		}
		if !ok {
			break
		}
		switch block.Type {
		case ssu2.BlockACK:
			var ranges [ssu2.MaxACKRanges]ssu2.ACKRange
			acked, err := ssu2.ParseACKRanges(block.Data, ranges[:0])
			if err != nil {
				return
			}
			session.acknowledge(acked)
		case ssu2.BlockI2NP:
			ackEliciting = true
			if !newPacket {
				continue
			}
			message, err := decodeSSU2I2NP(block.Data)
			if err != nil {
				return
			}
			dispatch, err = m.appendDispatchI2NP(dispatch, session.peer, message)
			if err != nil {
				return
			}
		case ssu2.BlockPeerTest:
			ackEliciting = true
			if !newPacket {
				continue
			}
			test, err := ssu2.ParsePeerTestBlock(block.Data)
			if err != nil {
				return
			}
			m.handleSessionPeerTest(session, test)
		case ssu2.BlockFirstFragment, ssu2.BlockFollowOnFragment:
			ackEliciting = true
			if !newPacket {
				continue
			}
			message, complete, err := session.addFragment(block.Type, block.Data, m.now())
			if err != nil {
				return
			}
			if complete {
				dispatch, err = m.appendDispatchI2NP(dispatch, session.peer, message)
				if err != nil {
					return
				}
			}
		case ssu2.BlockRelayTagRequest:
			ackEliciting = true
			if newPacket {
				m.handleRelayTagRequest(session)
			}
		case ssu2.BlockRelayTag:
			ackEliciting = true
			if newPacket {
				tag, err := ssu2.ParseRelayTagBlock(block.Data)
				if err != nil {
					return
				}
				m.handleRelayTag(session, tag)
			}
		case ssu2.BlockNewToken:
			ackEliciting = true
			if newPacket {
				token, err := ssu2.ParseNewTokenBlock(block.Data)
				if err != nil {
					return
				}
				m.storeNewToken(session, token)
			}
		case ssu2.BlockRelayRequest:
			ackEliciting = true
			if !newPacket {
				continue
			}
			if !m.limiter.allow(rateSSU2Control, rateKey(session.peer), uint64(m.now().UnixMilli())) {
				return
			}
			request, err := ssu2.ParseRelayRequestBlock(block.Data)
			if err != nil {
				return
			}
			m.handleRelayRequest(session, request)
		case ssu2.BlockRelayIntro:
			ackEliciting = true
			if !newPacket {
				continue
			}
			if !m.limiter.allow(rateSSU2Control, rateKey(session.peer), uint64(m.now().UnixMilli())) {
				return
			}
			intro, err := ssu2.ParseRelayIntroBlock(block.Data)
			if err != nil {
				return
			}
			m.handleRelayIntro(session, intro)
		case ssu2.BlockRelayResponse:
			ackEliciting = true
			if !newPacket {
				continue
			}
			if !m.limiter.allow(rateSSU2Control, rateKey(session.peer), uint64(m.now().UnixMilli())) {
				return
			}
			response, err := ssu2.ParseRelayResponseBlock(block.Data)
			if err != nil {
				return
			}
			m.handleRelayResponse(session, response)
			m.forwardRelayResponse(session, response, block.Data)
		case ssu2.BlockPathChallenge:
			ackEliciting = true
			challenge, err := ssu2.ParsePathChallengeBlock(block.Data)
			if err != nil {
				return
			}
			response, _ := ssu2.MarshalPathResponseBlock(nil, ssu2.PathResponse{Data: challenge.Data})
			_ = m.sendSessionData(session, response, false)
		case ssu2.BlockPathResponse:
			ackEliciting = true
		case ssu2.BlockAddress, ssu2.BlockDateTime, ssu2.BlockPadding:
		case ssu2.BlockTermination:
			terminated = true
			ackEliciting = true
		default:
			ackEliciting = true
		}
	}
	if dispatch != nil {
		if m.dispatchI2NPBatch(dispatch) != nil {
			return
		}
		dispatch = nil
	}
	if terminated {
		lifetimeHeld = false
		session.lifetimeMu.RUnlock()
		m.removeSession(session)
		return
	}
	if ackEliciting {
		_ = m.sendACK(session)
	}
}

func (m *SSU2Manager) handleCandidatePath(session *ssu2TransportSession, payload []byte, remote net.Addr) {
	candidate, ok := cloneUDPAddress(remote).(*net.UDPAddr)
	if !ok || candidate == nil {
		return
	}
	now := m.now()
	session.pathMu.Lock()
	current := session.candidate
	if current != nil && !current.expires.After(now) {
		clear(current.challenge[:])
		session.candidate = nil
		current = nil
	}
	if current == nil {
		var challenge [8]byte
		if _, err := rand.Read(challenge[:]); err != nil {
			session.pathMu.Unlock()
			return
		}
		current = &ssu2PathCandidate{remote: candidate, challenge: challenge, expires: now.Add(m.timeout)}
		session.candidate = current
	} else if !sameUDPAddress(current.remote, candidate) {
		session.pathMu.Unlock()
		return
	}
	challenge := current.challenge
	session.pathMu.Unlock()

	probe, err := ssu2.MarshalPathChallengeBlock(nil, ssu2.PathChallenge{Data: challenge})
	if err != nil || m.sendSessionDataTo(session, candidate, probe) != nil {
		return
	}
	iterator := ssu2.NewBlockIterator(payload)
	for {
		block, ok, err := iterator.Next()
		if err != nil || !ok {
			return
		}
		switch block.Type {
		case ssu2.BlockPathChallenge:
			request, err := ssu2.ParsePathChallengeBlock(block.Data)
			if err != nil {
				return
			}
			response, _ := ssu2.MarshalPathResponseBlock(nil, ssu2.PathResponse{Data: request.Data})
			_ = m.sendSessionDataTo(session, candidate, response)
		case ssu2.BlockPathResponse:
			response, err := ssu2.ParsePathResponseBlock(block.Data)
			if err != nil {
				return
			}
			session.pathMu.Lock()
			live := session.candidate
			valid := live != nil && live.expires.After(now) &&
				sameUDPAddress(live.remote, candidate) && hmac.Equal(live.challenge[:], response.Data[:])
			if valid {
				// The source, challenge and bounded lifetime have all been
				// authenticated; update the endpoint under the send lock.
				session.setRemote(candidate)
				clear(live.challenge[:])
				session.candidate = nil
			}
			session.pathMu.Unlock()
		}
	}
}

func (m *SSU2Manager) sendSessionDataTo(session *ssu2TransportSession, remote net.Addr, payload []byte) error {
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if !m.sessionActive(session) || session.nextPacket == 0 || session.send == nil {
		return ErrSSU2Session
	}
	packet, err := session.send.SealDataTo(session.sendPacket[:], ssu2.ShortHeader{DestinationID: session.sendID, PacketNumber: session.nextPacket, Type: ssu2.Data}, payload)
	if err != nil {
		return err
	}
	if err = m.writeTo(packet, remote); err != nil {
		return err
	}
	session.nextPacket++
	return nil
}
func (m *SSU2Manager) sendData(session *ssu2TransportSession, payload []byte) error {
	return m.sendSessionData(session, payload, true)
}

func (m *SSU2Manager) sendACK(session *ssu2TransportSession) error {
	var ranges [ssu2.MaxACKRanges]ssu2.ACKRange
	session.ackMu.Lock()
	defer session.ackMu.Unlock()
	payload := session.ackPayload[:]
	session.receiveMu.Lock()
	if session.receive == nil {
		session.receiveMu.Unlock()
		return ErrSSU2Session
	}
	ackData, err := ssu2.MarshalACKRanges(payload[3:3], session.received.RangesInto(ranges[:0]))
	session.receiveMu.Unlock()
	if err != nil {
		return err
	}
	payload[0] = ssu2.BlockACK
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(ackData)))
	return m.sendSessionData(session, payload[:3+len(ackData)], false)
}
func (m *SSU2Manager) sendSessionData(session *ssu2TransportSession, payload []byte, reliable bool) error {
	if len(payload) < 8 {
		paddingLength := max(8-len(payload)-3, 0)
		var minimumPayload [10]byte
		padded := minimumPayload[:len(payload)+3+paddingLength]
		copy(padded, payload)
		padded[len(payload)] = ssu2.BlockPadding
		binary.BigEndian.PutUint16(padded[len(payload)+1:], uint16(paddingLength))
		payload = padded
	}
	session.sendMu.Lock()
	if !m.sessionActive(session) || session.send == nil {
		session.sendMu.Unlock()
		return ErrSSU2Session
	}
	var retained *ssu2SentPacket
	if reliable {
		if len(session.sent) >= ssu2MaxTrackedPackets {
			session.sendMu.Unlock()
			return ErrSSU2Session
		}
		retained = session.retainPayload(payload, m.now())
		if retained == nil {
			session.sendMu.Unlock()
			return ErrSSU2Session
		}
	}
	packetNumber := session.nextPacket
	if packetNumber == 0 {
		session.sendMu.Unlock()
		return ErrSSU2Session
	}
	packet, err := session.send.SealDataTo(session.sendPacket[:], ssu2.ShortHeader{DestinationID: session.sendID, PacketNumber: packetNumber, Type: ssu2.Data}, payload)
	if err != nil {
		retained.release()
		session.sendMu.Unlock()
		return err
	}
	if err = m.writeTo(packet, session.remoteAddr()); err != nil {
		retained.release()
		session.sendMu.Unlock()
		return err
	}
	session.nextPacket++
	now := m.now()
	session.touch(now)
	if reliable {
		retained.sentAt = now
		session.sent[packetNumber] = retained
	}
	session.sendMu.Unlock()
	return nil
}

func (s *ssu2TransportSession) touch(now time.Time) {
	s.activityMu.Lock()
	s.lastActivity = now
	s.activityMu.Unlock()
}

func (s *ssu2TransportSession) idle(now time.Time, timeout time.Duration) bool {
	s.activityMu.Lock()
	last := s.lastActivity
	s.activityMu.Unlock()
	return last.IsZero() || now.Sub(last) >= timeout
}

func (s *ssu2TransportSession) expirePath(now time.Time) {
	s.pathMu.Lock()
	if s.candidate != nil && !s.candidate.expires.After(now) {
		clear(s.candidate.challenge[:])
		s.candidate.remote = nil
		s.candidate = nil
	}
	s.pathMu.Unlock()
}

func (m *SSU2Manager) sessionActive(session *ssu2TransportSession) bool {
	m.mu.RLock()
	active := m.runningLocked() && m.sessionsByID[session.receiveID] == session && m.sessionsByPeer[session.peer] == session
	m.mu.RUnlock()
	return active
}

func (s *ssu2TransportSession) acknowledge(ranges []ssu2.ACKRange) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for number, sent := range s.sent {
		if !sent.inUse || !acknowledgedBy(ranges, number) {
			continue
		}
		for alternate, candidate := range s.sent {
			if candidate == sent {
				delete(s.sent, alternate)
			}
		}
		sent.release()
	}
}

func acknowledgedBy(ranges []ssu2.ACKRange, packet uint32) bool {
	for _, interval := range ranges {
		if packet >= interval.Start && packet <= interval.End {
			return true
		}
	}
	return false
}

func (m *SSU2Manager) sendRetry(remote net.Addr, request ssu2.LongHeader, token uint64) {
	packetNumber, err := randomPacketNumber()
	if err != nil {
		return
	}
	payload, err := ssu2SessionCreatedPayload(remote, m.now())
	if err != nil {
		return
	}
	packet, err := ssu2.BuildRetry(make([]byte, ssu2.MaxIPv4PacketLen), m.introKey, request.SourceID, request.DestinationID, token, packetNumber, payload)
	if err == nil {
		_ = m.writeTo(packet, remote)
	}
}

func (m *SSU2Manager) localConfirmedPayload() ([]byte, error) {
	bindings := m.currentBindings()
	if bindings.LocalInfo == nil {
		return nil, ErrSSU2ManagerConfig
	}
	info := bindings.LocalInfo.Snapshot()
	valid, err := info.Verify()
	if err != nil || !valid {
		return nil, ErrSSU2ManagerConfig
	}
	staticPublic, err := ecdhPublic(m.staticPrivate)
	if err != nil || !hasSSU2Keys(info, staticPublic, m.introKey) {
		return nil, ErrSSU2ManagerConfig
	}
	data := make([]byte, 2+len(info.Bytes()))
	data[1] = 1
	copy(data[2:], info.Bytes())
	return ssu2.MarshalBlock(nil, ssu2.BlockRouterInfo, data)
}

func (m *SSU2Manager) admitSSU2Peer(peer netdb.RouterInfo, static []byte, now time.Time) bool {
	if !validSSU2RouterInfoTime(peer, uint64(now.UnixMilli())) || m.database == nil {
		return false
	}
	if current, ok := m.database.Routers().Get(peer.Hash()); ok && current.Info.Published > peer.Published {
		if !hasSSU2Static(current.Info, static) {
			return false
		}
	}
	return m.database.AdmitRouterInfo(peer, false, uint64(now.UnixMilli())) == nil
}

func (m *SSU2Manager) newTokenLocked(remote net.Addr, destinationID, sourceID uint64) (uint64, error) {
	return m.retryToken(remote, destinationID, sourceID, m.tokenBucket(m.nowLocked()))
}

func newTokenCacheKey(peer foundation.Hash, remote net.Addr, destination uint64) string {
	if remote == nil || destination == 0 {
		return ""
	}
	return string(peer[:]) + "|" + remote.String() + "|" + strconv.FormatUint(destination, 10)
}

func (m *SSU2Manager) newNewTokenLocked(remote net.Addr) (ssu2.NewToken, error) {
	token, err := m.retryToken(remote, 0, 0, m.tokenBucket(m.nowLocked()))
	if err != nil {
		return ssu2.NewToken{}, err
	}
	return ssu2.NewToken{Token: token, Expiration: uint32(m.nowLocked().Add(m.tokenLifetime).Unix())}, nil
}

func (m *SSU2Manager) consumeNewTokenLocked(token uint64, remote net.Addr) bool {
	if token == 0 {
		return false
	}
	bucket := m.tokenBucket(m.nowLocked())
	expected, err := m.retryToken(remote, 0, 0, bucket)
	if err == nil && hmac.Equal(u64Bytes(token), u64Bytes(expected)) {
		return true
	}
	if bucket == 0 {
		return false
	}
	expected, err = m.retryToken(remote, 0, 0, bucket-1)
	return err == nil && hmac.Equal(u64Bytes(token), u64Bytes(expected))
}

func (m *SSU2Manager) expireExtensions(now time.Time) {
	type renewal struct {
		peer    foundation.Hash
		session *ssu2TransportSession
	}
	var renew []renewal
	var expiredTests []struct {
		nonce uint32
		state *ssu2PeerTestState
	}
	publishChanged := false
	m.mu.Lock()
	for peer, lease := range m.relayGrants {
		if lease.expires.After(now) {
			continue
		}
		if m.introducers[lease.tag] == peer {
			delete(m.introducers, lease.tag)
		}
		delete(m.relayGrants, peer)
	}
	for peer, lease := range m.advertisedRelays {
		if !lease.expires.After(now) {
			delete(m.advertisedRelays, peer)
			delete(m.relayTagPending, peer)
			publishChanged = true
			continue
		}
		if !lease.renewing && lease.expires.Sub(now) <= m.tokenLifetime/3 {
			if session := m.sessionsByPeer[peer]; session != nil {
				lease.renewing = true
				m.advertisedRelays[peer] = lease
				m.relayTagPending[peer] = now.Add(m.timeout)
				renew = append(renew, renewal{peer: peer, session: session})
			}
		}
	}
	if publishChanged {
		m.relayRevision++
	}
	for key, lease := range m.newTokens {
		if !lease.expires.After(now) {
			delete(m.newTokens, key)
		}
	}
	for nonce, state := range m.peerTests {
		if !state.expires.After(now) {
			expiredTests = append(expiredTests, struct {
				nonce uint32
				state *ssu2PeerTestState
			}{nonce: nonce, state: state})
		}
	}
	m.mu.Unlock()
	if publishChanged {
		m.syncRelayTagPublication()
	}
	for _, item := range renew {
		if err := m.requestRelayTagOnSession(item.session); err != nil {
			m.mu.Lock()
			delete(m.relayTagPending, item.peer)
			if lease, ok := m.advertisedRelays[item.peer]; ok {
				lease.renewing = false
				m.advertisedRelays[item.peer] = lease
			}
			m.mu.Unlock()
		}
	}
	m.maintainIntroducers()
	for _, expired := range expiredTests {
		m.expirePeerTest(expired.nonce, expired.state)
	}
}

func u64Bytes(value uint64) []byte {
	var bytes [8]byte
	binary.BigEndian.PutUint64(bytes[:], value)
	return bytes[:]
}

func (m *SSU2Manager) sendNewToken(session *ssu2TransportSession) error {
	m.mu.Lock()
	if !m.runningLocked() {
		m.mu.Unlock()
		return ErrSSU2Session
	}
	token, err := m.newNewTokenLocked(session.remoteAddr())
	m.mu.Unlock()
	if err != nil {
		return err
	}
	var storage [32]byte
	payload, err := ssu2.MarshalNewTokenBlock(storage[:0], token)
	if err != nil {
		return err
	}
	return m.sendSessionData(session, payload, true)
}

func (m *SSU2Manager) storeNewToken(session *ssu2TransportSession, token ssu2.NewToken) {
	expires := time.Unix(int64(token.Expiration), 0)
	now := m.now()
	if !expires.After(now) || expires.Sub(now) > m.tokenLifetime {
		return
	}
	remote := session.remoteAddr()
	key := newTokenCacheKey(session.peer, remote, session.sendID)
	if key == "" {
		return
	}
	m.mu.Lock()
	if m.runningLocked() {
		endpoint := remote.String()
		for existingKey, lease := range m.newTokens {
			if !lease.expires.After(now) || (lease.peer == session.peer && lease.endpoint == endpoint) {
				delete(m.newTokens, existingKey)
			}
		}
		if len(m.newTokens) >= ssu2MaxNewTokens {
			evictKey := ""
			var evictExpiry time.Time
			for existingKey, lease := range m.newTokens {
				storeNewTokenSelected := evictKey == "" || lease.expires.Before(evictExpiry)
				if !storeNewTokenSelected {
					storeNewTokenSelected = (lease.expires.Equal(evictExpiry) && existingKey < evictKey)
				}
				if storeNewTokenSelected {
					evictKey, evictExpiry = existingKey, lease.expires
				}
			}
			delete(m.newTokens, evictKey)
		}
		m.newTokens[key] = ssu2NewTokenLease{peer: session.peer, endpoint: endpoint, destination: session.sendID, token: token.Token, expires: expires}
	}
	m.mu.Unlock()
}

func (m *SSU2Manager) cachedNewTokenLocked(peer foundation.Hash, remote net.Addr, destination uint64) uint64 {
	key := newTokenCacheKey(peer, remote, destination)
	lease, ok := m.newTokens[key]
	if !ok || lease.destination != destination || !lease.expires.After(m.nowLocked()) {
		if ok {
			delete(m.newTokens, key)
		}
		return 0
	}
	return lease.token
}

func (m *SSU2Manager) cachedNewTokenDestinationLocked(peer foundation.Hash, remote net.Addr) uint64 {
	for _, lease := range m.newTokens {
		if lease.peer == peer && lease.endpoint == remote.String() && lease.destination != 0 && lease.expires.After(m.nowLocked()) {
			return lease.destination
		}
	}
	return 0
}

func (m *SSU2Manager) consumeTokenLocked(token uint64, remote net.Addr, destinationID, sourceID uint64) bool {
	bucket := m.tokenBucket(m.nowLocked())
	expected, err := m.retryToken(remote, destinationID, sourceID, bucket)
	if err == nil && token == expected {
		return true
	}
	if bucket == 0 {
		return false
	}
	expected, err = m.retryToken(remote, destinationID, sourceID, bucket-1)
	return err == nil && token == expected
}

func (m *SSU2Manager) tokenBucket(now time.Time) uint64 {
	seconds := uint64(m.tokenLifetime / time.Second)

	seconds = cmp.Or(seconds, 1)

	return uint64(now.Unix()) / seconds
}

func (m *SSU2Manager) retryToken(remote net.Addr, destinationID, sourceID, bucket uint64) (uint64, error) {
	endpoint, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return 0, ErrSSU2Session
	}
	addr := endpoint.AddrPort()
	if !addr.IsValid() || addr.Port() == 0 {
		return 0, ErrSSU2Session
	}
	var ip [16]byte
	ipLength := 16
	if addr.Addr().Is4() {
		ip4 := addr.Addr().As4()
		copy(ip[:4], ip4[:])
		ipLength = 4
	} else {
		ip = addr.Addr().As16()
	}
	var fields [26]byte
	binary.BigEndian.PutUint16(fields[:2], addr.Port())
	binary.BigEndian.PutUint64(fields[2:10], destinationID)
	binary.BigEndian.PutUint64(fields[10:18], sourceID)
	binary.BigEndian.PutUint64(fields[18:26], bucket)
	mac := hmac.New(sha256.New, m.tokenSecret[:])
	_, _ = mac.Write([]byte{byte(ipLength)})
	_, _ = mac.Write(ip[:ipLength])
	_, _ = mac.Write(fields[:])
	sum := mac.Sum(nil)
	token := binary.BigEndian.Uint64(sum[:8]) | 1
	clear(sum)
	return token, nil
}

func (m *SSU2Manager) installSessionLocked(session *ssu2TransportSession) bool {
	if !m.runningLocked() || len(m.sessionsByID) >= m.maxSessions || m.sessionsByID[session.receiveID] != nil {
		return false
	}
	m.sessionsByID[session.receiveID] = session
	if m.sessionsByPeer[session.peer] == nil {
		m.sessionsByPeer[session.peer] = session
	}
	return true
}

func (m *SSU2Manager) finishOutboundLocked(pending *ssu2OutboundPending, err error) bool {
	if m.outbound[pending.peer] != pending {
		return false
	}
	if pending.timer != nil {
		pending.timer.Stop()
	}
	delete(m.outbound, pending.peer)
	endpoint, _ := addrPortKey(pending.remote)
	delete(m.outboundAddr, endpoint)
	pending.err = err
	pending.releaseOnExit.Store(true)
	close(pending.ready)
	return true
}

func (p *ssu2OutboundPending) releaseSensitive() {
	p.releaseOnce.Do(func() {
		p.parseMu.Lock()
		if p.initiator != nil {
			p.initiator.ReleaseSensitive()
			p.initiator = nil
		}
		clear(p.packet[:])
		p.parseMu.Unlock()
	})
}

func (m *SSU2Manager) markOutboundFailed(pending *ssu2OutboundPending, err error) {
	m.mu.Lock()
	m.finishOutboundLocked(pending, err)
	m.mu.Unlock()
}

func (m *SSU2Manager) failOutbound(pending *ssu2OutboundPending, err error) {
	m.markOutboundFailed(pending, err)
	pending.releaseSensitive()
}

type ssu2HandshakeError struct{ phase string }

func (e ssu2HandshakeError) Error() string {
	return fmt.Sprintf("router: SSU2 %s timeout", e.phase)
}

func (e ssu2HandshakeError) Unwrap() error { return ErrSSU2Session }

func (m *SSU2Manager) recordOutboundFailure(peer foundation.Hash, err error) {
	if m.metrics != nil {
		m.metrics.IncTransportHandshakeFailures()
	}
	if m.logger != nil {
		phase := ssu2FailurePhase(err)
		m.logger.Warn("public transport handshake failed", "transport", "SSU2", "peer", routerHashDiagnostic(peer), "phase", phase, "error", err)
	}
}

func ssu2FailurePhase(err error) string {
	if handshake, ok := errors.AsType[ssu2HandshakeError](err); ok {
		return handshake.phase + "_timeout"
	}
	switch {
	case errors.Is(err, ErrSSU2Session):
		return "session_install"
	case errors.Is(err, ErrSSU2Peer):
		return "router_info_or_endpoint"
	case errors.Is(err, ErrSSU2Introduction):
		return "introduction"
	default:
		return "handshake"
	}
}

func (m *SSU2Manager) removeInbound(destinationID uint64, pending *ssu2InboundPending) {
	m.mu.Lock()
	if m.inbound[destinationID] == pending {
		delete(m.inbound, destinationID)
	}
	m.mu.Unlock()
	pending.reassemblyMu.Lock()
	defer pending.reassemblyMu.Unlock()
	m.removeInboundHeld(destinationID, pending)
}

// removeInboundHeld is called with pending.reassemblyMu held.
func (m *SSU2Manager) removeInboundHeld(destinationID uint64, pending *ssu2InboundPending) {
	m.mu.Lock()
	if m.inbound[destinationID] == pending {
		delete(m.inbound, destinationID)
	}
	m.mu.Unlock()
	if pending.timer != nil {
		pending.timer.Stop()
	}
	pending.responder.ReleaseSensitive()
	pending.responder = nil
	pending.reassembly.ReleaseSensitive()
}

// dispatchI2NP remains the narrow single-message entry point used by direct
// callers; the live receive path always calls dispatchI2NPBatch once per UDP
// packet.
func (m *SSU2Manager) dispatchI2NP(peer foundation.Hash, message i2np.Message) error {
	batch, err := m.appendDispatchI2NP(nil, peer, message)
	if err != nil {
		return err
	}
	return m.dispatchI2NPBatch(batch)
}

func (m *SSU2Manager) runningLocked() bool {
	return m.started && m.ctx != nil && m.ctx.Err() == nil
}

func (m *SSU2Manager) currentBindings() TransportBindings {
	m.mu.RLock()
	bindings := m.bindings
	m.mu.RUnlock()
	return bindings
}

// RateLimitSnapshot returns cumulative per-source SSU2 control admission
func (m *SSU2Manager) borrowDispatchBatch() (*ssu2DispatchBatch, error) {
	m.mu.RLock()
	free, running := m.dispatchFree, m.runningLocked()
	m.mu.RUnlock()
	if free == nil {
		// Direct, non-started callers use a stack-local batch; the live path
		// always leases preallocated storage from dispatchFree.
		return &ssu2DispatchBatch{}, nil
	}
	if !running {
		return nil, ErrSSU2Session
	}
	select {
	case batch := <-free:
		return batch, nil
	case <-m.contextDone():
		return nil, ErrSSU2Session
	}
}

func (m *SSU2Manager) releaseDispatchBatch(batch *ssu2DispatchBatch) {
	if batch == nil {
		return
	}
	for index := range int(batch.count) {
		batch.items[index] = ssu2DispatchItem{}
	}
	batch.count = 0
	m.mu.RLock()
	free := m.dispatchFree
	m.mu.RUnlock()
	if free == nil {
		return
	}
	select {
	case free <- batch:
	case <-m.contextDone():
	}
}

func (m *SSU2Manager) appendDispatchI2NP(batch *ssu2DispatchBatch, peer foundation.Hash, message i2np.Message) (*ssu2DispatchBatch, error) {
	if batch == nil {
		var err error
		batch, err = m.borrowDispatchBatch()
		if err != nil || batch == nil {
			return batch, err
		}
	}
	if int(batch.count) == len(batch.items) {
		return batch, ErrSSU2Session
	}
	batch.items[batch.count] = ssu2DispatchItem{peer: peer, message: message}
	batch.count++
	return batch, nil
}

// dispatchI2NPBatch transfers a complete set of synchronous, borrowed message
// views to the bounded dispatch stage. The caller retains the receive packet
// until this returns, so HandleI2NP must not retain Payload.
func (m *SSU2Manager) dispatchI2NPBatch(batch *ssu2DispatchBatch) error {
	if batch == nil || batch.count == 0 {
		m.releaseDispatchBatch(batch)
		return nil
	}
	m.mu.RLock()
	queues := m.dispatchQueues
	running := m.runningLocked()
	m.mu.RUnlock()
	if len(queues) == 0 {
		for index := range int(batch.count) {
			if err := m.deliverI2NPRecovered(batch.items[index].peer, batch.items[index].message); err != nil {
				m.releaseDispatchBatch(batch)
				return err
			}
		}
		m.releaseDispatchBatch(batch)
		return nil
	}
	queue := queues[int(batch.items[0].peer[0])%len(queues)]
	if !running {
		m.releaseDispatchBatch(batch)
		return ErrSSU2Session
	}
	select {
	case queue <- batch:
	case <-m.contextDone():
		m.releaseDispatchBatch(batch)
		return ErrSSU2Session
	}
	select {
	case err := <-batch.done:
		m.releaseDispatchBatch(batch)
		return err
	case <-m.contextDone():
		err := <-batch.done
		m.releaseDispatchBatch(batch)
		return err
	}
}

func (m *SSU2Manager) dispatchLoop(queue chan *ssu2DispatchBatch) {
	defer m.wg.Done()
	for {
		select {
		case batch := <-queue:
			var err error
			for index := range int(batch.count) {
				if err = m.deliverI2NPRecovered(batch.items[index].peer, batch.items[index].message); err != nil {
					break
				}
			}
			batch.done <- err
		case <-m.contextDone():
			failQueuedDispatches(queue)
			return
		}
	}
}

func failQueuedDispatches(queue chan *ssu2DispatchBatch) {
	for {
		select {
		case batch := <-queue:
			batch.done <- ErrSSU2Session
		default:
			return
		}
	}
}

func (m *SSU2Manager) deliverI2NPRecovered(peer foundation.Hash, message i2np.Message) (err error) {
	defer ingress.Recover(&err, m.reporter, ingress.BoundarySSU2Packet, nil)
	return m.deliverI2NP(peer, message)
}

func (m *SSU2Manager) deliverI2NP(peer foundation.Hash, message i2np.Message) error {
	bindings := m.currentBindings()
	if bindings.HandleI2NPContext == nil {
		return ErrSSU2ManagerConfig
	}
	nowMillis := uint64(bindings.Clock.Now().UnixMilli())
	return bindings.HandleI2NPContext(m.ctx, peer, message, nowMillis, false)
}

func (m *SSU2Manager) contextDone() <-chan struct{} {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return closedSSU2Context
	}
	return ctx.Done()
}

var closedSSU2Context = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

func (m *SSU2Manager) contextErr() error {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return ErrSSU2Session
	}
	return ctx.Err()
}

func (m *SSU2Manager) writeTo(packet []byte, remote net.Addr) error {
	return m.writeToClass(packet, remote, false, 0)
}

func (m *SSU2Manager) writeRelayTo(packet []byte, remote net.Addr, flow uint64) error {
	return m.writeToClass(packet, remote, true, flow)
}

func (m *SSU2Manager) writeToClass(packet []byte, remote net.Addr, relay bool, flow uint64) error {
	if len(packet) == 0 || len(packet) > ssu2.MaxIPv4PacketLen {
		return ErrSSU2Session
	}
	endpoint, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return ErrSSU2Session
	}
	addrPort := endpoint.AddrPort()
	if !addrPort.IsValid() {
		return ErrSSU2Session
	}
	m.mu.RLock()
	free := m.egressFree
	queue := m.egressQueue
	running := m.runningLocked()
	m.mu.RUnlock()
	if !running || free == nil || queue == nil {
		if running && m.conn != nil {
			if m.metrics != nil {
				m.metrics.AddSSU2SendEnqueuedDatagrams(1)
			}
			n, err := m.conn.WriteToUDP(packet, net.UDPAddrFromAddrPort(addrPort))
			if err == nil && n == len(packet) {
				if m.metrics != nil {
					m.metrics.AddSSU2SentDatagrams(1)
					m.metrics.AddTransportSentBytes(uint64(n))
				}
				return nil
			}
			if m.metrics != nil {
				m.metrics.AddSSU2SendFailedDatagrams(1)
			}
			if err == nil {
				return ErrSSU2Session
			}
			return err
		}
		return ErrSSU2Session
	}
	var slot *ssu2EgressSlot
	select {
	case slot = <-free:
	default:
		m.ioStats.dropped.Add(1)
		if m.metrics != nil {
			m.metrics.AddSSU2SendEnqueuedDatagrams(1)
			m.metrics.AddSSU2SendQueueDrops(1)
		}
		return ErrSSU2Session
	}
	copy(slot.data[:], packet)
	slot.length = len(packet)
	slot.addr = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
	slot.zone = 0
	slot.relay = relay
	slot.flow = flow
	select {
	case queue <- slot:
		if m.metrics != nil {
			m.metrics.AddSSU2SendEnqueuedDatagrams(1)
			m.metrics.IncSSU2EgressQueueDepth()
		}
	default:
		m.ioStats.dropped.Add(1)
		slot.length = 0
		slot.relay = false
		slot.flow = 0
		clear(slot.data[:len(packet)])
		free <- slot
		if m.metrics != nil {
			m.metrics.AddSSU2SendEnqueuedDatagrams(1)
			m.metrics.AddSSU2SendQueueDrops(1)
		}
		return ErrSSU2Session
	}
	err := <-slot.done
	slot.length = 0
	slot.relay = false
	slot.flow = 0
	clear(slot.data[:len(packet)])
	select {
	case m.egressFree <- slot:
	case <-m.contextDone():
	}
	return err
}

func (m *SSU2Manager) egressLoop() {
	defer m.wg.Done()
	defer m.failQueuedEgress()
	batch, err := ssu2.NewBatch(ssu2EgressSlots, ssu2.MaxIPv4PacketLen)
	if err != nil {
		m.recordSSU2Error(err)
		_ = m.Close()
		return
	}
	packets := batch.Packets()
	target := ssu2EgressMinTarget
	timer := time.NewTimer(ssu2EgressFlush)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var slots [ssu2EgressSlots]*ssu2EgressSlot
	for {
		count, ok := m.collectEgressBatch(timer, target, &slots)
		if !ok {
			return
		}
		activeSlots := slots[:count]
		shuffleRelaySlots(activeSlots)
		for index, slot := range activeSlots {
			packets[index] = ssu2.Datagram{Data: slot.data[:], Len: slot.length, Addr: slot.addr, Zone: slot.zone}
		}
		written, writeErr := m.batchConn.WriteBatchPrefix(batch, count)
		m.recordEgressWrite(activeSlots, written)
		m.completeEgressSlots(activeSlots, written, writeErr)
		if writeErr != nil && m.contextErr() == nil && !errors.Is(writeErr, net.ErrClosed) {
			m.recordSSU2Error(writeErr)
			_ = m.Close()
			return
		}
		if count == target && target < ssu2EgressSlots {
			target++
		} else if count < target {
			target = ssu2EgressMinTarget
		}
	}
}

func (m *SSU2Manager) collectEgressBatch(timer *time.Timer, target int, slots *[ssu2EgressSlots]*ssu2EgressSlot) (int, bool) {
	select {
	case slots[0] = <-m.egressQueue:
	case <-m.contextDone():
		return 0, false
	}
	count := 1
	timer.Reset(ssu2EgressFlush)
	for count < target {
		select {
		case slots[count] = <-m.egressQueue:
			count++
		case <-timer.C:
			return count, true
		case <-m.contextDone():
			m.failEgressSlots(slots[:count])
			return 0, false
		}
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	return count, true
}

func (m *SSU2Manager) failEgressSlots(slots []*ssu2EgressSlot) {
	for _, slot := range slots {
		slot.done <- ErrSSU2Session
		if m.metrics != nil {
			m.metrics.AddSSU2SendFailedDatagrams(1)
			m.metrics.DecSSU2EgressQueueDepth()
		}
	}
}

func shuffleRelaySlots(slots []*ssu2EgressSlot) {
	for start := 0; start < len(slots); {
		if !slots[start].relay || slots[start].flow == 0 {
			start++
			continue
		}
		end := start + 1
		for end < len(slots) && slots[end].relay && slots[end].flow != 0 {
			end++
		}
		shuffleIndependentRelayRun(slots[start:end])
		start = end
	}
}

func (m *SSU2Manager) recordEgressWrite(slots []*ssu2EgressSlot, written int) {
	if written > 0 {
		m.ioStats.datagramsSent.Add(uint64(written))
		for _, slot := range slots[:written] {
			m.ioStats.bytesSent.Add(uint64(slot.length))
		}
	}
	if m.metrics == nil {
		return
	}
	m.metrics.AddSSU2SentDatagrams(uint64(written))
	if written > 1 {
		m.metrics.IncSSU2SendMultiBatches()
	}
	for _, slot := range slots[:written] {
		m.metrics.AddTransportSentBytes(uint64(slot.length))
	}
	if written < len(slots) {
		m.metrics.AddSSU2SendFailedDatagrams(uint64(len(slots) - written))
	}
}

func (m *SSU2Manager) completeEgressSlots(slots []*ssu2EgressSlot, written int, writeErr error) {
	for index, slot := range slots {
		if m.metrics != nil {
			m.metrics.DecSSU2EgressQueueDepth()
		}
		switch {
		case index < written:
			slot.done <- nil
		case writeErr != nil:
			slot.done <- writeErr
		default:
			slot.done <- ErrSSU2Session
		}
		slots[index] = nil
	}
}
func shuffleIndependentRelayRun(slots []*ssu2EgressSlot) {
	if len(slots) < 2 || len(slots) > ssu2EgressSlots {
		return
	}
	var flows [ssu2EgressSlots]uint64
	flowCount := 0
	for _, slot := range slots {
		known := false
		for index := range flowCount {
			if flows[index] == slot.flow {
				known = true
				break
			}
		}
		if !known {
			flows[flowCount] = slot.flow
			flowCount++
		}
	}
	if flowCount < 2 {
		return
	}
	for index := flowCount - 1; index > 0; index-- {
		limit := ^uint64(0) - (^uint64(0) % uint64(index+1))
		var random uint64
		var err error
		for {
			random, err = randomUint64()
			if err != nil {
				return
			}
			if random < limit {
				break
			}
		}
		swap := int(random % uint64(index+1))
		flows[index], flows[swap] = flows[swap], flows[index]
	}
	var shuffled [ssu2EgressSlots]*ssu2EgressSlot
	output := 0
	for flowIndex := range flowCount {
		for _, slot := range slots {
			if slot.flow == flows[flowIndex] {
				shuffled[output] = slot
				output++
			}
		}
	}
	copy(slots, shuffled[:len(slots)])
}

func (m *SSU2Manager) failQueuedEgress() {
	for {
		select {
		case slot := <-m.egressQueue:
			if slot != nil {
				if m.metrics != nil {
					m.metrics.DecSSU2EgressQueueDepth()
				}
				slot.done <- ErrSSU2Session
				if m.metrics != nil {
					m.metrics.AddSSU2SendFailedDatagrams(1)
				}
			}
		default:
			return
		}
	}
}

// IOStats reports SSU2 vector socket activity. These counters are updated only
// at the read and write vector boundaries.
func (m *SSU2Manager) IOStats() IOStats {
	if m == nil {
		return IOStats{}
	}
	return m.ioStats.snapshot()
}

func (m *SSU2Manager) recordSSU2Error(err error) {
	m.mu.Lock()
	if m.err == nil {
		m.err = err
	}
	m.mu.Unlock()
}

func (m *SSU2Manager) now() time.Time {
	return m.currentBindings().Clock.Now()
}

func (m *SSU2Manager) nowLocked() time.Time {
	return m.bindings.Clock.Now()
}

func (m *SSU2Manager) timestampValid(payload []byte) bool {
	iterator := ssu2.NewBlockIterator(payload)
	for {
		block, ok, err := iterator.Next()
		if err != nil || !ok {
			return false
		}
		if block.Type != ssu2.BlockDateTime {
			continue
		}
		timestamp := binary.BigEndian.Uint32(block.Data)
		delta := m.now().Unix() - int64(timestamp)
		if delta < 0 {
			delta = -delta
		}
		return time.Duration(delta)*time.Second <= m.maxClockSkew
	}
}

func ssu2DateTimeBlockTo(dst []byte, now time.Time) ([]byte, error) {
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], uint32(now.Unix()))
	return ssu2.MarshalBlock(dst, ssu2.BlockDateTime, timestamp[:])
}

func ssu2DateTimeBlock(now time.Time) ([]byte, error) {
	return ssu2DateTimeBlockTo(nil, now)
}

func ssu2DateTimePayload(now time.Time) ([]byte, error) {
	payload, err := ssu2DateTimeBlock(now)
	if err != nil {
		return nil, err
	}
	return ssu2.MarshalBlock(payload, ssu2.BlockPadding, nil)
}

func ssu2SessionCreatedPayload(remote net.Addr, now time.Time) ([]byte, error) {
	payload, err := ssu2DateTimeBlock(now)
	if err != nil {
		return nil, err
	}
	endpoint, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return nil, ErrSSU2Session
	}
	address := endpoint.AddrPort()
	if !address.IsValid() || address.Port() == 0 {
		return nil, ErrSSU2Session
	}
	var data [18]byte
	binary.BigEndian.PutUint16(data[:2], address.Port())
	if address.Addr().Is4() {
		ip := address.Addr().As4()
		copy(data[2:6], ip[:])
		return ssu2.MarshalBlock(payload, ssu2.BlockAddress, data[:6])
	}
	ip := address.Addr().As16()
	copy(data[2:], ip[:])
	return ssu2.MarshalBlock(payload, ssu2.BlockAddress, data[:])
}

// forEachSSU2I2NPFragment frames one payload at a time into caller-owned
// storage. send must consume the view synchronously before returning.
func forEachSSU2I2NPFragment(scratch []byte, message i2np.Message, send func([]byte) error) error {
	const (
		maxFirst = ssu2.MaxIPv4PacketLen - ssu2.ShortHeaderLen - ssu2.PacketTagLen - 3 - i2np.TransportHeaderLen
		maxNext  = ssu2.MaxIPv4PacketLen - ssu2.ShortHeaderLen - ssu2.PacketTagLen - 3 - 5
	)
	if len(scratch) < ssu2.MaxIPv4PacketLen {
		return ErrSSU2Session
	}
	if len(message.Payload) <= maxFirst {
		payload, err := marshalSSU2I2NPTo(scratch, message)
		if err != nil {
			return err
		}
		return send(payload)
	}
	if len(message.Payload) > i2np.I2PDMaxPayload {
		return i2np.ErrPayloadTooLarge
	}
	expiration, ok := i2np.EncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		return i2np.ErrPayloadTooLarge
	}
	firstDataLen := i2np.TransportHeaderLen + maxFirst
	first := scratch[:3+firstDataLen]
	first[0] = ssu2.BlockFirstFragment
	binary.BigEndian.PutUint16(first[1:3], uint16(firstDataLen))
	first[3] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(first[4:8], message.Header.ID)
	binary.BigEndian.PutUint32(first[8:12], expiration)
	copy(first[3+i2np.TransportHeaderLen:], message.Payload[:maxFirst])
	if err := send(first); err != nil {
		return err
	}
	for offset, number := maxFirst, uint8(1); offset < len(message.Payload); number++ {
		if number == 0 {
			return i2np.ErrPayloadTooLarge
		}
		end := min(offset+maxNext, len(message.Payload))
		dataLen := 5 + end - offset
		follow := scratch[:3+dataLen]
		follow[0] = ssu2.BlockFollowOnFragment
		binary.BigEndian.PutUint16(follow[1:3], uint16(dataLen))
		follow[3] = number << 1
		if end == len(message.Payload) {
			follow[3] |= 1
		}
		binary.BigEndian.PutUint32(follow[4:8], message.Header.ID)
		copy(follow[8:], message.Payload[offset:end])
		if err := send(follow); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func marshalSSU2I2NPTo(dst []byte, message i2np.Message) ([]byte, error) {
	if len(message.Payload) > i2np.I2PDMaxPayload {
		return nil, i2np.ErrPayloadTooLarge
	}
	expiration, ok := i2np.EncodeTransportExpiration(message.Header.Expiration)
	if !ok {
		return nil, i2np.ErrPayloadTooLarge
	}
	dataLen := i2np.TransportHeaderLen + len(message.Payload)
	frameLen := 3 + dataLen
	if len(dst) < frameLen {
		return nil, io.ErrShortBuffer
	}
	payload := dst[:frameLen]
	payload[0] = ssu2.BlockI2NP
	binary.BigEndian.PutUint16(payload[1:3], uint16(dataLen))
	payload[3] = byte(message.Header.Type)
	binary.BigEndian.PutUint32(payload[4:8], message.Header.ID)
	binary.BigEndian.PutUint32(payload[8:12], expiration)
	copy(payload[3+i2np.TransportHeaderLen:], message.Payload)
	return payload, nil
}

func decodeSSU2I2NP(data []byte) (i2np.Message, error) {
	header, err := i2np.ParseTransportHeader(data)
	if err != nil {
		return i2np.Message{}, err
	}
	// data aliases the authenticated receive batch. Dispatch completes before
	// that batch is returned to the socket, so this is a synchronous borrowed
	// payload view, not an ownership transfer.
	return i2np.Message{
		Header:  i2np.Header{Type: header.Type, ID: header.ID, Expiration: header.Expiration},
		Payload: data[i2np.TransportHeaderLen:],
	}, nil
}

func (s *ssu2TransportSession) addFragment(kind uint8, data []byte, now time.Time) (i2np.Message, bool, error) {
	s.fragmentMu.Lock()
	defer s.fragmentMu.Unlock()

	var id uint32
	var assembly *ssu2FragmentAssembly
	switch kind {
	case ssu2.BlockFirstFragment:
		header, err := i2np.ParseTransportHeader(data)
		if err != nil || len(data) == i2np.TransportHeaderLen {
			return i2np.Message{}, false, ErrSSU2Peer
		}
		id = header.ID
		assembly = s.fragments[id]
		if assembly == nil {
			if len(s.fragments) >= ssu2MaxFragmentedMessages {
				return i2np.Message{}, false, ErrSSU2Session
			}
			assembly = &ssu2FragmentAssembly{header: header, following: make(map[uint8][]byte)}
			s.fragments[id] = assembly
		} else if assembly.first != nil && (assembly.header != header || !bytes.Equal(assembly.first, data[i2np.TransportHeaderLen:])) {
			delete(s.fragments, id)
			return i2np.Message{}, false, ErrSSU2Peer
		}
		if assembly.first == nil {
			assembly.first = append([]byte(nil), data[i2np.TransportHeaderLen:]...)
			assembly.header = header
			assembly.size += len(assembly.first)
		}
	case ssu2.BlockFollowOnFragment:
		if len(data) <= 5 {
			return i2np.Message{}, false, ErrSSU2Peer
		}
		number := data[0] >> 1
		if number == 0 {
			return i2np.Message{}, false, ErrSSU2Peer
		}
		id = binary.BigEndian.Uint32(data[1:5])
		assembly = s.fragments[id]
		if assembly == nil {
			if len(s.fragments) >= ssu2MaxFragmentedMessages {
				return i2np.Message{}, false, ErrSSU2Session
			}
			assembly = &ssu2FragmentAssembly{following: make(map[uint8][]byte)}
			s.fragments[id] = assembly
		}
		if existing := assembly.following[number]; existing != nil {
			if !bytes.Equal(existing, data[5:]) {
				delete(s.fragments, id)
				return i2np.Message{}, false, ErrSSU2Peer
			}
		} else {
			assembly.following[number] = append([]byte(nil), data[5:]...)
			assembly.size += len(data) - 5
		}
		if data[0]&1 != 0 {
			if assembly.last != 0 && assembly.last != number {
				delete(s.fragments, id)
				return i2np.Message{}, false, ErrSSU2Peer
			}
			assembly.last = number
		}
	default:
		return i2np.Message{}, false, ErrSSU2Peer
	}
	assembly.updated = now
	if assembly.size > i2np.I2PDMaxPayload || assembly.first == nil || assembly.last == 0 {
		if assembly.size > i2np.I2PDMaxPayload {
			delete(s.fragments, id)
			return i2np.Message{}, false, ErrSSU2Peer
		}
		return i2np.Message{}, false, nil
	}
	payload := make([]byte, 0, assembly.size)
	payload = append(payload, assembly.first...)
	for number := uint8(1); number <= assembly.last; number++ {
		part := assembly.following[number]
		if part == nil {
			return i2np.Message{}, false, nil
		}
		payload = append(payload, part...)
	}
	if len(payload) != assembly.size {
		delete(s.fragments, id)
		return i2np.Message{}, false, ErrSSU2Peer
	}
	message := i2np.Message{
		Header:  i2np.Header{Type: assembly.header.Type, ID: assembly.header.ID, Expiration: assembly.header.Expiration},
		Payload: payload,
	}
	delete(s.fragments, id)
	return message, true, nil
}

func (s *ssu2TransportSession) expireFragments(now time.Time) {
	s.fragmentMu.Lock()
	defer s.fragmentMu.Unlock()
	for id, assembly := range s.fragments {
		if now.Sub(assembly.updated) >= ssu2FragmentLifetime {
			delete(s.fragments, id)
		}
	}
}

func validateSSU2ConfirmedPayload(payload, static []byte) (netdb.RouterInfo, []byte, error) {
	iterator := ssu2.NewBlockIterator(payload)
	first, ok, err := iterator.Next()
	validateSSU2ConfirmedPayloadRejected := err != nil || !ok || first.Type != ssu2.BlockRouterInfo || len(first.Data) < 2 || first.Data[0]&^byte(3) != 0
	if !validateSSU2ConfirmedPayloadRejected {
		validateSSU2ConfirmedPayloadRejected = first.Data[1] != 1
	}
	if validateSSU2ConfirmedPayloadRejected {
		return netdb.RouterInfo{}, nil, ErrSSU2Peer
	}
	raw := first.Data[2:]
	if first.Data[0]&2 != 0 {
		raw, err = inflateSSU2RouterInfo(raw)
		if err != nil {
			return netdb.RouterInfo{}, nil, ErrSSU2Peer
		}
	}
	info, err := netdb.ParseRouterInfo(raw)
	if err != nil {
		return netdb.RouterInfo{}, nil, ErrSSU2Peer
	}
	valid, err := info.Verify()
	intro, found := ssu2IntroForStatic(info, static)
	if err != nil || !valid || !found {
		return netdb.RouterInfo{}, nil, ErrSSU2Peer
	}
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return netdb.RouterInfo{}, nil, ErrSSU2Peer
		}
		if !ok {
			return info, intro, nil
		}
		if block.Type != ssu2.BlockOptions && block.Type != ssu2.BlockPadding && block.Type != ssu2.BlockI2NP {
			return netdb.RouterInfo{}, nil, ErrSSU2Peer
		}
	}
}

func inflateSSU2RouterInfo(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, int64(netdb.MaxRouterInfoBytes+1)))
	if err != nil {
		return nil, err
	}
	if len(raw) > netdb.MaxRouterInfoBytes {
		return nil, netdb.ErrRouterInfoTooLarge
	}
	return raw, nil
}

func validSSU2RouterInfoTime(info netdb.RouterInfo, nowMillis uint64) bool {
	return netdb.RouterInfoFresh(info, nowMillis) == nil
}

func hasSSU2Keys(info netdb.RouterInfo, static, intro []byte) bool {
	candidate, ok := ssu2IntroForStatic(info, static)
	return ok && bytes.Equal(candidate, intro)
}

func hasSSU2Static(info netdb.RouterInfo, static []byte) bool {
	_, ok := ssu2IntroForStatic(info, static)
	return ok
}

func ssu2IntroForStatic(info netdb.RouterInfo, static []byte) ([]byte, bool) {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return nil, false
		}
		if !bytes.Equal(address.TransportStyle, []byte("SSU")) && !bytes.Equal(address.TransportStyle, []byte("SSU2")) {
			continue
		}
		var advertisedStatic, intro, version []byte
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "s":
				advertisedStatic = append(advertisedStatic[:0], value...)
			case "i":
				intro = append(intro[:0], value...)
			case "v":
				version = append(version[:0], value...)
			}
		}
		decodedStatic, staticErr := foundation.DecodeI2PBase64(advertisedStatic)
		decodedIntro, introErr := foundation.DecodeI2PBase64(intro)
		ssu2IntroForStaticRejected := staticErr == nil && introErr == nil && len(decodedStatic) == 32 && len(decodedIntro) == 32 && supportsSSU2Version(string(version))
		if ssu2IntroForStaticRejected {
			ssu2IntroForStaticRejected = bytes.Equal(decodedStatic, static)
		}
		if ssu2IntroForStaticRejected {
			return decodedIntro, true
		}
	}
}

func selectSSU2Address(info netdb.RouterInfo) (ssu2PeerAddress, error) {
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil {
			return ssu2PeerAddress{}, err
		}
		if !ok {
			return ssu2PeerAddress{}, ErrSSU2Peer
		}
		if !bytes.Equal(address.TransportStyle, []byte("SSU")) && !bytes.Equal(address.TransportStyle, []byte("SSU2")) {
			continue
		}
		var host, port, static, intro, version string
		options := address.Options.Iterator()
		for {
			name, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			switch string(name) {
			case "host":
				host = string(value)
			case "port":
				port = string(value)
			case "s":
				static = string(value)
			case "i":
				intro = string(value)
			case "v":
				version = string(value)
			}
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portNumber == 0 || !supportsSSU2Version(version) || net.ParseIP(host) == nil {
			continue
		}
		staticKey, staticErr := foundation.DecodeI2PBase64([]byte(static))
		introKey, introErr := foundation.DecodeI2PBase64([]byte(intro))
		if staticErr != nil || introErr != nil || len(staticKey) != 32 || len(introKey) != 32 {
			continue
		}
		var selected ssu2PeerAddress
		selected.host, selected.port = host, uint16(portNumber)
		copy(selected.static[:], staticKey)
		copy(selected.intro[:], introKey)
		return selected, nil
	}
}

func supportsSSU2Version(version string) bool {
	for part := range strings.SplitSeq(version, ",") {
		if part == "2" {
			return true
		}
	}
	return false
}

func addrPortKey(remote net.Addr) (netip.AddrPort, bool) {
	endpoint, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return netip.AddrPort{}, false
	}
	addr := endpoint.AddrPort()
	if !addr.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), true
}

func sameUDPAddress(expected, actual net.Addr) bool {
	left, leftOK := addrPortKey(expected)
	right, rightOK := addrPortKey(actual)
	return leftOK && rightOK && left == right
}

func cloneUDPAddress(remote net.Addr) net.Addr {
	endpoint, ok := addrPortKey(remote)
	if !ok {
		return remote
	}
	return net.UDPAddrFromAddrPort(endpoint)
}

func randomConnectionIDs() (uint64, uint64, error) {
	left, err := randomUint64()
	if err != nil {
		return 0, 0, err
	}
	for right := uint64(0); right == 0 || right == left; {
		right, err = randomUint64()
		if err != nil {
			return 0, 0, err
		}
		if left != 0 && right != 0 && right != left {
			return left, right, nil
		}
	}
	return 0, 0, ErrSSU2Session
}

func randomPacketNumber() (uint32, error) {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(bytes[:]), nil
}

func randomUint64() (uint64, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(bytes[:]), nil
}

var _ TransportManager = (*SSU2Manager)(nil)
