package netdb

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
)

var (
	ErrLookupResponderConfig            = errors.New("netdb: invalid lookup responder configuration")
	ErrLookupResponderFull              = errors.New("netdb: lookup responder queue is full")
	ErrLookupResponderClosed            = errors.New("netdb: lookup responder is closed")
	ErrLookupReplyEncryptionUnsupported = errors.New("netdb: encrypted lookup reply is unsupported")
	ErrLookupReplyRoute                 = errors.New("netdb: invalid lookup reply route")
)

const (
	lookupResponderQueue                  = 64
	lookupResponderPerSource              = 4
	lookupResponderRouterInfoMaxAgeMillis = uint64(time.Hour / time.Millisecond)
)

// ReplySender owns the selected direct or tunnel route for a NetDB reply.
type ReplySender interface {
	SendNetDBReply(context.Context, foundation.Hash, uint32, foundation.I2NPMessage) error
}

// ReplyPathSource supplies the current local direct or inbound-tunnel return
// path for confirmed publication. A zero tunnel ID means direct delivery.
type ReplyPathSource interface {
	NetDBReplyPath() (gateway foundation.Hash, tunnelID uint32, ok bool)
}

// LookupReplyWrapper is the explicit encrypted-reply boundary. Validation runs
// synchronously at ingress so impossible encrypted work is never queued.
// Implementors must return an owned Garlic message; callers never downgrade to
// plaintext.
type LookupReplyWrapper interface {
	ValidateDatabaseLookupReply(foundation.I2NPDatabaseLookupMessage) error
	WrapDatabaseLookupReply(foundation.I2NPDatabaseLookupMessage, foundation.I2NPMessage) (foundation.I2NPMessage, error)
}

type LookupResponderConfig struct {
	Database *Database
	Sender   ReplySender
	Local    foundation.Hash
	Now      func() uint64
	Random   func() uint32
	Wrapper  LookupReplyWrapper
	Logger   *slog.Logger
}

type lookupJob struct {
	source foundation.Hash
	lookup foundation.I2NPDatabaseLookupMessage
}

// LookupResponder is a lifecycle-owned bounded control-plane responder. It
// copies parser views at ingress and never performs table selection or send I/O
// on an authenticated transport worker.
type LookupResponder struct {
	database *Database
	sender   ReplySender
	local    foundation.Hash
	now      func() uint64
	random   func() uint32
	wrapper  LookupReplyWrapper
	logger   *slog.Logger

	jobs        []lookupJob
	available   chan struct{}
	outstanding map[foundation.Hash]int
	running     map[foundation.Hash]bool
	total       int
	done        chan struct{}
	mu          sync.Mutex

	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	err     error
}

func NewLookupResponder(config LookupResponderConfig) (*LookupResponder, error) {
	if config.Database == nil || config.Sender == nil || config.Local == (foundation.Hash{}) || config.Now == nil || config.Random == nil {
		return nil, ErrLookupResponderConfig
	}
	return &LookupResponder{
		database: config.Database, sender: config.Sender, local: config.Local,
		now: config.Now, random: config.Random, wrapper: config.Wrapper, logger: config.Logger,
		jobs: make([]lookupJob, 0, lookupResponderQueue), available: make(chan struct{}, 1),
		outstanding: make(map[foundation.Hash]int), running: make(map[foundation.Hash]bool),
		done: make(chan struct{}),
	}, nil
}

// Start launches a CPU-scaled worker set bounded by the responder queue. It is
// safe to enqueue before Start so daemon wiring can accept ingress immediately.
func (r *LookupResponder) Start(parent context.Context) error {
	if parent ==
		nil {
		parent = context.Background()
	}

	r.mu.Lock()
	if r.closed || r.started {
		r.mu.Unlock()
		return ErrLookupResponderClosed
	}
	ctx, cancel := context.WithCancel(parent)
	r.started, r.cancel = true, cancel
	workers := parallelism.Workers(lookupResponderQueue)
	r.wg.Add(workers)
	for range workers {
		go r.worker(ctx)
	}
	r.mu.Unlock()
	return nil
}

// Enqueue admits work against the authenticated transport source. Anonymous
// Garlic and tunnel deliveries share a single budget; a direct reply must
// return to its authenticated sender. Tunnel replies name a gateway by design.
func (r *LookupResponder) Enqueue(source dataplane.RouterI2NPSource, lookup foundation.I2NPDatabaseLookupMessage) error {
	if lookup.Key == (foundation.Hash{}) {
		return nil
	}
	if lookup.From == (foundation.Hash{}) ||
		lookup.ReplyThroughTunnel() != (lookup.ReplyTunnelID != 0) ||
		(source.Direct && (source.Peer == (foundation.Hash{}) ||
			(!lookup.ReplyThroughTunnel() && lookup.From != source.Peer))) {
		return ErrLookupReplyRoute
	}
	if lookup.ReplyEncrypted() && !lookup.ReplyUsesECIESPublicKey() {
		if r.wrapper == nil {
			return ErrLookupReplyEncryptionUnsupported
		}
		if err := r.wrapper.ValidateDatabaseLookupReply(lookup); err != nil {
			return err
		}
	}
	peer := foundation.Hash{}
	if source.Direct {
		peer = source.Peer
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrLookupResponderClosed
	}
	if r.total >= lookupResponderQueue || r.outstanding[peer] >= lookupResponderPerSource {
		r.mu.Unlock()
		if r.logger != nil {
			r.logger.Debug("netdb lookup dropped", "reason", "queue_full", "key", foundation.EncodeI2PBase64(lookup.Key[:]))
		}
		return ErrLookupResponderFull
	}
	// Admission includes queued and executing work until the send returns.
	job := lookupJob{source: peer, lookup: foundation.I2NPDatabaseLookupMessage{
		Key: lookup.Key, From: lookup.From, Flags: lookup.Flags, ReplyTunnelID: lookup.ReplyTunnelID,
		Excluded: append([]byte(nil), lookup.Excluded...), ReplyKey: append([]byte(nil), lookup.ReplyKey...),
		ReplyTags: append([]byte(nil), lookup.ReplyTags...), ReplyTagLen: lookup.ReplyTagLen,
		ReplyPublicKey: append([]byte(nil), lookup.ReplyPublicKey...),
	}}
	r.jobs = append(r.jobs, job)
	r.total++
	r.outstanding[peer]++
	r.mu.Unlock()
	r.notify()
	return nil
}

func (r *LookupResponder) notify() {
	select {
	case r.available <- struct{}{}:
	default:
	}
}

// take skips sources already executing a response, so one slow peer cannot
// occupy every worker. The bounded FIFO preserves arrival order across peers.
func (r *LookupResponder) take(ctx context.Context) (lookupJob, bool) {
	for {
		if ctx.Err() != nil {
			return lookupJob{}, false
		}
		r.mu.Lock()
		for index, job := range r.jobs {
			if r.running[job.source] {
				continue
			}
			r.running[job.source] = true
			copy(r.jobs[index:], r.jobs[index+1:])
			r.jobs[len(r.jobs)-1] = lookupJob{}
			r.jobs = r.jobs[:len(r.jobs)-1]
			r.mu.Unlock()
			r.notify()
			return job, true
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return lookupJob{}, false
		case <-r.available:
		}
	}
}

func (r *LookupResponder) finish(job *lookupJob, err error) {
	clearLookupJob(job)
	r.mu.Lock()
	delete(r.running, job.source)
	if r.outstanding[job.source] == 1 {
		delete(r.outstanding, job.source)
	} else {
		r.outstanding[job.source]--
	}
	r.total--
	if err != nil && !errors.Is(err, context.Canceled) && r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	r.notify()
}

func (r *LookupResponder) worker(ctx context.Context) {
	defer r.wg.Done()
	for {
		job, ok := r.take(ctx)
		if !ok {
			return
		}
		r.finish(&job, r.respond(ctx, job.lookup))
	}
}

func clearLookupJob(job *lookupJob) {
	if job == nil {
		return
	}
	clear(job.lookup.ReplyKey)
	clear(job.lookup.ReplyTags)
	clear(job.lookup.ReplyPublicKey)
	job.lookup.ReplyKey = nil
	job.lookup.ReplyTags = nil
	job.lookup.ReplyPublicKey = nil
}

func (r *LookupResponder) respond(ctx context.Context, lookup foundation.I2NPDatabaseLookupMessage) error {
	var payload []byte
	switch LookupType(lookup.LookupType()) {
	case RouterInfoLookup:
		ref, ok := r.database.Routers().Get(lookup.Key)
		if ok && routerInfoCurrentForLookup(ref.Info, r.now()) {
			compressed, err := foundation.NetworkDatabaseCompressRouterInfo(ref.Info.Bytes())
			if err != nil {
				return err
			}
			payload, err = foundation.NetworkDatabaseMarshalDatabaseStore(lookup.Key, foundation.I2NPStoreRouterInfo, compressed, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case LeaseSetLookup:
		typeID, data, ok := r.database.StoredPublishedLeaseSet(lookup.Key, r.now())
		if ok {
			var err error
			payload, err = foundation.NetworkDatabaseMarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case 0: // legacy Any: prefer RouterInfo then a retained LeaseSet.
		if ref, ok := r.database.Routers().Get(lookup.Key); ok && routerInfoCurrentForLookup(ref.Info, r.now()) {
			compressed, err := foundation.NetworkDatabaseCompressRouterInfo(ref.Info.Bytes())
			if err != nil {
				return err
			}
			payload, err = foundation.NetworkDatabaseMarshalDatabaseStore(lookup.Key, foundation.I2NPStoreRouterInfo, compressed, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		} else if typeID, data, ok := r.database.StoredPublishedLeaseSet(lookup.Key, r.now()); ok {
			var err error
			payload, err = foundation.NetworkDatabaseMarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case ExplorationLookup:
	default:
		return foundation.NetworkDatabaseErrInvalidDatabaseStore
	}
	var message foundation.I2NPMessage
	if len(payload) != 0 {
		message = foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: r.messageID(), Expiration: saturatingAdd(r.now(), databaseLookupEnvelopeLifetime)}, Payload: payload}
	} else {
		message = foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseSearchReply, ID: r.messageID(), Expiration: saturatingAdd(r.now(), databaseLookupEnvelopeLifetime)}, Payload: r.searchReply(lookup)}
	}
	if lookup.ReplyEncrypted() && !lookup.ReplyUsesECIESPublicKey() {
		if r.wrapper == nil {
			return ErrLookupReplyEncryptionUnsupported
		}
		wrapped, err := r.wrapper.WrapDatabaseLookupReply(lookup, message)
		if err != nil {
			return err
		}
		message = wrapped
	}
	tunnelID := uint32(0)
	if lookup.ReplyThroughTunnel() {
		tunnelID = lookup.ReplyTunnelID
	}
	err := r.sender.SendNetDBReply(ctx, lookup.From, tunnelID, message)
	if r.logger != nil {
		r.logger.Debug("netdb lookup respond", "key", foundation.EncodeI2PBase64(lookup.Key[:]), "store", len(payload) != 0, "tunnel", tunnelID, "to", foundation.EncodeI2PBase64(lookup.From[:]), "err", err)
	}
	return err
}

func routerInfoCurrentForLookup(info foundation.NetworkDatabaseRouterInfo, now uint64) bool {
	return info.Published <= now && now-info.Published <= lookupResponderRouterInfoMaxAgeMillis
}

func (r *LookupResponder) searchReply(lookup foundation.I2NPDatabaseLookupMessage) []byte {
	excluded := make(map[foundation.Hash]struct{}, lookup.ExcludedCount())
	for off := 0; off < len(lookup.Excluded); off += foundation.HashLength {
		var hash foundation.Hash
		copy(hash[:], lookup.Excluded[off:off+foundation.HashLength])
		excluded[hash] = struct{}{}
	}
	var refs []RouterRef
	if LookupType(lookup.LookupType()) == ExplorationLookup {
		refs = r.database.Routers().ClosestRoutingNonFloodfillsExcludingInto(make([]RouterRef, 16), RoutingKey(lookup.Key, r.now()), excluded)
	} else {
		refs = r.database.Routers().ClosestFloodfillsExcludingInto(make([]RouterRef, 16), RoutingKey(lookup.Key, r.now()), excluded)
	}
	peers := make([]foundation.Hash, 0, 3)
	for _, ref := range refs {
		peers = append(peers, ref.Hash)
		if len(peers) == 3 {
			break
		}
	}
	payload := make([]byte, 32+1+len(peers)*foundation.HashLength+32)
	copy(payload[:32], lookup.Key[:])
	payload[32] = byte(len(peers))
	off := 33
	for _, peer := range peers {
		copy(payload[off:off+foundation.HashLength], peer[:])
		off += foundation.HashLength
	}
	copy(payload[off:], r.local[:])
	return payload
}

func (r *LookupResponder) messageID() uint32 {
	if id := r.random(); id != 0 {
		return id
	}
	return 1
}

func (r *LookupResponder) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
	for index := range r.jobs {
		clearLookupJob(&r.jobs[index])
		r.jobs[index] = lookupJob{}
	}
	r.jobs = nil
	r.outstanding = nil
	r.running = nil
	r.total = 0
	r.mu.Unlock()
	close(r.done)
	return nil
}
func (r *LookupResponder) Wait() error { <-r.done; r.mu.Lock(); defer r.mu.Unlock(); return r.err }
