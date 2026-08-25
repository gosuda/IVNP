package networkdatabase

import (
	"context"
	"errors"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/networking/internal/i2np"
	"sync"
)

var (
	ErrLookupResponderConfig            = errors.New("netdb: invalid lookup responder configuration")
	ErrLookupResponderFull              = errors.New("netdb: lookup responder queue is full")
	ErrLookupResponderClosed            = errors.New("netdb: lookup responder is closed")
	ErrLookupReplyEncryptionUnsupported = errors.New("netdb: encrypted lookup reply is unsupported")
)

const lookupResponderQueue = 64

// ReplySender owns the selected direct or tunnel route for a NetDB reply.
type ReplySender interface {
	SendNetDBReply(context.Context, foundation.Hash, uint32, i2np.Message) error
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
	ValidateDatabaseLookupReply(i2np.DatabaseLookupMessage) error
	WrapDatabaseLookupReply(i2np.DatabaseLookupMessage, i2np.Message) (i2np.Message, error)
}

type LookupResponderConfig struct {
	Database *Database
	Sender   ReplySender
	Local    foundation.Hash
	Now      func() uint64
	Random   func() uint32
	Wrapper  LookupReplyWrapper
}

type lookupJob struct {
	lookup i2np.DatabaseLookupMessage
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

	jobs    chan lookupJob
	done    chan struct{}
	mu      sync.Mutex
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
	return &LookupResponder{database: config.Database, sender: config.Sender, local: config.Local, now: config.Now, random: config.Random, wrapper: config.Wrapper, jobs: make(chan lookupJob, lookupResponderQueue), done: make(chan struct{})}, nil
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
	workers := parallelism.Workers(cap(r.jobs))
	r.wg.Add(workers)
	for range workers {
		go r.worker(ctx)
	}
	r.mu.Unlock()
	return nil
}

func (r *LookupResponder) Enqueue(lookup i2np.DatabaseLookupMessage) error {
	if lookup.ReplyEncrypted() {
		if r.wrapper == nil {
			return ErrLookupReplyEncryptionUnsupported
		}
		if err := r.wrapper.ValidateDatabaseLookupReply(lookup); err != nil {
			return err
		}
	}
	job := lookupJob{lookup: i2np.DatabaseLookupMessage{
		Key: lookup.Key, From: lookup.From, Flags: lookup.Flags, ReplyTunnelID: lookup.ReplyTunnelID,
		Excluded: append([]byte(nil), lookup.Excluded...), ReplyKey: append([]byte(nil), lookup.ReplyKey...),
		ReplyTags: append([]byte(nil), lookup.ReplyTags...), ReplyTagLen: lookup.ReplyTagLen,
	}}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		clearLookupJob(&job)
		return ErrLookupResponderClosed
	}
	select {
	case r.jobs <- job:
		r.mu.Unlock()
		return nil
	default:
		r.mu.Unlock()
		clearLookupJob(&job)
		return ErrLookupResponderFull
	}
}

func (r *LookupResponder) worker(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.jobs:
			err := r.respond(ctx, job.lookup)
			clearLookupJob(&job)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.mu.Lock()
				if r.err == nil {
					r.err = err
				}
				r.mu.Unlock()
			}
		}
	}
}
func clearLookupJob(job *lookupJob) {
	if job == nil {
		return
	}
	clear(job.lookup.ReplyKey)
	clear(job.lookup.ReplyTags)
	job.lookup.ReplyKey = nil
	job.lookup.ReplyTags = nil
}

func (r *LookupResponder) respond(ctx context.Context, lookup i2np.DatabaseLookupMessage) error {
	var payload []byte
	switch LookupType(lookup.LookupType()) {
	case RouterInfoLookup:
		ref, ok := r.database.Routers().Get(lookup.Key)
		if ok {
			compressed, err := CompressRouterInfo(ref.Info.Bytes())
			if err != nil {
				return err
			}
			payload, err = MarshalDatabaseStore(lookup.Key, i2np.StoreRouterInfo, compressed, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case LeaseSetLookup:
		typeID, data, ok := r.database.StoredLeaseSet(lookup.Key)
		if ok {
			var err error
			payload, err = MarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case 0: // legacy Any: prefer RouterInfo then a retained LeaseSet.
		if ref, ok := r.database.Routers().Get(lookup.Key); ok {
			compressed, err := CompressRouterInfo(ref.Info.Bytes())
			if err != nil {
				return err
			}
			payload, err = MarshalDatabaseStore(lookup.Key, i2np.StoreRouterInfo, compressed, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		} else if typeID, data, ok := r.database.StoredLeaseSet(lookup.Key); ok {
			var err error
			payload, err = MarshalDatabaseStore(lookup.Key, typeID, data, 0, foundation.Hash{}, 0)
			if err != nil {
				return err
			}
		}
	case ExplorationLookup:
	default:
		return ErrInvalidDatabaseStore
	}
	var message i2np.Message
	if len(payload) != 0 {
		message = i2np.Message{Header: i2np.Header{Type: i2np.DatabaseStore, ID: r.messageID(), Expiration: saturatingAdd(r.now(), databaseLookupEnvelopeLifetime)}, Payload: payload}
	} else {
		message = i2np.Message{Header: i2np.Header{Type: i2np.DatabaseSearchReply, ID: r.messageID(), Expiration: saturatingAdd(r.now(), databaseLookupEnvelopeLifetime)}, Payload: r.searchReply(lookup)}
	}
	if lookup.ReplyEncrypted() {
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
	return r.sender.SendNetDBReply(ctx, lookup.From, tunnelID, message)
}

func (r *LookupResponder) searchReply(lookup i2np.DatabaseLookupMessage) []byte {
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
	for {
		select {
		case job := <-r.jobs:
			clearLookupJob(&job)
		default:
			close(r.done)
			return nil
		}
	}
}
func (r *LookupResponder) Wait() error { <-r.done; r.mu.Lock(); defer r.mu.Unlock(); return r.err }
