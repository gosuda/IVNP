package netdb

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

var (
	ErrStoreFlooderConfig = errors.New("netdb: invalid store flooder configuration")
	ErrStoreFlooderFull   = errors.New("netdb: store flooder queue is full")
	ErrStoreFlooderClosed = errors.New("netdb: store flooder is closed")
)

const (
	storeFlooderQueue            = 64
	storeFlooderTargets          = 3
	storeFlooderTargetSnapshot   = 8
	storeFlooderRecentCapacity   = 4_096
	storeFlooderRecentLifetime   = uint64((10 * time.Minute) / time.Millisecond)
	storeFlooderThrottleWindow   = uint64((90 * time.Second) / time.Millisecond)
	storeFlooderMaxFloodsPerKey  = 3
	storeFlooderEnvelopeLifetime = uint64(time.Minute / time.Millisecond)
	storeFlooderSendTimeout      = 15 * time.Second
	storeFlooderNextLeaseWindow  = uint64((10 * time.Minute) / time.Millisecond)
	storeFlooderNextRouterWindow = uint64((45 * time.Minute) / time.Millisecond)
	storeFlooderNextTargets      = 2
)

// StoreFloodSender sends one owned DatabaseStore message to a verified
// floodfill. Implementations may retain the message until Send returns.
type StoreFloodSender interface {
	Send(context.Context, RouterRef, i2np.Message) error
}

type storeFloodEligibility interface {
	Eligible(RouterRef) bool
}

type StoreFlooderConfig struct {
	Database *Database
	Sender   StoreFloodSender
	Local    foundation.Hash
	Now      func() uint64
	Random   func() uint32
	Logger   *slog.Logger
}

type storeFloodJob struct {
	source foundation.Hash
	store  i2np.DatabaseStoreMessage
}

type storeFloodCount struct {
	until uint64
	count uint8
}

// StoreFlooder propagates newly admitted, reply-requesting stores to the three
// closest known floodfills. One worker owns duplicate suppression; network
// sends fan out only across the bounded target set.
type StoreFlooder struct {
	database *Database
	sender   StoreFloodSender
	local    foundation.Hash
	now      func() uint64
	random   func() uint32
	logger   *slog.Logger

	jobs      chan storeFloodJob
	done      chan struct{}
	mu        sync.Mutex
	start     bool
	closed    bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	recent    map[[32]byte]uint64
	keyFloods map[foundation.Hash]storeFloodCount
}

func NewStoreFlooder(config StoreFlooderConfig) (*StoreFlooder, error) {
	if config.Database == nil || config.Sender == nil || config.Local == (foundation.Hash{}) || config.Now == nil || config.Random == nil {
		return nil, ErrStoreFlooderConfig
	}
	return &StoreFlooder{
		database:  config.Database,
		sender:    config.Sender,
		local:     config.Local,
		now:       config.Now,
		random:    config.Random,
		logger:    config.Logger,
		jobs:      make(chan storeFloodJob, storeFlooderQueue),
		done:      make(chan struct{}),
		recent:    make(map[[32]byte]uint64, storeFlooderRecentCapacity),
		keyFloods: make(map[foundation.Hash]storeFloodCount, storeFlooderRecentCapacity),
	}, nil
}

func (f *StoreFlooder) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	f.mu.Lock()
	if f.closed || f.start {
		f.mu.Unlock()
		return ErrStoreFlooderClosed
	}
	ctx, cancel := context.WithCancel(parent)
	f.start, f.cancel = true, cancel
	f.wg.Add(1)
	go f.worker(ctx)
	f.mu.Unlock()
	return nil
}

// Enqueue copies one admitted store. Stores without a reply token are already
// flood propagation traffic and are never flooded again.
func (f *StoreFlooder) Enqueue(source foundation.Hash, store i2np.DatabaseStoreMessage) error {
	if store.ReplyToken == 0 || store.Key == (foundation.Hash{}) {
		return nil
	}
	if !f.database.StoreMatchesCurrent(store) {
		return nil
	}
	job := storeFloodJob{source: source, store: store}
	job.store.Data = append([]byte(nil), store.Data...)
	job.store.ReplyGateway = foundation.Hash{}
	job.store.ReplyTunnelID = 0
	job.store.ReplyToken = 0
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		clear(job.store.Data)
		return ErrStoreFlooderClosed
	}
	select {
	case f.jobs <- job:
		f.mu.Unlock()
		return nil
	default:
		f.mu.Unlock()
		clear(job.store.Data)
		return ErrStoreFlooderFull
	}
}

func (f *StoreFlooder) worker(ctx context.Context) {
	defer f.wg.Done()
	defer close(f.done)
	for {
		select {
		case <-ctx.Done():
			f.drain()
			return
		case job := <-f.jobs:
			f.flood(ctx, &job)
			clear(job.store.Data)
		}
	}
}

func (f *StoreFlooder) flood(ctx context.Context, job *storeFloodJob) {
	now := f.now()
	if !f.markNew(job.store, now) {
		return
	}
	payload, err := MarshalDatabaseStore(job.store.Key, job.store.Type, job.store.Data, 0, foundation.Hash{}, 0)
	if err != nil {
		f.logFailure(job.store.Key, foundation.Hash{}, err)
		return
	}
	messageID := cmp.Or(f.random(), uint32(1))
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.DatabaseStore, ID: messageID, Expiration: saturatingAdd(now, storeFlooderEnvelopeLifetime)},
		Payload: payload,
	}
	candidates := f.floodCandidates(job.store, now)
	targets := make([]RouterRef, 0, storeFlooderTargets)
	for _, candidate := range candidates {
		if candidate.Hash == f.local || candidate.Hash == job.source || !f.targetEligible(candidate) {
			continue
		}
		targets = append(targets, candidate)
		if len(targets) == storeFlooderTargets {
			break
		}
	}
	errs := make([]error, len(targets))
	var sends sync.WaitGroup
	for index, target := range targets {
		sends.Go(func() {
			sendCtx, cancel := context.WithTimeout(ctx, storeFlooderSendTimeout)
			errs[index] = f.sender.Send(sendCtx, target, message)
			cancel()
		})
	}
	sends.Wait()
	for index, err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) {
			f.logFailure(job.store.Key, targets[index].Hash, err)
		}
	}
}

func (f *StoreFlooder) targetEligible(target RouterRef) bool {
	eligibility, ok := f.sender.(storeFloodEligibility)
	return !ok || eligibility.Eligible(target)
}

func (f *StoreFlooder) markNew(store i2np.DatabaseStoreMessage, now uint64) bool {
	hash := sha256.New()
	_, _ = hash.Write(store.Key[:])
	_, _ = hash.Write([]byte{byte(store.Type)})
	_, _ = hash.Write(store.Data)
	var fingerprint [32]byte
	hash.Sum(fingerprint[:0])
	if until := f.recent[fingerprint]; until > now {
		return false
	}
	if len(f.recent) >= storeFlooderRecentCapacity {
		var oldestKey [32]byte
		oldestUntil := ^uint64(0)
		for key, until := range f.recent {
			if until <= now {
				delete(f.recent, key)
				continue
			}
			if until < oldestUntil {
				oldestKey, oldestUntil = key, until
			}
		}
		if len(f.recent) >= storeFlooderRecentCapacity {
			delete(f.recent, oldestKey)
		}
	}
	f.recent[fingerprint] = saturatingAdd(now, storeFlooderRecentLifetime)
	count := f.keyFloods[store.Key]
	if count.until <= now {
		count = storeFloodCount{until: saturatingAdd(now, storeFlooderThrottleWindow)}
	}
	count.count++
	f.keyFloods[store.Key] = count
	if len(f.keyFloods) > storeFlooderRecentCapacity {
		var oldestKey foundation.Hash
		oldestUntil := ^uint64(0)
		for key, current := range f.keyFloods {
			if current.until <= now {
				delete(f.keyFloods, key)
				continue
			}
			if current.until < oldestUntil {
				oldestKey, oldestUntil = key, current.until
			}
		}
		if len(f.keyFloods) > storeFlooderRecentCapacity {
			delete(f.keyFloods, oldestKey)
		}
	}
	return count.count <= storeFlooderMaxFloodsPerKey
}

func (f *StoreFlooder) floodCandidates(store i2np.DatabaseStoreMessage, now uint64) []RouterRef {
	current := f.database.FloodTargetsAt(make([]RouterRef, storeFlooderTargetSnapshot), store.Key, now)
	candidates := append(make([]RouterRef, 0, len(current)+storeFlooderNextTargets), current...)
	if !storeNeedsNextRoutingKey(store, now) {
		return candidates
	}
	until := timeUntilUTCMidnight(now)
	next := f.database.FloodTargetsAt(make([]RouterRef, storeFlooderNextTargets), store.Key, saturatingAdd(now, until+1))
	for _, candidate := range next {
		duplicate := false
		for _, current := range candidates {
			if current.Hash == candidate.Hash {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func storeNeedsNextRoutingKey(store i2np.DatabaseStoreMessage, now uint64) bool {
	until := timeUntilUTCMidnight(now)
	if store.Type == i2np.StoreRouterInfo {
		return until < storeFlooderNextRouterWindow
	}
	if until >= storeFlooderNextLeaseWindow {
		return false
	}
	var latest uint64
	var err error
	switch store.Type {
	case i2np.StoreLeaseSet:
		var set LeaseSet
		set, err = ParseLeaseSet(store.Data)
		if err == nil {
			_, latest, err = legacyLeaseRange(set)
		}
	case i2np.StoreLeaseSet2:
		var set LeaseSet2
		set, err = ParseLeaseSet2(store.Data)
		if err == nil {
			_, latest, err = leaseSet2Range(set)
		}
	case i2np.StoreMetaLeaseSet:
		var set MetaLeaseSet
		set, err = ParseMetaLeaseSet(store.Data)
		if err == nil {
			_, latest, err = metaLeaseSetRange(set)
		}
	case i2np.StoreEncryptedLeaseSet:
		var set EncryptedLeaseSet
		set, err = ParseEncryptedLeaseSet(store.Data)
		if err == nil {
			latest = (uint64(set.Published) + uint64(set.Expires)) * 1000
		}
	default:
		return false
	}
	return err == nil && latest > saturatingAdd(now, until)
}

func timeUntilUTCMidnight(now uint64) uint64 {
	current := time.UnixMilli(int64(now)).UTC()
	year, month, day := current.Date()
	next := time.Date(year, month, day+1, 0, 0, 0, 0, time.UTC)
	nextMillis := uint64(next.UnixMilli())
	if nextMillis <= now {
		return 0
	}
	return nextMillis - now
}

func (f *StoreFlooder) logFailure(key, target foundation.Hash, err error) {
	if f.logger != nil {
		f.logger.Debug("floodfill store propagation failed", "key", foundation.EncodeI2PBase64(key[:]), "target", foundation.EncodeI2PBase64(target[:]), "error", err)
	}
}

func (f *StoreFlooder) drain() {
	for {
		select {
		case job := <-f.jobs:
			clear(job.store.Data)
		default:
			return
		}
	}
}

func (f *StoreFlooder) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	if f.cancel != nil {
		f.cancel()
	} else {
		close(f.done)
	}
	f.mu.Unlock()
	f.wg.Wait()
	clear(f.recent)
	clear(f.keyFloods)
	return nil
}

func (f *StoreFlooder) Wait() error {
	if f == nil {
		return ErrStoreFlooderClosed
	}
	<-f.done
	return nil
}
