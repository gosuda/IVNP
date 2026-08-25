package netdb

import "cmp"

import (
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"log/slog"
	"sync"
)

const (
	PublicationConfirmTimeout uint64 = 30_000
	publicationRecentLifetime uint64 = 10 * 60_000
	publicationTargetSnapshot        = 8
	PublicationFloodfillK            = 3
)

var ErrPublicationTokenExhausted = errors.New("netdb: publication token space exhausted")

// ConfirmedPublisher is a NetDB producer that advances only after a matching
// DeliveryStatus acknowledgement.
type ConfirmedPublisher interface {
	Maintain(context.Context) (int, error)
	HandleDeliveryStatus(i2np.DeliveryStatusMessage) bool
}

type publicationTokenOwner func(i2np.DeliveryStatusMessage) bool

// PublicationTokenRegistry is the single bounded allocation domain for every
// NetDB publication producer. Tokens keep their high bit clear, leaving the
// high-bit domain available to tunnel health probes.
type PublicationTokenRegistry struct {
	mu     sync.Mutex
	now    func() uint64
	random func() uint32
	active map[uint32]publicationTokenOwner
	recent map[uint32]uint64
	closed bool
}

func NewPublicationTokenRegistry(now func() uint64, random func() uint32) *PublicationTokenRegistry {
	if now == nil {
		now = func() uint64 { return 0 }
	}
	if random ==
		nil {
		random = func() uint32 { return 1 }
	}

	return &PublicationTokenRegistry{now: now, random: random, active: make(map[uint32]publicationTokenOwner), recent: make(map[uint32]uint64)}
}

func (r *PublicationTokenRegistry) allocate(owner func(uint32) publicationTokenOwner) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrPublicationTokenExhausted
	}
	now := r.now()
	r.expireLocked(now)
	candidate := r.random() &^ (uint32(1) << 31)
	for range 1024 {
		if candidate != 0 {
			if _, live := r.active[candidate]; !live {
				if _, recent := r.recent[candidate]; !recent {
					r.active[candidate] = owner(candidate)
					return candidate, nil
				}
			}
		}
		candidate++
		candidate &= ^(uint32(1) << 31)

		candidate = cmp.Or(candidate,
			1)

	}
	return 0, ErrPublicationTokenExhausted
}
func (r *PublicationTokenRegistry) retire(token uint32) {
	if token == 0 {
		return
	}
	r.mu.Lock()
	if _, exists := r.active[token]; exists {
		delete(r.active, token)
		r.recent[token] = saturatingAdd(r.now(), publicationRecentLifetime)
	}
	r.mu.Unlock()
}
func (r *PublicationTokenRegistry) expireLocked(now uint64) {
	for token, expiry := range r.recent {
		if expiry <= now {
			delete(r.recent, token)
		}
	}
}
func (r *PublicationTokenRegistry) HandleDeliveryStatus(status i2np.DeliveryStatusMessage) bool {
	if status.MessageID == 0 || status.MessageID&(uint32(1)<<31) != 0 {
		return false
	}
	r.mu.Lock()
	owner := r.active[status.MessageID]
	r.mu.Unlock()
	if owner == nil || !owner(status) {
		return false
	}
	r.retire(status.MessageID)
	return true
}
func (r *PublicationTokenRegistry) Close() {
	r.mu.Lock()
	r.closed = true
	clear(r.active)
	clear(r.recent)
	r.mu.Unlock()
}

type publicationAttempt struct {
	token            uint32
	target           RouterRef
	sentAt, deadline uint64
}

type confirmedPublication struct {
	database   *Database
	sender     LeaseSetPublishSender
	route      ReplyPathSource
	registry   *PublicationTokenRegistry
	now        func() uint64
	random     func() uint32
	key        ivnp.Hash
	typeID     i2np.StoreType
	preferred  []ivnp.Hash
	data       []byte
	generation uint64
	targets    []RouterRef
	nextTarget int
	attempts   map[uint32]publicationAttempt
	confirmed  int
	nextRetry  uint64
	logger     *slog.Logger
	mu         sync.Mutex
}

func newConfirmedPublication(database *Database, sender LeaseSetPublishSender, route ReplyPathSource, registry *PublicationTokenRegistry, now func() uint64, random func() uint32, key ivnp.Hash, typeID i2np.StoreType, preferred []ivnp.Hash, logger *slog.Logger) *confirmedPublication {

	if registry == nil {
		registry = NewPublicationTokenRegistry(now,

			random)
	}
	return &confirmedPublication{database: database, sender: sender, route: route, registry: registry, now: now, random: random, key: key, typeID: typeID, preferred: append([]ivnp.Hash(nil), preferred...), attempts: make(map[uint32]publicationAttempt), logger: logger}
}

func (p *confirmedPublication) replace(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if string(p.data) == string(data) {
		return
	}
	for token := range p.attempts {
		p.registry.retire(token)
	}
	clear(p.attempts)
	p.data = append(p.data[:0], data...)
	p.generation++
	p.targets = nil
	p.nextTarget = 0
	p.confirmed = 0
	p.nextRetry = 0
}

func (p *confirmedPublication) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	for token := range p.attempts {
		p.registry.retire(token)
	}
	clear(p.attempts)
	clear(p.data)
	p.targets = nil
	p.mu.Unlock()
}

func (p *confirmedPublication) maintain(ctx context.Context, force bool) (int, error) {

	if ctx == nil {
		ctx = context.
			Background()
	}
	now := p.now()
	p.mu.Lock()
	maintainSelected := len(p.data) == 0
	if !maintainSelected {
		maintainSelected = (!force && p.nextRetry != 0 && now < p.nextRetry)
	}
	if maintainSelected {
		p.mu.Unlock()
		return 0, nil
	}
	for token, attempt := range p.attempts {
		if attempt.deadline <= now {
			delete(p.attempts, token)
			p.registry.retire(token)
			if p.database != nil && p.database.metrics != nil {
				p.database.metrics.IncPublicationTimeouts()
			}
			if p.logger != nil {
				p.logger.Warn("netdb publication confirmation timeout", "store_type", uint8(p.typeID), "target", ivnp.EncodeI2PBase64(attempt.target.Hash[:]), "generation", p.generation, "elapsed_ms", now-attempt.sentAt)
			}
		}
	}
	if len(p.attempts) == 0 && p.confirmed < PublicationFloodfillK && len(p.targets) != 0 && p.nextTarget >= len(p.targets) && p.nextRetry <= now {
		p.targets = nil
		p.nextTarget = 0
	}
	if p.targets == nil {
		p.targets = p.snapshotTargets()
	}
	p.mu.Unlock()

	type publicationSend struct {
		token      uint32
		target     RouterRef
		message    i2np.Message
		generation uint64
	}
	sent := 0
	var first error
	stop := false
	for !stop {
		batch := make([]publicationSend, 0, PublicationFloodfillK)
		for len(batch) < PublicationFloodfillK {
			if err := ctx.Err(); err != nil {
				if first == nil {
					first = err
				}

				stop = true
				break
			}
			p.mu.Lock()
			if p.confirmed+len(p.attempts) >= PublicationFloodfillK || p.nextTarget >= len(p.targets) {
				p.nextRetry = saturatingAdd(now, PublicationConfirmTimeout)
				p.mu.Unlock()
				break
			}
			target := p.targets[p.nextTarget]
			p.nextTarget++
			generation := p.generation
			data := p.data
			p.mu.Unlock()

			token, err := p.registry.allocate(func(token uint32) publicationTokenOwner {
				return func(status i2np.DeliveryStatusMessage) bool {
					return p.confirm(token, status, generation)
				}
			})
			if err != nil {
				if first == nil {
					first =
						err
				}

				stop = true
				break
			}
			gateway, tunnelID, ok := p.replyPath()
			if !ok {
				p.registry.retire(token)
				if first ==
					nil {
					first = ErrInvalidReplyRoute

				}

				continue
			}
			payload, err := MarshalDatabaseStore(p.key, p.typeID, data, token, gateway, tunnelID)
			if err != nil {
				p.registry.retire(token)
				if first == nil {
					first = err
				}

				continue
			}
			message := i2np.Message{Header: i2np.Header{Type: i2np.DatabaseStore, ID: p.messageID(), Expiration: saturatingAdd(now, leaseSetPublicationEnvelopeLifetime)}, Payload: payload}
			p.mu.Lock()
			if p.generation == generation {
				p.attempts[token] = publicationAttempt{token: token, target: target, sentAt: now, deadline: saturatingAdd(now, PublicationConfirmTimeout)}
			}
			p.mu.Unlock()
			if p.database != nil && p.database.metrics != nil {
				p.database.metrics.IncPublicationAttempts()
			}
			if p.logger != nil {
				p.logger.Info("netdb publication attempt", "store_type", uint8(p.typeID), "target", ivnp.EncodeI2PBase64(target.Hash[:]), "generation", generation, "reply_via_tunnel", tunnelID != 0)
			}
			batch = append(batch, publicationSend{token: token, target: target, message: message, generation: generation})
		}
		if len(batch) == 0 {
			break
		}
		results := make([]error, len(batch))
		var group sync.WaitGroup
		group.Add(len(batch))
		for index := range batch {
			go func() {
				defer group.Done()
				results[index] = p.sender.Send(ctx, batch[index].target, batch[index].message)
			}()
		}
		group.Wait()
		for index, err := range results {
			work := batch[index]
			if err == nil {
				sent++
				continue
			}
			p.mu.Lock()
			delete(p.attempts, work.token)
			p.mu.Unlock()
			p.registry.retire(work.token)
			if first == nil {
				first = err
			}

			if p.database != nil && p.database.metrics != nil {
				p.database.metrics.IncPublicationSendFailures()
			}
			if p.logger != nil {
				p.logger.Warn("netdb publication send failed", "store_type", uint8(p.typeID), "target", ivnp.EncodeI2PBase64(work.target.Hash[:]), "generation", work.generation, "error", err)
			}
		}
	}
	return sent, first
}

func (p *confirmedPublication) snapshotTargets() []RouterRef {
	targets := make([]RouterRef, 0, publicationTargetSnapshot+len(p.preferred))
	for _, hash := range p.preferred {
		ref, ok := p.database.Routers().Get(hash)
		if !ok || !ref.Floodfill || !publicationTargetEligible(p.sender, ref) {
			continue
		}
		targets = append(targets, ref)
	}
	for _, candidate := range p.database.FloodTargetsAt(make([]RouterRef, publicationTargetSnapshot), p.key, p.now()) {
		duplicate := false
		for _, existing := range targets {
			if existing.Hash == candidate.Hash {
				duplicate = true
				break
			}
		}
		if !duplicate && publicationTargetEligible(p.sender, candidate) {
			targets = append(targets, candidate)
		}
	}
	return targets
}

func publicationTargetEligible(sender LeaseSetPublishSender, target RouterRef) bool {
	eligibility, ok := sender.(leaseSetTargetEligibility)
	return !ok || eligibility.Eligible(target)
}

func (p *confirmedPublication) confirm(token uint32, status i2np.DeliveryStatusMessage, generation uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	attempt, ok := p.attempts[uint32(token)]
	if !ok || p.generation != generation || status.Timestamp < attempt.sentAt || status.Timestamp > attempt.deadline {
		return false
	}
	delete(p.attempts, uint32(token))
	p.confirmed++
	if p.database != nil && p.database.metrics != nil {
		switch p.typeID {
		case i2np.StoreRouterInfo:
			p.database.metrics.IncPublicationRouterInfoSuccesses()
		case i2np.StoreLeaseSet2, i2np.StoreEncryptedLeaseSet:
			p.database.metrics.IncPublicationLeaseSet2Successes()
		}
	}
	if p.logger != nil {
		p.logger.Info("netdb publication confirmed", "store_type", uint8(p.typeID), "target", ivnp.EncodeI2PBase64(attempt.target.Hash[:]), "generation", generation, "latency_ms", status.Timestamp-attempt.sentAt)
	}
	return true
}
func (p *confirmedPublication) replyPath() (ivnp.Hash, uint32, bool) {
	if p.route == nil {
		return ivnp.Hash{}, 0, false
	}
	return p.route.NetDBReplyPath()
}
func (p *confirmedPublication) messageID() uint32 {
	if id := p.random(); id != 0 {
		return id
	}
	return 1
}
func (p *confirmedPublication) handle(status i2np.DeliveryStatusMessage) bool {
	return p.registry.HandleDeliveryStatus(status)
}

func (p *confirmedPublication) confirmationCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.confirmed
}
