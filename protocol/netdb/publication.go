package netdb

import (
	"context"
	"errors"
	"gosuda.org/ivnp"
	"gosuda.org/ivnp/internal/parallelism"
	"gosuda.org/ivnp/protocol/i2np"
	"log/slog"
	"sync"
	"time"
)

var ErrLeaseSetPublisherConfig = errors.New("netdb: invalid LeaseSet publisher configuration")

const (
	leaseSetPublicationEnvelopeLifetime = 60_000
	leaseSetPublicationRetryDelay       = 1_000
)

// InboundLeaseSource supplies the currently usable inbound leases. It is kept
// deliberately independent of tunnel implementations so publication can be
// driven by any circuit owner. Returned leases are copied before retention.
type InboundLeaseSource interface {
	CurrentInboundLeases(nowMillis uint64) []Lease
}

// InboundLeaseSourceFunc adapts a function to an InboundLeaseSource.
type InboundLeaseSourceFunc func(nowMillis uint64) []Lease

func (f InboundLeaseSourceFunc) CurrentInboundLeases(nowMillis uint64) []Lease {
	return f(nowMillis)
}

// LeaseSetPublishSender sends a DatabaseStore to a floodfill peer. Distinct
// targets may be sent concurrently. The message payload is borrowed and is
// valid only until Send returns; a sender which queues work must retain a copy.
type LeaseSetPublishSender interface {
	Send(context.Context, RouterRef, i2np.Message) error
}

// LeaseSetPublishSenderFunc adapts a function to a LeaseSetPublishSender.
type LeaseSetPublishSenderFunc func(context.Context, RouterRef, i2np.Message) error

func (f LeaseSetPublishSenderFunc) Send(ctx context.Context, peer RouterRef, message i2np.Message) error {
	return f(ctx, peer, message)
}

type leaseSetTargetEligibility interface {
	Eligible(RouterRef) bool
}

// LeaseSetPublisherConfig supplies one local LeaseSet producer and the narrow
// interfaces needed to publish it. Exactly one of Local and Local2 must be
// supplied. Local is retained only for a remote legacy interoperability
// identity; newly-created local Destinations use Local2.
type LeaseSetPublisherConfig struct {
	Local         *LocalLeaseSet
	Local2        *LocalLeaseSet2
	Encrypted     *LocalEncryptedLeaseSet
	Database      *Database
	InboundLeases InboundLeaseSource
	Sender        LeaseSetPublishSender
	// Discovery iteratively learns floodfills near the daily routing key before
	// and during publication. Publication still proceeds while discovery runs.
	Discovery        *RequestManager
	EncryptionKey    []byte
	SigningKey       []byte
	Sign             func([]byte) ([]byte, error)
	Now              func() uint64
	Random           func() uint32
	FloodfillLimit   int
	RepublishBefore  uint64
	PreferredTargets []ivnp.Hash
	// Registry and ReplyPath enable DeliveryStatus-confirmed publication. They
	// are supplied once by the daemon and shared with RouterInfo publication.
	Registry  *PublicationTokenRegistry
	ReplyPath ReplyPathSource
	Logger    *slog.Logger
}

// LeaseSetPublisher refreshes local inbound leases and publishes their signed
// legacy LeaseSet to the closest floodfills. It performs no background work;
// callers invoke Maintain from their maintenance loop.
type LeaseSetPublisher struct {
	local           *LocalLeaseSet
	local2          *LocalLeaseSet2
	encrypted       *LocalEncryptedLeaseSet
	database        *Database
	inboundLeases   InboundLeaseSource
	sender          LeaseSetPublishSender
	discovery       *RequestManager
	encryptionKey   []byte
	signingKey      []byte
	sign            func([]byte) ([]byte, error)
	now             func() uint64
	random          func() uint32
	floodfillLimit  int
	republishBefore uint64
	confirmed       *confirmedPublication
	storeType       i2np.StoreType
	hash            ivnp.Hash

	mu               sync.Mutex
	leases           []Lease
	storePayload     []byte // immutable signed LeaseSet bytes, not a Store envelope
	expiresAt        uint64
	nextPublication  uint64
	discoveryResult  <-chan LookupResult
	discoveryTargets []ivnp.Hash
	discoveryDay     uint64
	discoveryHash    ivnp.Hash
	discoveryRetryAt uint64
	closed           bool
}

// NewLeaseSetPublisher validates and owns the publication configuration. Its
// key slices are copied; the signing callback remains owned by its caller.
func NewLeaseSetPublisher(config LeaseSetPublisherConfig) (*LeaseSetPublisher, error) {
	if ((config.Local != nil) == (config.Local2 != nil) && config.Encrypted == nil) || (config.Encrypted != nil && (config.Local != nil || config.Local2 != nil)) || config.Database == nil || config.InboundLeases == nil || config.Sender == nil || (config.Encrypted == nil && config.Sign == nil) || config.Now == nil || config.Random == nil || config.FloodfillLimit < 1 {
		return nil, ErrLeaseSetPublisherConfig
	}
	storeType := i2np.StoreLeaseSet
	var hash ivnp.Hash
	if config.Local != nil {
		if len(config.EncryptionKey) != 256 {
			return nil, ErrInvalidKeyLength
		}
		identitySnapshot, ok := config.Local.Snapshot(0)
		if !ok {
			return nil, ErrLeaseSetPublisherConfig
		}
		signingLen, ok := identitySnapshot.Identity.SigningKeyType().PublicKeyLen()
		if !ok || len(config.SigningKey) != signingLen {
			return nil, ErrInvalidKeyLength
		}
		hash = config.Local.Hash()
	} else if config.Local2 != nil {
		storeType = i2np.StoreLeaseSet2
		hash = config.Local2.Hash()
	} else {
		storeType = i2np.StoreEncryptedLeaseSet
		var err error
		hash, err = config.Encrypted.Hash(time.UnixMilli(int64(config.Now())))
		if err != nil {
			return nil, err
		}
	}
	publisher := &LeaseSetPublisher{
		local:           config.Local,
		local2:          config.Local2,
		encrypted:       config.Encrypted,
		database:        config.Database,
		inboundLeases:   config.InboundLeases,
		sender:          config.Sender,
		discovery:       config.Discovery,
		encryptionKey:   append([]byte(nil), config.EncryptionKey...),
		signingKey:      append([]byte(nil), config.SigningKey...),
		sign:            config.Sign,
		now:             config.Now,
		random:          config.Random,
		floodfillLimit:  config.FloodfillLimit,
		republishBefore: config.RepublishBefore,
		storeType:       storeType,
		hash:            hash,
	}
	if config.ReplyPath != nil {
		publisher.confirmed = newConfirmedPublication(config.Database, config.Sender, config.ReplyPath, config.Registry, config.Now, config.Random, hash, storeType, config.PreferredTargets, config.Logger)
	}
	return publisher, nil
}

// Maintain refreshes leases from the configured source, removes stale leases,
// and republishes when a changed snapshot, retry deadline, or renewal deadline
// requires it.
func (p *LeaseSetPublisher) Maintain(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, nil
	}
	defer p.mu.Unlock()
	return p.publish(ctx, false)
}

// Publish refreshes leases and sends the current snapshot immediately. An
// unchanged snapshot reuses its signed canonical DatabaseStore payload.
func (p *LeaseSetPublisher) Publish(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, nil
	}
	defer p.mu.Unlock()
	return p.publish(ctx, true)
}

// Confirmed reports whether at least one floodfill acknowledged the current
// immutable LeaseSet generation.
func (p *LeaseSetPublisher) Confirmed() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	confirmed := p.confirmed
	closed := p.closed
	p.mu.Unlock()
	return !closed && confirmed != nil && confirmed.confirmationCount() > 0
}

// Close retires outstanding publication tokens and releases all copied
// signing/encryption material and any owned encrypted LeaseSet policy.
func (p *LeaseSetPublisher) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	clear(p.leases)
	clear(p.storePayload)
	clear(p.encryptionKey)
	clear(p.signingKey)
	p.leases, p.storePayload = nil, nil
	p.encryptionKey, p.signingKey = nil, nil
	p.sign = nil
	p.local, p.local2 = nil, nil
	encrypted := p.encrypted
	p.encrypted = nil
	p.nextPublication, p.expiresAt = 0, 0
	p.discovery = nil
	p.discoveryResult = nil
	p.discoveryTargets = nil
	confirmed := p.confirmed
	p.confirmed = nil
	p.mu.Unlock()
	confirmed.close()
	encrypted.ReleaseSensitive()
}

// ReleaseSensitive is the sensitive-owner spelling of Close.
func (p *LeaseSetPublisher) ReleaseSensitive() { p.Close() }

func (p *LeaseSetPublisher) publish(ctx context.Context, force bool) (int, error) {
	now := p.now()
	inbound := p.inboundLeases.CurrentInboundLeases(now)
	var (
		leases    []Lease
		expiresAt uint64
	)
	if p.local2 != nil || p.encrypted != nil {
		local2 := p.local2
		if p.encrypted != nil {
			local2 = p.encrypted.inner
			hash, err := p.encrypted.Hash(time.UnixMilli(int64(now)))
			if err != nil {
				return 0, err
			}
			if hash != p.hash {
				p.hash = hash
				p.storePayload = nil
				p.leases = nil
				if p.confirmed != nil {
					p.confirmed = newConfirmedPublication(p.database, p.sender, p.confirmed.route, p.confirmed.registry, p.now, p.random, hash, p.storeType, p.confirmed.preferred, p.confirmed.logger)
				}
			}
		}
		if err := local2.ReplaceInboundLeases(inbound); err != nil {
			return 0, err
		}
		leases = inbound
		for _, lease := range leases {
			if lease.EndDate > expiresAt {
				expiresAt = lease.EndDate
			}
		}
	} else {
		if err := p.local.ReplaceInboundLeases(inbound); err != nil {
			return 0, err
		}
		p.local.Expire(now)
		snapshot, ok := p.local.Snapshot(now)
		if !ok {
			return 0, ErrLeaseSetPublisherConfig
		}
		leases, expiresAt = snapshot.Leases, snapshot.ExpiresAt
	}
	if len(leases) == 0 {
		p.leases = nil
		p.storePayload = nil
		p.expiresAt = 0
		p.nextPublication = 0
		return 0, nil
	}

	changed := !sameLeases(p.leases, leases)
	if changed {
		store, err := p.marshalLeaseSet(now)
		if err != nil {
			return 0, err
		}
		p.leases = append(p.leases[:0], leases...)
		p.storePayload = store
		localStore, err := MarshalDatabaseStore(p.hash, p.storeType, store, 0, ivnp.Hash{}, 0)
		if err != nil {
			return 0, err
		}
		parsedStore, err := i2np.ParseDatabaseStore(localStore)
		if err != nil {
			return 0, err
		}
		if err = p.database.HandleDatabaseStore(parsedStore, false, now); err != nil {
			return 0, err
		}
		p.expiresAt = expiresAt
		p.nextPublication = 0
		if p.confirmed != nil {
			p.confirmed.replace(store)
		}
	}
	discoveryChanged := p.maintainDiscovery(ctx, now)
	if p.confirmed != nil {
		return p.confirmed.maintain(ctx, force || discoveryChanged)
	}
	if !force && !discoveryChanged && !changed && (p.nextPublication == 0 || now < p.nextPublication) {
		return 0, nil
	}

	messageID := p.random()
	if messageID == 0 {
		messageID = 1
	}
	message := i2np.Message{
		Header: i2np.Header{Type: i2np.DatabaseStore, ID: messageID, Expiration: saturatingAdd(now, leaseSetPublicationEnvelopeLifetime)},
	}
	payload, err := MarshalDatabaseStore(p.hash, p.storeType, p.storePayload, 0, ivnp.Hash{}, 0)
	if err != nil {
		return 0, err
	}
	message.Payload = payload
	targets := p.database.FloodTargetsAt(make([]RouterRef, p.floodfillLimit), p.hash, now)
	results := make([]error, len(targets))
	jobs := make(chan int)
	workers := parallelism.Workers(len(targets))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				if err := ctx.Err(); err != nil {
					results[index] = err
					continue
				}
				results[index] = p.sender.Send(ctx, targets[index], message)
			}
		}()
	}
	for index := range targets {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	sent := 0
	var firstErr error
	for _, err := range results {
		if err == nil {
			sent++
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if sent == 0 {
		p.nextPublication = retryAt(now, p.expiresAt)
	} else {
		p.nextPublication = republishAt(now, p.expiresAt, p.republishBefore)
	}
	return sent, firstErr
}
func (p *LeaseSetPublisher) maintainDiscovery(ctx context.Context, now uint64) bool {
	if p.discovery == nil {
		return false
	}
	day := now/uint64((24*time.Hour)/time.Millisecond) + 1
	if p.discoveryHash != p.hash {
		p.discoveryHash = p.hash
		p.discoveryDay = 0
		p.discoveryResult = nil
		p.discoveryTargets = nil
		p.discoveryRetryAt = 0
	}
	if p.discoveryResult != nil {
		select {
		case result := <-p.discoveryResult:
			p.discoveryResult = nil
			if result.Err != nil {
				p.discoveryRetryAt = saturatingAdd(now, databaseLookupAttemptTimeout)
				return false
			}
			current := p.discoveryTargetHashes(now)
			changed := !sameHashes(p.discoveryTargets, current)
			p.discoveryTargets = nil
			p.discoveryDay = day
			p.discoveryRetryAt = 0
			return changed
		default:
			current := p.discoveryTargetHashes(now)
			if sameHashes(p.discoveryTargets, current) {
				return false
			}
			p.discoveryTargets = current
			return true
		}
	}
	if p.discoveryDay == day || now < p.discoveryRetryAt {
		return false
	}
	result, err := p.discovery.Explore(ctx, p.hash)
	if err != nil {
		p.discoveryRetryAt = saturatingAdd(now, databaseLookupAttemptTimeout)
		return false
	}
	p.discoveryTargets = p.discoveryTargetHashes(now)
	p.discoveryResult = result
	return false
}

func (p *LeaseSetPublisher) discoveryTargetHashes(now uint64) []ivnp.Hash {
	targets := p.database.FloodTargetsAt(make([]RouterRef, p.floodfillLimit), p.hash, now)
	hashes := make([]ivnp.Hash, len(targets))
	for index := range targets {
		hashes[index] = targets[index].Hash
	}
	return hashes
}

func sameHashes(left, right []ivnp.Hash) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (p *LeaseSetPublisher) marshalLeaseSet(now uint64) ([]byte, error) {
	leaseSet := make([]byte, MaxLeaseSetBytes)
	var (
		n   int
		err error
	)
	if p.encrypted != nil {
		n, err = p.encrypted.MarshalTo(leaseSet, now)
	} else if p.local2 != nil {
		n, err = p.local2.MarshalTo(leaseSet, now, p.sign)
	} else {
		snapshot, ok := p.local.Snapshot(now)
		if !ok {
			return nil, ErrLeaseSetPublisherConfig
		}
		n, err = snapshot.MarshalLegacy(leaseSet, p.encryptionKey, p.signingKey, p.sign)
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), leaseSet[:n]...), nil
}

// HandleDeliveryStatus accepts only a current, timely acknowledgement for a
// LeaseSet publication attempt.
func (p *LeaseSetPublisher) HandleDeliveryStatus(status i2np.DeliveryStatusMessage) bool {
	if p.confirmed == nil {
		return false
	}
	return p.confirmed.handle(status)
}

func saturatingAdd(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}

func retryAt(now, expiresAt uint64) uint64 {
	retry := saturatingAdd(now, leaseSetPublicationRetryDelay)
	if retry > expiresAt {
		return expiresAt
	}
	return retry
}
func republishAt(now, expiresAt, before uint64) uint64 {
	if expiresAt <= now || expiresAt <= before || expiresAt-before <= now {
		return 0
	}
	return expiresAt - before
}

func sameLeases(left, right []Lease) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
