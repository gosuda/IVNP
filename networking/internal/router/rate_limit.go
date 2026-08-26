package router

import (
	"errors"
	"hash/maphash"
	"net"
	"net/netip"
	"sync"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/parallelism"
)

// ErrRateLimited reports that a single authenticated peer or UDP source has
// exhausted the budget for a costly router operation.
var ErrRateLimited = errors.New("router: rate limited")

const rateLimitEntries = 512

var rateLimitShardSeed = maphash.MakeSeed()

type rateClass uint8

const (
	rateI2NPAdmission rateClass = iota
	rateTunnelBuild
	rateNetDBLookup
	rateNetDBStore
	rateGarlicDecrypt
	rateSSU2Control
	rateClassCount
)

// ratePolicy is a token bucket: capacity is the bounded burst and one token is
// restored every refillMillis. Data-bearing Garlic must sustain the configured
// streaming rate; control classes retain much smaller per-peer budgets. The
// aggregate admission rate exceeds the sum of specialized rates so accepted
// control traffic cannot consume the data plane's reserved throughput.
type ratePolicy struct {
	capacity     uint16
	refillMillis uint64
}

var ratePolicies = [...]ratePolicy{
	rateI2NPAdmission: {capacity: 256, refillMillis: 5}, // 200 messages/s
	rateTunnelBuild:   {capacity: 8, refillMillis: 125}, // 8 builds/s
	rateNetDBLookup:   {capacity: 16, refillMillis: 62}, // ~16 lookups/s
	rateNetDBStore:    {capacity: 16, refillMillis: 62}, // ~16 stores/s
	rateGarlicDecrypt: {capacity: 64, refillMillis: 16}, // ~62 payloads/s
	rateSSU2Control:   {capacity: 16, refillMillis: 62}, // ~16 controls/s
}

type rateBucket struct {
	tokens      uint16
	at          uint64
	initialized bool
}

type rateEntry struct {
	key     [32]byte
	used    bool
	buckets [rateClassCount]rateBucket
}

type rateCounters struct {
	allowed uint64
	denied  uint64
}

// RateLimitCounters is one limiter's cumulative decision count.
type RateLimitCounters struct {
	Allowed uint64
	Denied  uint64
}

// RateLimitSnapshot is an allocation-free view of admission limiter decisions.
// Counters are cumulative across every dynamically sized shard.
type RateLimitSnapshot struct {
	I2NPAdmission RateLimitCounters
	TunnelBuild   RateLimitCounters
	NetDBLookup   RateLimitCounters
	NetDBStore    RateLimitCounters
	GarlicDecrypt RateLimitCounters
	SSU2Control   RateLimitCounters
}

type rateLimiterShard struct {
	mu       sync.Mutex
	entries  []rateEntry
	counters [rateClassCount]rateCounters
}

type rateLimiter struct {
	once   sync.Once
	shards []rateLimiterShard
}

func (l *rateLimiter) initialize() {
	shards := parallelism.Workers(rateLimitEntries)
	entriesPerShard := (rateLimitEntries + shards - 1) / shards
	l.shards = make([]rateLimiterShard, shards)
	for index := range l.shards {
		l.shards[index].entries = make([]rateEntry, entriesPerShard)
	}
}
func (l *rateLimiter) shardIndex(key [32]byte) int {
	l.once.Do(l.initialize)
	hash := maphash.Bytes(rateLimitShardSeed, key[:])
	return int(hash % uint64(len(l.shards)))
}

func (l *rateLimiter) allow(class rateClass, key [32]byte, nowMillis uint64) bool {
	l.once.Do(l.initialize)
	hash := maphash.Bytes(rateLimitShardSeed, key[:])
	shard := &l.shards[int(hash%uint64(len(l.shards)))]
	start := int((hash / uint64(len(l.shards))) % uint64(len(shard.entries)))
	policy := ratePolicies[class]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry := shard.entry(key, start, nowMillis)
	if entry == nil {
		shard.counters[class].denied++
		return false
	}
	bucket := &entry.buckets[class]
	if !bucket.initialized {
		bucket.initialized = true
		bucket.at = nowMillis
		bucket.tokens = policy.capacity
	} else if nowMillis > bucket.at {
		elapsed := nowMillis - bucket.at
		if elapsed >= policy.refillMillis {
			refills := elapsed / policy.refillMillis
			if refills >= uint64(policy.capacity) || uint64(bucket.tokens)+refills >= uint64(policy.capacity) {
				bucket.tokens = policy.capacity
			} else {
				bucket.tokens += uint16(refills)
			}
			bucket.at += refills * policy.refillMillis
		}
	}
	if bucket.tokens == 0 {
		shard.counters[class].denied++
		return false
	}
	bucket.tokens--
	shard.counters[class].allowed++
	return true
}

func (l *rateLimiterShard) entry(key [32]byte, start int, nowMillis uint64) *rateEntry {
	idle := -1
	for offset := range len(l.entries) {
		index := (start + offset) % len(l.entries)
		entry := &l.entries[index]
		if entry.used {
			if entry.key == key {
				return entry
			}
			if idle < 0 && rateEntryIdle(entry, nowMillis) {
				idle = index
			}
			continue
		}
		if idle >= 0 {
			index = idle
		}
		l.entries[index] = rateEntry{key: key, used: true}
		return &l.entries[index]
	}
	if idle < 0 {
		return nil
	}
	l.entries[idle] = rateEntry{key: key, used: true}
	return &l.entries[idle]
}

func rateEntryIdle(entry *rateEntry, nowMillis uint64) bool {
	for class, bucket := range entry.buckets {
		if !bucket.initialized {
			continue
		}
		policy := ratePolicies[rateClass(class)]
		missing := uint64(policy.capacity - bucket.tokens)
		if missing == 0 {
			continue
		}
		if nowMillis <= bucket.at || (nowMillis-bucket.at)/policy.refillMillis < missing {
			return false
		}
	}
	return true
}

func (l *rateLimiter) snapshot() RateLimitSnapshot {
	l.once.Do(l.initialize)
	var counters [rateClassCount]rateCounters
	for index := range l.shards {
		shard := &l.shards[index]
		shard.mu.Lock()
		for class := range shard.counters {
			counters[class].allowed += shard.counters[class].allowed
			counters[class].denied += shard.counters[class].denied
		}
		shard.mu.Unlock()
	}
	return RateLimitSnapshot{
		I2NPAdmission: rateLimitCounters(counters[rateI2NPAdmission]),
		TunnelBuild:   rateLimitCounters(counters[rateTunnelBuild]),
		NetDBLookup:   rateLimitCounters(counters[rateNetDBLookup]),
		NetDBStore:    rateLimitCounters(counters[rateNetDBStore]),
		GarlicDecrypt: rateLimitCounters(counters[rateGarlicDecrypt]),
		SSU2Control:   rateLimitCounters(counters[rateSSU2Control]),
	}
}

func rateLimitCounters(counters rateCounters) RateLimitCounters {
	return RateLimitCounters{Allowed: counters.allowed, Denied: counters.denied}
}

func rateKey(peer foundation.Hash) [32]byte { return [32]byte(peer) }

func rateKeyFromAddr(remote net.Addr) (key [32]byte, ok bool) {
	endpoint, ok := remote.(interface{ AddrPort() netip.AddrPort })
	if !ok {
		return key, false
	}
	addr := endpoint.AddrPort()
	if !addr.IsValid() {
		return key, false
	}
	ip := addr.Addr().As16()
	copy(key[:16], ip[:])
	key[16] = byte(addr.Port() >> 8)
	key[17] = byte(addr.Port())
	return key, true
}
