package router

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
	"net"
	"runtime"
	"testing"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestRateLimiterBoundaryAndRefill(t *testing.T) {
	var limiter rateLimiter
	var source [32]byte
	source[0] = 1
	policy := ratePolicies[rateTunnelBuild]

	for attempt := uint16(0); attempt < policy.capacity; attempt++ {
		if !limiter.allow(rateTunnelBuild, source, 0) {
			t.Fatalf("attempt %d before capacity %d was denied", attempt, policy.capacity)
		}
	}
	if limiter.allow(rateTunnelBuild, source, 0) {
		t.Fatal("capacity boundary was admitted")
	}
	if !limiter.allow(rateTunnelBuild, source, policy.refillMillis) {
		t.Fatal("one full refill interval did not restore a token")
	}
	if limiter.allow(rateTunnelBuild, source, policy.refillMillis) {
		t.Fatal("refilled token admitted more than one request")
	}

	metrics := limiter.snapshot().TunnelBuild
	if metrics.Allowed != uint64(policy.capacity+1) || metrics.Denied != 2 {
		t.Fatalf("metrics = %+v, want allowed %d denied 2", metrics, policy.capacity+1)
	}
}

func TestRateLimiterGarlicRefillsAtStreamingRate(t *testing.T) {
	var limiter rateLimiter
	var source [32]byte
	source[0] = 1
	policy := ratePolicies[rateGarlicDecrypt]
	for range policy.capacity {
		if !limiter.allow(rateGarlicDecrypt, source, 0) {
			t.Fatal("Garlic burst was denied before capacity")
		}
	}
	if limiter.allow(rateGarlicDecrypt, source, 0) {
		t.Fatal("Garlic burst exceeded capacity")
	}
	const restored = 8
	at := uint64(restored) * policy.refillMillis
	for range restored {
		if !limiter.allow(rateGarlicDecrypt, source, at) {
			t.Fatal("Garlic streaming refill denied an available token")
		}
	}
	if limiter.allow(rateGarlicDecrypt, source, at) {
		t.Fatal("Garlic streaming refill admitted more tokens than elapsed time")
	}
}

func TestRateLimiterIsolatesSources(t *testing.T) {
	var limiter rateLimiter
	var exhausted, independent [32]byte
	exhausted[0] = 1
	independent[0] = 2
	policy := ratePolicies[rateGarlicDecrypt]

	for attempt := uint16(0); attempt < policy.capacity; attempt++ {
		if !limiter.allow(rateGarlicDecrypt, exhausted, 50) {
			t.Fatalf("attempt %d before capacity was denied", attempt)
		}
	}
	if limiter.allow(rateGarlicDecrypt, exhausted, 50) {
		t.Fatal("exhausted source was admitted")
	}
	if !limiter.allow(rateGarlicDecrypt, independent, 50) {
		t.Fatal("independent source inherited another source's limit")
	}
}
func TestRateLimiterDistributesIPv4SourcesAcrossCapacity(t *testing.T) {
	previous := runtime.GOMAXPROCS(8)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	var limiter rateLimiter
	const sources = 256
	loads := make(map[int]int)
	for index := range sources {
		remote := &net.UDPAddr{IP: net.IPv4(10, 0, byte(index>>8), byte(index)), Port: 12_345}
		key, ok := rateKeyFromAddr(remote)
		if !ok {
			t.Fatalf("IPv4 source %s did not produce a limiter key", remote)
		}
		shard := limiter.shardIndex(key)
		loads[shard]++
		if !limiter.allow(rateSSU2Control, key, 1) {
			t.Fatalf("IPv4 source %s was denied after shard load %d", remote, loads[shard])
		}
	}
	if len(loads) < 4 {
		t.Fatalf("%d IPv4 sources reached only %d of %d shards", sources, len(loads), len(limiter.shards))
	}
}

func TestRateLimiterOpenAddressingIsolatesCollisions(t *testing.T) {
	var limiter rateLimiter
	type location struct {
		shard int
		slot  int
	}
	collisions := make(map[location][][32]byte)
	var keys [][32]byte
	for value := uint64(1); value < 10_000 && len(keys) < 3; value++ {
		var key [32]byte
		binary.BigEndian.PutUint64(key[:8], value)
		limiter.once.Do(limiter.initialize)
		hash := maphash.Bytes(rateLimitShardSeed, key[:])
		shard := int(hash % uint64(len(limiter.shards)))
		slot := int((hash / uint64(len(limiter.shards))) % uint64(len(limiter.shards[shard].entries)))
		where := location{shard: shard, slot: slot}
		collisions[where] = append(collisions[where], key)
		if len(collisions[where]) == 3 {
			keys = collisions[where]
		}
	}
	if len(keys) != 3 {
		t.Fatal("failed to find deterministic open-addressing collisions")
	}

	policy := ratePolicies[rateTunnelBuild]
	for range policy.capacity {
		if !limiter.allow(rateTunnelBuild, keys[0], 1) {
			t.Fatal("colliding source was denied before capacity")
		}
	}
	if limiter.allow(rateTunnelBuild, keys[0], 1) {
		t.Fatal("exhausted colliding source was admitted")
	}
	if !limiter.allow(rateTunnelBuild, keys[1], 1) || !limiter.allow(rateTunnelBuild, keys[2], 1) {
		t.Fatal("open-addressing collision shared another source's bucket")
	}
	if limiter.allow(rateTunnelBuild, keys[0], 1) {
		t.Fatal("collision insertion replaced an active exhausted source")
	}
}

func TestRateLimiterEvictsOnlyFullyRefilledEntry(t *testing.T) {
	var limiter rateLimiter
	var incoming [32]byte
	incoming[0] = 1
	limiter.once.Do(limiter.initialize)
	hash := maphash.Bytes(rateLimitShardSeed, incoming[:])
	shard := &limiter.shards[int(hash%uint64(len(limiter.shards)))]
	policy := ratePolicies[rateTunnelBuild]
	shard.mu.Lock()
	for index := range shard.entries {
		key := [32]byte{byte(index + 2)}
		shard.entries[index] = rateEntry{key: key, used: true}
		shard.entries[index].buckets[rateTunnelBuild] = rateBucket{initialized: true, tokens: 0, at: 0}
	}
	shard.mu.Unlock()

	fullRefill := uint64(policy.capacity) * policy.refillMillis
	if limiter.allow(rateTunnelBuild, incoming, fullRefill-1) {
		t.Fatal("new source evicted an entry before its bucket fully refilled")
	}
	if !limiter.allow(rateTunnelBuild, incoming, fullRefill) {
		t.Fatal("new source did not reuse a fully refilled entry")
	}
}

func TestServiceRateLimitsInvalidI2NPByPeer(t *testing.T) {
	service := NewService(nil)
	var attacker, peer foundation.Hash
	attacker[0] = 1
	peer[0] = 2
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.Data, ID: 1, Expiration: 1_000},
		Payload: nil,
	}
	policy := ratePolicies[rateI2NPAdmission]
	for attempt := uint16(0); attempt < policy.capacity; attempt++ {
		message.Header.ID++
		if err := service.HandleI2NPFrom(attacker, message, 1_000, false); errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt %d was rate limited before capacity", attempt)
		}
	}
	if err := service.HandleI2NPFrom(attacker, message, 1_000, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("exhausted peer error = %v, want ErrRateLimited", err)
	}
	if err := service.HandleI2NPFrom(peer, message, 1_000, false); errors.Is(err, ErrRateLimited) {
		t.Fatalf("independent peer inherited limit: %v", err)
	}
}
