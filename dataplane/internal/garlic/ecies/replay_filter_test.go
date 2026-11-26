package garlicecies

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func replayLimitedPair(t testing.TB, maxReplays int) (*RatchetManager, *RatchetManager, uint64) {
	t.Helper()
	a, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	b, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	aM, err := NewRatchetManager(a, RatchetConfig{TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(aM.ReleaseSensitive)
	bM, err := NewRatchetManager(b, RatchetConfig{TagLookahead: 4, MaxReplays: maxReplays})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bM.ReleaseSensitive)
	return aM, bM, 1_800_000_000_000
}

// +checklocksignore
func TestRatchetNewSessionReplayCacheIsBounded(t *testing.T) {
	const limit = 4
	a, b, now := replayLimitedPair(t, limit)
	public := ratchetPublic(t, b)
	for i := range limit {
		ns, err := a.EncryptUnbound(make([]byte, 2048), public, 4, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now+uint64(i)); err != nil {
			t.Fatalf("New Session %d: %v", i, err)
		}
	}
	first, err := a.EncryptUnbound(make([]byte, 2048), public, 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), first, now+limit); !errors.Is(err, ErrRatchetReplayFull) {
		t.Fatalf("New Session beyond replay capacity: err = %v, want %v", err, ErrRatchetReplayFull)
	}
	if got := b.Stats().NewSessions; got != limit {
		t.Fatalf("authenticated New Sessions = %d, want %d", got, limit)
	}
	if b.replays.count != limit {
		t.Fatalf("replay reservations = %d, want %d", b.replays.count, limit)
	}

	// Reservations lapse one bucket span after the DateTime window closes.
	later := now + replayAcceptWindow + b.replays.span + limit
	ns, err := a.EncryptUnbound(make([]byte, 2048), public, 4, nil, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, later); err != nil {
		t.Fatalf("New Session after reservations expired: %v", err)
	}
	if b.replays.count != 1 {
		t.Fatalf("replay reservations after expiry = %d, want 1", b.replays.count)
	}
}

// +checklocksignore
func TestRatchetNewSessionReplayExpiryDoesNotScheduleSweep(t *testing.T) {
	a, b, now := replayLimitedPair(t, 0)
	ns, err := a.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, b), 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Receive(make([]byte, 2048), make([]byte, 2048), ns, now); err != nil {
		t.Fatal(err)
	}
	if b.nextExpiry != ^uint64(0) {
		t.Fatalf("replay reservation scheduled a session sweep at %d", b.nextExpiry)
	}
}

func TestReplayFilterDropsWholeBuckets(t *testing.T) {
	filter := newReplayFilter(0, 1<<20)
	const now = 1_000_000_000
	// One reservation per second over the whole window stays within the fixed
	// bucket set and is released bucket by bucket.
	for i := range uint64(replayAcceptWindow / 1000) {
		var key [32]byte
		key[0], key[1] = byte(i), byte(i>>8)
		filter.add(key, now+i*1000+replayAcceptWindow)
		if !filter.contains(key, now+i*1000+replayAcceptWindow) {
			t.Fatalf("key %d not reserved through its expiry", i)
		}
	}
	if filter.count != replayAcceptWindow/1000 {
		t.Fatalf("reservations = %d, want %d", filter.count, replayAcceptWindow/1000)
	}
	occupied := 0
	for _, bucket := range filter.buckets {
		if bucket.keys != nil {
			occupied++
		}
	}
	if occupied > replayBuckets {
		t.Fatalf("occupied buckets = %d", occupied)
	}
	filter.expire(now + 2*replayAcceptWindow + filter.span)
	if filter.count != 0 {
		t.Fatalf("reservations after expiry = %d, want 0", filter.count)
	}
	for _, bucket := range filter.buckets {
		if bucket.keys != nil {
			t.Fatal("expired bucket retained its keys")
		}
	}
}

func TestReplayFilterKeepsKeysWhenClockStepsBack(t *testing.T) {
	filter := newReplayFilter(0, 1<<20)
	const now = 10_000_000
	var keys [replayBuckets + 2][32]byte
	for i := range keys {
		keys[i][0] = byte(i + 1)
		// Expiries march forward faster than the reference clock, then the
		// last insert steps far back.
		filter.add(keys[i], now+uint64(i)*filter.span+replayAcceptWindow)
	}
	var back [32]byte
	filter.add(back, now/2)
	for i, key := range keys {
		expires := now + uint64(i)*filter.span + replayAcceptWindow
		filter.expire(expires)
		if !filter.contains(key, expires) {
			t.Fatalf("key %d released before its expiry", i)
		}
	}
}
