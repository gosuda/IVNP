package garlicecies

import (
	"encoding/binary"
	"errors"
	"testing"
)

const testReplayLifetime = 5 * 60 * 1000

func replayTestKey(i uint64) [32]byte {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], i)
	return key
}

func TestReplayWindowLifetimeAndReinsertion(t *testing.T) {
	window := newReplayWindow(testReplayLifetime)
	now := uint64(1_800_000_000_000) / window.tick * window.tick
	key := replayTestKey(1)
	if err := window.check(key, now); err != nil {
		t.Fatal(err)
	}
	window.add(key, now, testReplayLifetime)
	if err := window.check(key, now+testReplayLifetime); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("replay at expiration = %v", err)
	}
	revived := now + testReplayLifetime + 1
	if err := window.check(key, revived); err != nil {
		t.Fatalf("expired replay = %v", err)
	}
	window.add(key, revived, testReplayLifetime)
	nextReuse := now + replayBucketCount*window.tick
	if err := window.check(replayTestKey(2), nextReuse); err != nil {
		t.Fatal(err)
	}
	if err := window.check(key, nextReuse); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("reinserted key deleted on old-bucket recycle: %v", err)
	}
}

func TestReplayWindowAdmissionAndBoundedExpiry(t *testing.T) {
	window := newReplayWindow(testReplayLifetime)
	start := uint64(1_800_000_000_000) / window.tick * window.tick
	for epoch := range replayBucketCount {
		now := start + uint64(epoch)*window.tick
		for slot := range replayBucketCapacity {
			key := replayTestKey(uint64(epoch*replayBucketCapacity + slot + 1))
			if err := window.check(key, now); err != nil {
				t.Fatalf("epoch=%d slot=%d: %v", epoch, slot, err)
			}
			window.add(key, now, testReplayLifetime)
		}
		if err := window.check(replayTestKey(0), now); !errors.Is(err, ErrRatchetReplayFull) {
			t.Fatalf("epoch=%d full error=%v", epoch, err)
		}
		if got := len(window.entries); got > replayBucketCount*replayBucketCapacity {
			t.Fatalf("unbounded replay entries: %d", got)
		}
	}
	if got, want := len(window.entries), replayBucketCount*replayBucketCapacity; got != want {
		t.Fatalf("entries=%d, want %d", got, want)
	}
	next := start + replayBucketCount*window.tick
	if err := window.check(replayTestKey(0), next); err != nil {
		t.Fatal(err)
	}
	if got, want := len(window.entries), (replayBucketCount-1)*replayBucketCapacity; got != want {
		t.Fatalf("recycled entries=%d, want %d", got, want)
	}
	if err := window.check(replayTestKey(uint64(2*replayBucketCapacity+1)), next); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("still live key after recycling = %v", err)
	}
	window.add(replayTestKey(0), next, testReplayLifetime)
	if got := len(window.entries); got > replayBucketCount*replayBucketCapacity {
		t.Fatalf("unbounded entries after recycle: %d", got)
	}
}

func TestReplayWindowClockRegressionFailsClosed(t *testing.T) {
	window := newReplayWindow(testReplayLifetime)
	now := uint64(1_800_000_000_000)
	if err := window.check(replayTestKey(1), now); err != nil {
		t.Fatal(err)
	}
	window.add(replayTestKey(1), now, testReplayLifetime)
	if err := window.check(replayTestKey(2), now-2*window.tick); !errors.Is(err, ErrRatchetExpired) {
		t.Fatalf("backwards time = %v", err)
	}
	if err := window.check(replayTestKey(1), now); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("backwards time erased replay record: %v", err)
	}
}
