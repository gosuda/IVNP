package garlicecies

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func replayEphemeralTestKey(value byte) [32]byte {
	var key [32]byte
	key[0] = value
	return key
}

func TestReplayWindowCapacityAndExpiration(t *testing.T) {
	const start uint64 = 1_800_000_000_000
	window := newReplayWindow(300_000, 2)
	if err := window.reserve(replayEphemeralTestKey(1), start); err != nil {
		t.Fatal(err)
	}
	if err := window.reserve(replayEphemeralTestKey(2), start+1); err != nil {
		t.Fatal(err)
	}
	if err := window.check(replayEphemeralTestKey(1), start+2); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := window.reserve(replayEphemeralTestKey(3), start+2); !errors.Is(err, ErrRatchetReplayExhausted) {
		t.Fatalf("at capacity: %v", err)
	}
	if window.count != 2 {
		t.Fatalf("count = %d, want 2", window.count)
	}
	window.expire(start + 300_000 + window.bucketWidth + 1)
	if window.count != 0 {
		t.Fatalf("count after expiration = %d", window.count)
	}
	if err := window.reserve(replayEphemeralTestKey(3), start+300_000+window.bucketWidth+1); err != nil {
		t.Fatal(err)
	}
}

func TestReplayWindowClockRollbackAndJump(t *testing.T) {
	window := newReplayWindow(300_000, 1)
	if err := window.reserve(replayEphemeralTestKey(1), 10_000_000); err != nil {
		t.Fatal(err)
	}
	window.expire(9_000_000)
	if err := window.check(replayEphemeralTestKey(1), 9_000_000); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("rollback replay: %v", err)
	}
	window.expire(99_999_999_999)
	if window.count != 0 {
		t.Fatalf("expired count = %d", window.count)
	}
	if err := window.reserve(replayEphemeralTestKey(2), 99_999_999_999); err != nil {
		t.Fatal(err)
	}
	if window.count != 1 {
		t.Fatalf("new count = %d", window.count)
	}
}

func TestReplayWindowNoEarlyExpiration(t *testing.T) {
	for now := uint64(0); now < 40; now++ {
		window := newReplayWindow(11, 1)
		if err := window.reserve(replayEphemeralTestKey(1), now); err != nil {
			t.Fatal(err)
		}
		if err := window.check(replayEphemeralTestKey(1), now+11); !errors.Is(err, ErrRatchetReplay) {
			t.Fatalf("now=%d expired too early: %v", now, err)
		}
		if window.count != 1 {
			t.Fatalf("now=%d count=%d", now, window.count)
		}
		window.expire(now + 13)
		if window.count != 0 {
			t.Fatalf("now=%d expired count=%d", now, window.count)
		}
	}
}

// Exercise the authenticated New Session path with a small public capacity.
func TestRatchetReplayCapacityRejectsNewSessions(t *testing.T) {
	senderLocal, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer senderLocal.ReleaseSensitive()
	receiverLocal, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer receiverLocal.ReleaseSensitive()
	sender, err := NewRatchetManager(senderLocal, RatchetConfig{CryptoTypes: []uint16{4}, TagLookahead: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.ReleaseSensitive()
	receiver, err := NewRatchetManager(receiverLocal, RatchetConfig{CryptoTypes: []uint16{4}, TagLookahead: 4, MaxReplayEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.ReleaseSensitive()

	const now uint64 = 1_800_000_000_000
	public := ratchetPublic(t, receiver)
	var packets [3][]byte
	for i := range packets {
		packets[i], err = sender.EncryptUnbound(make([]byte, 2048), public, 4, clove("unbound"), now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		result, receiveErr := receiver.Receive(make([]byte, 2048), make([]byte, 2048), packets[i], now)
		if receiveErr != nil || !result.NewSession || result.Candidate != nil {
			t.Fatalf("unbound session %d: result=%#v err=%v", i, result, receiveErr)
		}
	}
	if _, err := receiver.Receive(make([]byte, 2048), make([]byte, 2048), packets[0], now); !errors.Is(err, ErrRatchetReplay) {
		t.Fatalf("duplicate at limit: %v", err)
	}
	if _, err := receiver.Receive(make([]byte, 2048), make([]byte, 2048), packets[2], now); !errors.Is(err, ErrRatchetReplayExhausted) {
		t.Fatalf("new unbound at limit: %v", err)
	}
	bound, err := sender.Encrypt(make([]byte, 2048), receiverLocal.Hash(), public, 4, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if result, receiveErr := receiver.Receive(make([]byte, 2048), make([]byte, 2048), bound, now); !errors.Is(receiveErr, ErrRatchetReplayExhausted) || result.Candidate != nil {
		t.Fatalf("new bound at limit: result=%#v err=%v", result, receiveErr)
	}
	if receiver.replays.count != 2 {
		t.Fatalf("replay entries at capacity = %d, want 2", receiver.replays.count)
	}
	if stats := receiver.Stats(); stats.NewSessions != 2 || stats.Sessions != 0 {
		t.Fatalf("capacity rejection retained session state: %+v", stats)
	}

	future := now + defaultReplayLife + receiver.replays.bucketWidth + 1
	packet, err := sender.EncryptUnbound(make([]byte, 2048), public, 4, clove("after expiry"), future)
	if err != nil {
		t.Fatal(err)
	}
	if result, receiveErr := receiver.Receive(make([]byte, 2048), make([]byte, 2048), packet, future); receiveErr != nil || !result.NewSession {
		t.Fatalf("new unbound after expiry: result=%#v err=%v", result, receiveErr)
	}
	if receiver.replays.count != 1 {
		t.Fatalf("replay entries after expiry = %d, want 1", receiver.replays.count)
	}
}
