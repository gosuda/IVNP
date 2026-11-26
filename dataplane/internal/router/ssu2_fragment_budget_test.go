package router

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/foundation"
)

const ssu2TestFragmentChunk = 1200

func newSSU2FragmentTestSession(pool *atomic.Int64) *ssu2TransportSession {
	return &ssu2TransportSession{fragments: make(map[uint32]*ssu2FragmentAssembly), fragmentPool: pool}
}

func ssu2TestFirstFragment(id uint32, now time.Time) []byte {
	first := make([]byte, foundation.I2NPTransportHeaderLen+ssu2TestFragmentChunk)
	first[0] = byte(foundation.I2NPData)
	binary.BigEndian.PutUint32(first[1:5], id)
	binary.BigEndian.PutUint32(first[5:9], uint32(now.Add(time.Hour).Unix()))
	return first
}

func ssu2TestFollowOn(id uint32, number uint8, last bool) []byte {
	fragment := make([]byte, 5+ssu2TestFragmentChunk)
	fragment[0] = number << 1
	if last {
		fragment[0] |= 1
	}
	binary.BigEndian.PutUint32(fragment[1:5], id)
	return fragment
}

// addSSU2TestFragment holds the lifetime read lock that the receive path
// holds around addFragment.
func addSSU2TestFragment(s *ssu2TransportSession, kind uint8, data []byte, now time.Time) (foundation.I2NPMessage, bool, error) {
	s.lifetimeMu.RLock()
	defer s.lifetimeMu.RUnlock()
	return s.addFragment(kind, data, now)
}

func ssu2HeldFragmentBytes(s *ssu2TransportSession) (held, accounted int) {
	s.fragmentMu.Lock()
	defer s.fragmentMu.Unlock()
	for _, assembly := range s.fragments {
		held += assembly.size
	}
	return held, s.fragmentBytes
}

// One authenticated peer that never sends the final fragment of its messages
// must not pin more than the per-session reassembly budget.
func TestSSU2FragmentReassemblyIsCappedPerSession(t *testing.T) {
	var pool atomic.Int64
	s := newSSU2FragmentTestSession(&pool)
	now := time.Now()
	refused := 0
	for id := uint32(1); id <= ssu2MaxFragmentedMessages; id++ {
		if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFirstFragment, ssu2TestFirstFragment(id, now), now); err != nil {
			refused++
			continue
		}
		for number := uint8(2); number <= 52; number++ {
			if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(id, number, false), now); err != nil {
				refused++
				break
			}
		}
	}
	held, accounted := ssu2HeldFragmentBytes(s)
	if held > ssu2MaxFragmentBytesPerSession {
		t.Fatalf("session pins %d reassembly bytes, cap is %d", held, ssu2MaxFragmentBytesPerSession)
	}
	if refused == 0 {
		t.Fatal("no fragment was refused after the per-session budget was spent")
	}
	if held != accounted || int64(held) != pool.Load() {
		t.Fatalf("reassembly accounting drifted: held=%d session=%d pool=%d", held, accounted, pool.Load())
	}
	s.ReleaseSensitive()
	if pool.Load() != 0 {
		t.Fatalf("released session kept %d bytes charged to the global pool", pool.Load())
	}
}

// Duplicate or new follow-on fragments must not extend an incomplete
// message past its lifetime, which runs from the first fragment received.
func TestSSU2FragmentReassemblyExpiresFromCreation(t *testing.T) {
	var pool atomic.Int64
	s := newSSU2FragmentTestSession(&pool)
	start := time.Now()
	const id = 7
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFirstFragment, ssu2TestFirstFragment(id, start), start); err != nil {
		t.Fatal(err)
	}
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(id, 2, false), start); err != nil {
		t.Fatal(err)
	}
	refresh := start.Add(ssu2FragmentLifetime - time.Second)
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(id, 2, false), refresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(id, 3, false), refresh); err != nil {
		t.Fatal(err)
	}
	s.expireFragments(start.Add(ssu2FragmentLifetime + time.Second))
	s.fragmentMu.Lock()
	remaining := len(s.fragments)
	s.fragmentMu.Unlock()
	if remaining != 0 {
		t.Fatalf("refreshed message outlived its creation lifetime: %d assemblies remain", remaining)
	}
	if held, accounted := ssu2HeldFragmentBytes(s); held != 0 || accounted != 0 || pool.Load() != 0 {
		t.Fatalf("expiry did not release reassembly bytes: held=%d session=%d pool=%d", held, accounted, pool.Load())
	}
}

// Reassembly across all sessions shares one global budget, and every exit
// path returns what a message held.
func TestSSU2FragmentReassemblyHonorsGlobalBudgetAndReleases(t *testing.T) {
	var pool atomic.Int64
	pool.Store(ssu2MaxFragmentBytes - ssu2TestFragmentChunk/2)
	s := newSSU2FragmentTestSession(&pool)
	now := time.Now()
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFirstFragment, ssu2TestFirstFragment(1, now), now); !errors.Is(err, ErrSSU2Session) {
		t.Fatalf("fragment beyond the global budget: err=%v, want ErrSSU2Session", err)
	}
	if got := pool.Load(); got != ssu2MaxFragmentBytes-ssu2TestFragmentChunk/2 {
		t.Fatalf("refused fragment changed the global pool to %d", got)
	}
	if held, accounted := ssu2HeldFragmentBytes(s); held != 0 || accounted != 0 {
		t.Fatalf("refused fragment stayed resident: held=%d session=%d", held, accounted)
	}

	pool.Store(0)
	if _, _, err := addSSU2TestFragment(s, dataplanessu2.BlockFirstFragment, ssu2TestFirstFragment(2, now), now); err != nil {
		t.Fatal(err)
	}
	message, complete, err := addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(2, 1, true), now)
	if err != nil || !complete || len(message.Payload) != 2*ssu2TestFragmentChunk {
		t.Fatalf("complete message: complete=%v len=%d err=%v", complete, len(message.Payload), err)
	}
	if held, accounted := ssu2HeldFragmentBytes(s); held != 0 || accounted != 0 || pool.Load() != 0 {
		t.Fatalf("completed message kept reassembly bytes: held=%d session=%d pool=%d", held, accounted, pool.Load())
	}

	if _, _, err = addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, ssu2TestFollowOn(3, 1, false), now); err != nil {
		t.Fatal(err)
	}
	conflicting := ssu2TestFollowOn(3, 1, false)
	conflicting[5] = 1
	if _, _, err = addSSU2TestFragment(s, dataplanessu2.BlockFollowOnFragment, conflicting, now); !errors.Is(err, ErrSSU2Peer) {
		t.Fatalf("conflicting fragment: err=%v, want ErrSSU2Peer", err)
	}
	if held, accounted := ssu2HeldFragmentBytes(s); held != 0 || accounted != 0 || pool.Load() != 0 {
		t.Fatalf("rejected message kept reassembly bytes: held=%d session=%d pool=%d", held, accounted, pool.Load())
	}
}
