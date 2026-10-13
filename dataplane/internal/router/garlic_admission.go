package router

import (
	"crypto/sha256"
	"errors"
	"sync"
)

var (
	ErrGarlicPreauthLimit  = errors.New("router: Garlic pre-authentication work limit exceeded")
	ErrGarlicPreauthReplay = errors.New("router: repeated unauthenticated Garlic ciphertext")
)

const (
	// Worst case: a router-key attempt, three ECIES formats and a legacy
	// attempt for each of the maximum number of destinations.
	garlicPreauthBurstUnits        = 4*maxGarlicDestinations + 1
	garlicPreauthGlobalUnitsPerSec = 128
	garlicPreauthPeerUnitsPerSec   = 64
	garlicPreauthMaxConcurrent     = 2
	garlicPreauthMaxPeers          = 256
	garlicPreauthReplaySlots       = 4096
	garlicPreauthReplayLifetime    = 60_000 // milliseconds
	garlicPreauthUnitScale         = 1000
)

type garlicWorkBudget struct {
	available uint64 // thousandths of a work unit
	last      uint64 // milliseconds
}

func (b *garlicWorkBudget) refill(now, unitsPerSecond uint64) {
	if now <= b.last {
		return
	}
	delta := now - b.last
	b.last = now
	capacity := uint64(garlicPreauthBurstUnits * garlicPreauthUnitScale)
	if delta >= capacity/unitsPerSecond+1 {
		b.available = capacity
		return
	}
	b.available = min(capacity, b.available+delta*unitsPerSecond)
}

type garlicPeerBudget struct {
	budget   garlicWorkBudget
	lastSeen uint64
}

type garlicReplayEntry struct {
	digest  [sha256.Size]byte
	expires uint64
}

// garlicPreauthAdmission bounds expensive cryptography before an unknown
// ciphertext has authenticated to any local destination. In-progress and
// replay state are shared across all destination ratchets of one receiver.
// Every successful admit must be paired with finish, including error paths.
type garlicPreauthAdmission struct {
	mu sync.Mutex

	global garlicWorkBudget
	peers  map[[32]byte]garlicPeerBudget
	active int

	seen    map[[sha256.Size]byte]uint64
	replays [garlicPreauthReplaySlots]garlicReplayEntry
	next    int
}

func newGarlicPreauthAdmission() garlicPreauthAdmission {
	return garlicPreauthAdmission{
		global: garlicWorkBudget{available: garlicPreauthBurstUnits * garlicPreauthUnitScale},
		peers:  make(map[[32]byte]garlicPeerBudget),
		seen:   make(map[[sha256.Size]byte]uint64),
	}
}

// admit reserves the worst-case number of crypto operations for this packet,
// atomically against both the global and predecessor-specific budgets.
// A zero predecessor hash is one shared anonymous-source budget.
func (a *garlicPreauthAdmission) admit(peer [32]byte, packet []byte, work int, now uint64) error {
	if work <= 0 || work > garlicPreauthBurstUnits {
		return ErrGarlicPreauthLimit
	}
	digest := sha256.Sum256(packet)
	a.mu.Lock()
	defer a.mu.Unlock()
	if until, exists := a.seen[digest]; exists && until > now {
		return ErrGarlicPreauthReplay
	}
	if a.active >= garlicPreauthMaxConcurrent {
		return ErrGarlicPreauthLimit
	}
	cost := uint64(work * garlicPreauthUnitScale)
	a.global.refill(now, garlicPreauthGlobalUnitsPerSec)
	if a.global.available < cost {
		return ErrGarlicPreauthLimit
	}
	state, exists := a.peers[peer]
	if !exists {
		state = garlicPeerBudget{budget: garlicWorkBudget{available: garlicPreauthBurstUnits * garlicPreauthUnitScale, last: now}}
	}
	state.budget.refill(now, garlicPreauthPeerUnitsPerSec)
	if state.budget.available < cost {
		return ErrGarlicPreauthLimit
	}
	if !exists && len(a.peers) == garlicPreauthMaxPeers {
		var oldest [32]byte
		oldestTime := ^uint64(0)
		for key, entry := range a.peers {
			if entry.lastSeen <= oldestTime {
				oldest, oldestTime = key, entry.lastSeen
			}
		}
		delete(a.peers, oldest)
	}
	state.budget.available -= cost
	state.lastSeen = now
	a.peers[peer] = state
	a.global.available -= cost
	a.active++

	old := a.replays[a.next]
	if until, exists := a.seen[old.digest]; exists && until == old.expires {
		delete(a.seen, old.digest)
	}
	expires := now + garlicPreauthReplayLifetime
	if expires < now {
		expires = ^uint64(0)
	}
	a.replays[a.next] = garlicReplayEntry{digest: digest, expires: expires}
	a.seen[digest] = expires
	a.next = (a.next + 1) % len(a.replays)
	return nil
}

func (a *garlicPreauthAdmission) finish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == 0 {
		panic("router: unbalanced Garlic pre-authentication admission")
	}
	a.active--
}
