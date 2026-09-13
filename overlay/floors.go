package overlay

import (
	"sync"
	"time"
)

// FloorKey scopes a publication rollback floor. The path that supplied a
// record is never part of the key: an IVNP-local copy and a public-netDB copy
// of the same verified record share one floor.
type FloorKey struct {
	Endpoint EndpointID
	Fabric   FabricID
	Realm    RealmID
	Port     uint16
	// Format is the contact format version (2 for x-ov.*, 1 for x-ivnp.*).
	Format uint8
}

// FloorVerdict classifies a record against the persisted floor.
type FloorVerdict uint8

const (
	// FloorAdvance accepts the record and raises the floor.
	FloorAdvance FloorVerdict = iota + 1
	// FloorReplay accepts a record identical to the floor without change.
	FloorReplay
	// FloorRollback rejects a record older than the floor.
	FloorRollback
	// FloorEquivocation rejects a record at floor position with a different digest.
	FloorEquivocation
)

// maxFloors bounds the tracked positions. A floor exists to protect a live
// record, so entries expire with the record that produced them; the sweep
// runs only when a new scope would exceed the bound. A still-full table
// fails closed — it never evicts a live floor to make room.
const maxFloors = 4096

// FloorTracker persists the highest accepted (incarnation, sequence, digest)
// per scope. Only verified records advance a floor; a higher unverified
// candidate never does.
type FloorTracker struct {
	mu     sync.Mutex
	floors map[FloorKey]floorPosition
}

type floorPosition struct {
	incarnation uint64
	sequence    uint64
	digest      [32]byte
	// notAfter is the verified lifetime bound of the record that set the
	// floor; zero never expires.
	notAfter int64
}

func NewFloorTracker() *FloorTracker {
	return &FloorTracker{floors: make(map[FloorKey]floorPosition)}
}

// Check classifies a candidate without mutating state. Use before signature
// verification to short-circuit stale work.
func (t *FloorTracker) Check(key FloorKey, incarnation, sequence uint64, digest [32]byte) FloorVerdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	floor, present := t.floors[key]
	if !present {
		return FloorAdvance
	}
	return classify(floor, incarnation, sequence, digest)
}

// Admit checks a verified record and advances the floor on FloorAdvance or
// FloorReplay. Call only after the record's authorization has been verified.
// notAfter is the record's verified lifetime bound; the floor entry expires
// with it. A new scope admitted at capacity first sweeps expired entries;
// a still-full table rejects the admission rather than weakening the
// rollback protection of a live scope.
func (t *FloorTracker) Admit(key FloorKey, incarnation, sequence uint64, digest [32]byte, notAfter int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if notAfter != 0 && notAfter <= time.Now().Unix() {
		return CodeRecordStale.Wrap("floor's protecting record is already expired")
	}
	floor, present := t.floors[key]
	if !present {
		if len(t.floors) >= maxFloors {
			t.sweepExpired(time.Now().Unix())
			if len(t.floors) >= maxFloors {
				return CodeRateLimited.Wrap("rollback floor table is at capacity")
			}
		}
		t.floors[key] = floorPosition{incarnation, sequence, digest, notAfter}
		return nil
	}
	switch classify(floor, incarnation, sequence, digest) {
	case FloorAdvance:
		t.floors[key] = floorPosition{incarnation, sequence, digest, notAfter}
		return nil
	case FloorReplay:
		return nil
	case FloorEquivocation:
		return CodeEquivocation.Wrap("equal sequence with different digest")
	default:
		return CodeRecordStale.Wrap("record precedes the rollback floor")
	}
}

// sweepExpired drops entries whose protecting record has expired. Callers
// hold t.mu.
func (t *FloorTracker) sweepExpired(now int64) {
	for key, floor := range t.floors {
		if floor.notAfter != 0 && floor.notAfter <= now {
			delete(t.floors, key)
		}
	}
}

// FloorEntry is one persisted rollback position; operators durably store the
// export and import it on restart so a reboot never re-accepts stale records.
type FloorEntry struct {
	Key         FloorKey
	Incarnation uint64
	Sequence    uint64
	Digest      [32]byte
	NotAfter    int64
}

// Export snapshots every floor for durable persistence.
func (t *FloorTracker) Export() []FloorEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]FloorEntry, 0, len(t.floors))
	for key, floor := range t.floors {
		out = append(out, FloorEntry{
			Key: key, Incarnation: floor.incarnation,
			Sequence: floor.sequence, Digest: floor.digest,
			NotAfter: floor.notAfter,
		})
	}
	return out
}

// Import restores persisted floors. Restores never lower an existing floor;
// entries whose protecting record already expired are dropped on arrival.
func (t *FloorTracker) Import(entries []FloorEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().Unix()
	for _, e := range entries {
		if e.NotAfter != 0 && e.NotAfter <= now {
			continue
		}
		if _, present := t.floors[e.Key]; !present && len(t.floors) >= maxFloors {
			t.sweepExpired(now)
			if len(t.floors) >= maxFloors {
				return
			}
		}
		floor, present := t.floors[e.Key]
		if present && classify(floor, e.Incarnation, e.Sequence, e.Digest) != FloorAdvance {
			continue
		}
		t.floors[e.Key] = floorPosition{e.Incarnation, e.Sequence, e.Digest, e.NotAfter}
	}
}

func classify(floor floorPosition, incarnation, sequence uint64, digest [32]byte) FloorVerdict {
	if incarnation != floor.incarnation {
		if incarnation < floor.incarnation {
			return FloorRollback
		}
		return FloorAdvance
	}
	if sequence != floor.sequence {
		if sequence < floor.sequence {
			return FloorRollback
		}
		return FloorAdvance
	}
	if digest != floor.digest {
		return FloorEquivocation
	}
	return FloorReplay
}
