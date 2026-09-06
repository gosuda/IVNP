package tunnel

import (
	"sync"
)

// CreatorBudget bounds preparing and reply-pending creators across router owners.
// Waiting is nonblocking and FIFO, with at most one queue entry per registered owner.
type CreatorBudget struct {
	mu        sync.Mutex
	capacity  int
	maxOwners int
	active    int
	owners    map[*BuildManager]struct{}
	waiters   []*BuildManager
}

func NewCreatorBudget(capacity, maxOwners int) *CreatorBudget {
	if capacity <= 0 {
		capacity = defaultMaxPendingBuilds
	}
	if maxOwners <= 0 {
		maxOwners = 1
	}
	return &CreatorBudget{capacity: capacity, maxOwners: maxOwners, owners: make(map[*BuildManager]struct{})}
}

func (b *CreatorBudget) register(owner *BuildManager) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.owners) >= b.maxOwners {
		return false
	}
	b.owners[owner] = struct{}{}
	return true
}

func (b *CreatorBudget) tryAcquire(owner *BuildManager) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.owners[owner]; !ok || b.active >= b.capacity || len(b.waiters) != 0 {
		return false
	}
	b.active++
	return true
}

func (b *CreatorBudget) acquireOrWait(owner *BuildManager) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.owners[owner]; !ok {
		return false
	}
	if b.active < b.capacity && (len(b.waiters) == 0 || b.waiters[0] == owner) {
		if len(b.waiters) != 0 {
			b.waiters[0] = nil
			b.waiters = b.waiters[1:]
		}
		b.active++
		b.wakeLocked()
		return true
	}
	for _, waiting := range b.waiters {
		if waiting == owner {
			return false
		}
	}
	b.waiters = append(b.waiters, owner)
	return false
}

func (b *CreatorBudget) release() {
	b.mu.Lock()
	b.active--
	b.wakeLocked()
	b.mu.Unlock()
}

func (b *CreatorBudget) cancelWait(owner *BuildManager) {
	b.mu.Lock()
	b.removeWaiterLocked(owner)
	b.wakeLocked()
	b.mu.Unlock()
}

func (b *CreatorBudget) unregister(owner *BuildManager) {
	b.mu.Lock()
	delete(b.owners, owner)
	b.removeWaiterLocked(owner)
	b.wakeLocked()
	b.mu.Unlock()
}

func (b *CreatorBudget) removeWaiterLocked(owner *BuildManager) {
	for index, waiting := range b.waiters {
		if waiting == owner {
			copy(b.waiters[index:], b.waiters[index+1:])
			b.waiters[len(b.waiters)-1] = nil
			b.waiters = b.waiters[:len(b.waiters)-1]
			return
		}
	}
}

func (b *CreatorBudget) wakeLocked() {
	if b.active < b.capacity && len(b.waiters) != 0 {
		// Build-event callbacks only enqueue work; they must not reenter admission.
		b.waiters[0].notifyBuildEvent()
	}
}
