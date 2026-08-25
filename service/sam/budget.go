package sam

import (
	"errors"
	"sync/atomic"
)

var (
	errQueueBudget          = errors.New("sam: queued-byte budget exceeded")
	errQueueBudgetUnderflow = errors.New("sam: queued-byte budget released without reservation")
)

// byteBudget is a non-blocking queued-memory budget. Reservations are charged
// before ownership crosses a goroutine or socket boundary and released by the
// final owner.
type byteBudget struct {
	limit int64
	used  atomic.Int64
}

func newByteBudget(limit int64) *byteBudget { return &byteBudget{limit: limit} }

func (b *byteBudget) acquire(size int64) bool {
	if b == nil || size < 0 || size > b.limit {
		return false
	}
	for {
		used := b.used.Load()
		if used > b.limit-size {
			return false
		}
		if b.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (b *byteBudget) TryReserve(size int) bool { return b.acquire(int64(size)) }
func (b *byteBudget) Release(size int)         { _ = b.release(int64(size)) }

func (b *byteBudget) release(size int64) error {
	if b == nil || size <= 0 {
		return nil
	}
	for {
		used := b.used.Load()
		if size > used {
			return errQueueBudgetUnderflow
		}
		if b.used.CompareAndSwap(used, used-size) {
			return nil
		}
	}
}
