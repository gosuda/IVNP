package router

import (
	"context"
	"sync"
)

// ssu2SendMutex keeps bulk locking allocation-free. Only a control sender
// waiting behind another writer allocates a cancellation notification.
type ssu2SendMutex struct {
	mu       sync.Mutex
	waitMu   sync.Mutex
	released chan struct{}
}

func (m *ssu2SendMutex) Lock() { m.mu.Lock() }

func (m *ssu2SendMutex) LockContext(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.waitMu.Lock()
		if m.mu.TryLock() {
			m.waitMu.Unlock()
			return nil
		}
		if m.released == nil {
			m.released = make(chan struct{})
		}
		released := m.released
		m.waitMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-released:
		}
	}
}

func (m *ssu2SendMutex) Unlock() {
	m.mu.Unlock()
	m.waitMu.Lock()
	if m.released != nil {
		close(m.released)
		m.released = nil
	}
	m.waitMu.Unlock()
}
