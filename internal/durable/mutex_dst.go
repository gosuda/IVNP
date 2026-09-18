//go:build dst || synctest

package durable

import (
	"sync"
)

// Mutex is a capacity-1 channel semaphore for testing under testing/synctest.
// Unlike sync.Mutex, a queued Lock parks on a channel — durably blocked —
// so a holder waiting on virtual-time work cannot freeze the simulated clock.
type Mutex struct {
	once sync.Once
	sem  chan struct{}
}

func (m *Mutex) init() {
	m.once.Do(func() { m.sem = make(chan struct{}, 1) })
}

func (m *Mutex) Lock() {
	m.init()
	m.sem <- struct{}{}
}

func (m *Mutex) Unlock() {
	m.init()
	select {
	case <-m.sem:
	default:
		panic("durable: Unlock of unlocked Mutex")
	}
}

func (m *Mutex) TryLock() bool {
	m.init()
	select {
	case m.sem <- struct{}{}:
		return true
	default:
		return false
	}
}
