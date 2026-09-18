//go:build dst || synctest

package durable

import (
	"sync"
)

// RWMutex parks contended readers and writers on bubble-local channels so
// testing/synctest can advance time. Like sync.RWMutex, it must not be copied
// after first use, and a waiting writer prevents new readers from entering.
type RWMutex struct {
	mu      Mutex
	readers int
	writers int
	writing bool
	changed chan struct{}
}

func (m *RWMutex) wait() {
	if m.changed == nil {
		m.changed = make(chan struct{})
	}
	changed := m.changed
	m.mu.Unlock()
	<-changed
	m.mu.Lock()
}

func (m *RWMutex) wake() {
	if m.changed != nil {
		close(m.changed)
		m.changed = nil
	}
}

func (m *RWMutex) Lock() {
	m.mu.Lock()
	m.writers++
	for m.writing || m.readers != 0 {
		m.wait()
	}
	m.writers--
	m.writing = true
	m.mu.Unlock()
}

func (m *RWMutex) Unlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.writing {
		panic("durable: Unlock of unlocked RWMutex")
	}
	m.writing = false
	m.wake()
}

func (m *RWMutex) RLock() {
	m.mu.Lock()
	for m.writing || m.writers != 0 {
		m.wait()
	}
	m.readers++
	m.mu.Unlock()
}

func (m *RWMutex) RUnlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readers == 0 {
		panic("durable: RUnlock of unlocked RWMutex")
	}
	m.readers--
	if m.readers == 0 {
		m.wake()
	}
}

func (m *RWMutex) TryLock() bool {
	if !m.mu.TryLock() {
		return false
	}
	defer m.mu.Unlock()
	if m.writing || m.readers != 0 {
		return false
	}
	m.writing = true
	return true
}

func (m *RWMutex) TryRLock() bool {
	if !m.mu.TryLock() {
		return false
	}
	defer m.mu.Unlock()
	if m.writing || m.writers != 0 {
		return false
	}
	m.readers++
	return true
}

func (m *RWMutex) RLocker() sync.Locker { return (*readLocker)(m) }

type readLocker RWMutex

func (m *readLocker) Lock()   { (*RWMutex)(m).RLock() }
func (m *readLocker) Unlock() { (*RWMutex)(m).RUnlock() }
