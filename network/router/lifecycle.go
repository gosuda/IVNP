package router

import (
	"context"
	"errors"
	"sync"
)

var ErrStopped = errors.New("router: service stopped")

// Lifecycle coordinates router-owned goroutines without leaking work after
// shutdown. Tasks are admitted only while running and observe the shared ctx.
type Lifecycle struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	workers sync.WaitGroup
}

func (l *Lifecycle) Start(parent context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running {
		return false
	}
	l.ctx, l.cancel = context.WithCancel(parent)
	l.running = true
	return true
}

func (l *Lifecycle) Context() context.Context {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx == nil {
		return context.Background()
	}
	return l.ctx
}

func (l *Lifecycle) Go(task func(context.Context)) error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return ErrStopped
	}
	ctx := l.ctx
	l.workers.Add(1)
	l.mu.Unlock()
	go func() { defer l.workers.Done(); task(ctx) }()
	return nil
}

func (l *Lifecycle) Stop() {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return
	}
	l.running = false
	cancel := l.cancel
	l.mu.Unlock()
	cancel()
	l.workers.Wait()
}
