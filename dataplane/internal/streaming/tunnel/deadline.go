package streamingtunnel

import (
	"context"
	"os"
	"sync"
	"time"
)

type connDeadline struct {
	mu         sync.Mutex
	at         time.Time
	timer      *time.Timer
	done       chan struct{}
	expired    bool
	generation uint64
}

func newConnDeadline() connDeadline { return connDeadline{done: make(chan struct{})} }

func (d *connDeadline) set(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.generation++
	generation := d.generation
	if d.timer != nil {
		d.timer.Stop()
	}
	if d.expired {
		d.done = make(chan struct{})
		d.expired = false
	}
	d.at = at
	if at.IsZero() {
		return
	}
	if !time.Now().Before(at) {
		close(d.done)
		d.expired = true
		return
	}
	d.timer = time.AfterFunc(time.Until(at), func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.generation == generation && !d.expired {
			close(d.done)
			d.expired = true
		}
	})
}

func (d *connDeadline) value() time.Time      { d.mu.Lock(); defer d.mu.Unlock(); return d.at }
func (d *connDeadline) Done() <-chan struct{} { d.mu.Lock(); defer d.mu.Unlock(); return d.done }
func (d *connDeadline) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.expired {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// The delivery worker observes deadline changes without a goroutine per write.
type writeContext struct {
	context.Context
	limit *connDeadline
	done  <-chan struct{}
}

func (c writeContext) Done() <-chan struct{} { return c.done }
func (c writeContext) Err() error {
	select {
	case <-c.done:
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}
func (c writeContext) Deadline() (time.Time, bool) { at := c.limit.value(); return at, !at.IsZero() }
