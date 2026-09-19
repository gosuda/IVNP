//go:build dst || synctest

package durable

// WaitGroup mirrors sync.WaitGroup but parks Wait on a channel — durably
// blocked — so testing/synctest can advance the fake clock while a goroutine
// joins workers that are themselves waiting on virtual-time work.
// Invariant: drained is non-nil exactly while count > 0.
type WaitGroup struct {
	mu      Mutex
	count   int
	drained chan struct{}
}

func (w *WaitGroup) Add(delta int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count == 0 && delta > 0 {
		w.drained = make(chan struct{})
	}
	w.count += delta
	if w.count < 0 {
		panic("durable: negative WaitGroup counter")
	}
	if w.count == 0 && w.drained != nil {
		close(w.drained)
		w.drained = nil
	}
}

func (w *WaitGroup) Done() {
	w.Add(-1)
}

func (w *WaitGroup) Wait() {
	w.mu.Lock()
	drained := w.drained
	w.mu.Unlock()
	if drained != nil {
		<-drained
	}
}

func (w *WaitGroup) Go(f func()) {
	w.Add(1)
	go func() {
		defer w.Done()
		f()
	}()
}
