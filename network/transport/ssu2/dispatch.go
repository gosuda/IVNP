package ssu2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

const (
	MaxDispatchWorkers = 256
	MaxDispatchQueue   = 4096
)

var ErrDispatcherClosed = errors.New("ssu2: packet dispatcher is closed")

// PacketHandler processes one isolated packet. The packet Data is valid only
// for the duration of the call and must not be retained.
type PacketHandler func(Datagram)

type dispatchSlot struct {
	packet Datagram
	buffer []byte
}

// Dispatcher is a fixed-worker, fixed-memory handoff queue. Dispatch copies a
// packet into one of its preallocated slots so the receive Batch can be reused
// immediately. When all workers and queue slots are busy, Dispatch waits for a
// slot or returns when ctx is cancelled; it never starts another goroutine.
type Dispatcher struct {
	done    chan struct{}
	free    chan *dispatchSlot
	jobs    chan *dispatchSlot
	handler PacketHandler
	closed  atomic.Bool
	once    sync.Once
	wg      sync.WaitGroup
}

// NewDispatcher creates workers and queue slots for packets up to packetSize.
// Close cancels queued work and waits for any active handler to return.
func NewDispatcher(workers, queue, packetSize int, handler PacketHandler) (*Dispatcher, error) {
	if workers < 1 || workers > MaxDispatchWorkers || queue < 0 || queue > MaxDispatchQueue ||
		packetSize < 1 || packetSize > MaxDatagramSize || handler == nil {
		return nil, ErrInvalidBatch
	}
	d := &Dispatcher{
		done:    make(chan struct{}),
		free:    make(chan *dispatchSlot, workers+queue),
		jobs:    make(chan *dispatchSlot, queue),
		handler: handler,
	}
	for range workers + queue {
		d.free <- &dispatchSlot{buffer: make([]byte, packetSize)}
	}
	d.wg.Add(workers)
	for range workers {
		go d.run()
	}
	return d, nil
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	for {
		select {
		case <-d.done:
			return
		case slot := <-d.jobs:
			d.handler(slot.packet)
			slot.packet = Datagram{}
			d.free <- slot
		}
	}
}

// Dispatch transfers a copy of packet into the bounded worker queue. packet is
// validated before it occupies a slot. The caller retains ownership of packet
// and may reuse its buffer as soon as Dispatch returns.
func (d *Dispatcher) Dispatch(ctx context.Context, packet Datagram) error {
	if d == nil || packet.Len < 0 || packet.Len > len(packet.Data) {
		return ErrInvalidDatagram
	}
	if d.closed.Load() {
		return ErrDispatcherClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-d.done:
		return ErrDispatcherClosed
	case <-ctx.Done():
		return ctx.Err()
	case slot := <-d.free:
		if d.closed.Load() {
			d.free <- slot
			return ErrDispatcherClosed
		}
		if packet.Len > len(slot.buffer) {
			d.free <- slot
			return ErrInvalidDatagram
		}
		slot.packet = Datagram{
			Data: slot.buffer[:packet.Len],
			Len:  packet.Len,
			Addr: packet.Addr,
			Zone: packet.Zone,
		}
		copy(slot.packet.Data, packet.Data[:packet.Len])
		if d.closed.Load() {
			slot.packet = Datagram{}
			d.free <- slot
			return ErrDispatcherClosed
		}
		select {
		case <-d.done:
			slot.packet = Datagram{}
			d.free <- slot
			return ErrDispatcherClosed
		case <-ctx.Done():
			slot.packet = Datagram{}
			d.free <- slot
			return ctx.Err()
		case d.jobs <- slot:
			return nil
		}
	}
}

// Close stops accepting packets, drops queued work, and waits for active
// handlers. A handler must return for Close to complete.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.done)
		d.wg.Wait()
	})
}
