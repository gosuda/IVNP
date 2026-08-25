package router

import (
	"sync"
	"sync/atomic"

	"gosuda.org/ivnp/networking/internal/i2np"
)

// DeliveryStatusHandler owns one disjoint status-token domain.
type DeliveryStatusHandler interface {
	HandleDeliveryStatus(i2np.DeliveryStatusMessage) bool
}

// DeliveryStatusMux routes a status to the first registered handler that
// claims it. Registration changes publish an immutable copy so authenticated
// ingress never invokes a handler while holding the registry lock.
type DeliveryStatusMux struct {
	mu        sync.Mutex
	next      uint64
	handlers  atomic.Pointer[[]deliveryStatusRegistration]
	unmatched atomic.Uint64
}

type deliveryStatusRegistration struct {
	id      uint64
	handler DeliveryStatusHandler
}

func NewDeliveryStatusMux(handlers ...DeliveryStatusHandler) *DeliveryStatusMux {
	mux := new(DeliveryStatusMux)
	for _, handler := range handlers {
		mux.Register(handler)
	}
	return mux
}

// Register adds one disjoint status-token owner and returns an idempotent
// unregister function.
func (m *DeliveryStatusMux) Register(handler DeliveryStatusHandler) func() {
	if m == nil || handler == nil {
		return func() {}
	}
	m.mu.Lock()
	m.next++
	id := m.next
	current := m.handlers.Load()
	next := make([]deliveryStatusRegistration, 0, registrationsLength(current)+1)
	if current != nil {
		next = append(next, (*current)...)
	}
	next = append(next, deliveryStatusRegistration{id: id, handler: handler})
	m.handlers.Store(&next)
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			current := m.handlers.Load()
			if current != nil {
				next := make([]deliveryStatusRegistration, 0, len(*current))
				for _, registration := range *current {
					if registration.id != id {
						next = append(next, registration)
					}
				}
				m.handlers.Store(&next)
			}
			m.mu.Unlock()
		})
	}
}
func registrationsLength(registrations *[]deliveryStatusRegistration) int {
	if registrations == nil {
		return 0
	}
	return len(*registrations)
}

func (m *DeliveryStatusMux) HandleDeliveryStatus(status i2np.DeliveryStatusMessage) bool {
	if m == nil {
		return false
	}
	registrations := m.handlers.Load()
	if registrations != nil {
		for _, registration := range *registrations {
			if registration.handler.HandleDeliveryStatus(status) {
				return true
			}
		}
	}
	m.unmatched.Add(1)
	return false
}

func (m *DeliveryStatusMux) Unmatched() uint64 {
	if m == nil {
		return 0
	}
	return m.unmatched.Load()
}

func (m *DeliveryStatusMux) Sink(status i2np.DeliveryStatusMessage) error {
	m.HandleDeliveryStatus(status)
	return nil
}
