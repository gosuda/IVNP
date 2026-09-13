package overlay

// EventKind names a host-visible lifecycle or security transition.
type EventKind uint8

const (
	EventContextOpened EventKind = iota + 1
	EventContextClosed
	EventRealmOpened
	EventRealmClosed
	EventPublicationFailed
	EventEquivocation
	EventHostDegraded
)

// HostEvent is a redacted lifecycle observation; it never carries secrets,
// decrypted routes, or other tenants' identifiers.
type HostEvent struct {
	Kind  EventKind
	Realm RealmID
}

// WatchEvents subscribes to host lifecycle events. The stream is bounded;
// slow consumers lose events rather than blocking the host. The channel closes
// when the host closes; subscribing to a closed host returns a closed channel.
func (h *Host) WatchEvents() <-chan HostEvent {
	return h.watchEvents()
}

func (h *Host) watchEvents() chan HostEvent {
	ch := make(chan HostEvent, 32)
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		close(ch)
		return ch
	}
	h.watchers = append(h.watchers, ch)
	h.mu.Unlock()
	return ch
}

// unwatch detaches a watcher; a subscriber that stops early must not leak.
func (h *Host) unwatch(ch chan HostEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, w := range h.watchers {
		if w == ch {
			h.watchers = append(h.watchers[:i], h.watchers[i+1:]...)
			return
		}
	}
}

func (h *Host) broadcast(event HostEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.watchers {
		select {
		case ch <- event:
		default:
		}
	}
}
