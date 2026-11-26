package router

import (
	"hash/maphash"
	"net"
	"net/netip"
	"time"
)

// ssu2RetryLimiter counts the Retry packets sent to each source in fixed
// ssu2RetryWindow intervals. Sources are IPv4 addresses or IPv6 /64 prefixes
// from ssu2InboundSourceKey. Each slot tracks one source at a time; a
// different source that hashes to an occupied slot takes it over. A takeover
// only loosens the limit and never refuses a source, and the per-manager hash
// seed keeps a sender from choosing sources that collide with a victim.
type ssu2RetryLimiter struct {
	seed  maphash.Seed
	slots [ssu2RetryLimiterSlots]ssu2RetrySlot
}

type ssu2RetrySlot struct {
	source netip.Prefix
	window int64
	count  uint16
}

// allow records one Retry for source at now and reports whether it is within
// ssu2MaxRetriesPerSource for the current window.
func (l *ssu2RetryLimiter) allow(source netip.Prefix, now time.Time) bool {
	if l.seed == (maphash.Seed{}) {
		l.seed = maphash.MakeSeed()
	}
	window := now.UnixNano() / int64(ssu2RetryWindow)
	slot := &l.slots[maphash.Comparable(l.seed, source)%ssu2RetryLimiterSlots]
	if slot.source != source || slot.window != window {
		*slot = ssu2RetrySlot{source: source, window: window}
	}
	if slot.count >= ssu2MaxRetriesPerSource {
		return false
	}
	slot.count++
	return true
}

// allowRetryLocked reports whether a Retry may be sent to remote. TokenRequest
// and token-less SessionRequest packets are unauthenticated, so remote may be
// a spoofed victim address; the per-source bound limits that reflection.
//
// +checklocks:m.mu
func (m *SSU2Manager) allowRetryLocked(remote net.Addr) bool {
	source, ok := ssu2InboundSourceKey(remote)
	if !ok {
		return false
	}
	return m.retryLimits.allow(source, m.nowLocked())
}
