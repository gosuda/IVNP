package main

import (
	"net/http"
	"sync"
	"time"
)

const (
	historyInterval       = 5 * time.Second
	historyCapacity       = 720
	recentBuildWindow     = 600 * time.Second
	actionLogCapacity     = 50
	actionOutcomeOK       = "ok"
	actionOutcomeError    = "error"
	actionReseed          = "reseed"
	actionProbe           = "probe"
	actionRestart         = "restart"
	actionConfig          = "config"
	actionRollback        = "rollback"
	millisecondsPerSecond = int64(time.Second / time.Millisecond)
)

type historySample struct {
	T              int64  `json:"t"`
	InRateBPS      uint64 `json:"in_rate_bps"`
	OutRateBPS     uint64 `json:"out_rate_bps"`
	ActiveTunnels  uint64 `json:"active_tunnels"`
	BuildSuccesses uint64 `json:"build_successes"`
	BuildFailures  uint64 `json:"build_failures"`
	NetDBRouters   uint64 `json:"netdb_routers"`
	Floodfills     uint64 `json:"floodfills"`
	Goroutines     uint64 `json:"goroutines"`
	HeapInuseBytes uint64 `json:"heap_inuse_bytes"`
}

type historyResponse struct {
	IntervalSeconds int             `json:"interval_seconds"`
	Samples         []historySample `json:"samples"`
}

// historyRing retains the most recent telemetry samples across node restarts.
type historyRing struct {
	mu      sync.RWMutex
	samples [historyCapacity]historySample
	next    int
	count   int
}

func (h *historyRing) add(sample historySample) {
	h.mu.Lock()
	h.samples[h.next] = sample
	h.next = (h.next + 1) % historyCapacity
	h.count = min(h.count+1, historyCapacity)
	h.mu.Unlock()
}

// since returns retained samples taken at or after cutoff, oldest first.
func (h *historyRing) since(cutoff int64) []historySample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	samples := make([]historySample, 0, h.count)
	start := (h.next - h.count + historyCapacity) % historyCapacity
	for offset := range h.count {
		sample := h.samples[(start+offset)%historyCapacity]
		if sample.T >= cutoff {
			samples = append(samples, sample)
		}
	}
	return samples
}

// recentBuilds sums build counter growth over the recent window ending at the
// current counters. A counter decrease marks a node restart, so the value
// after the reset counts as growth.
func (h *historyRing) recentBuilds(now int64, successes, failures uint64) (windowSeconds int, successDelta, failureDelta uint64) {
	samples := h.since(now - int64(recentBuildWindow/time.Millisecond))
	if len(samples) == 0 {
		return 0, 0, 0
	}
	previousSuccesses, previousFailures := samples[0].BuildSuccesses, samples[0].BuildFailures
	accumulate := func(currentSuccesses, currentFailures uint64) {
		successDelta += counterGrowth(currentSuccesses, previousSuccesses)
		failureDelta += counterGrowth(currentFailures, previousFailures)
		previousSuccesses, previousFailures = currentSuccesses, currentFailures
	}
	for _, sample := range samples[1:] {
		accumulate(sample.BuildSuccesses, sample.BuildFailures)
	}
	accumulate(successes, failures)
	return int(max(0, now-samples[0].T) / millisecondsPerSecond), successDelta, failureDelta
}

func counterGrowth(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

type actionEntry struct {
	At      int64  `json:"at"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

type actionsLogResponse struct {
	Entries []actionEntry `json:"entries"`
}

// actionLog retains the most recent administrative actions in memory.
type actionLog struct {
	mu      sync.Mutex
	entries [actionLogCapacity]actionEntry
	next    int
	count   int
}

func (l *actionLog) record(action, outcome, detail string) {
	l.mu.Lock()
	l.entries[l.next] = actionEntry{At: time.Now().UnixMilli(), Action: action, Outcome: outcome, Detail: detail}
	l.next = (l.next + 1) % actionLogCapacity
	l.count = min(l.count+1, actionLogCapacity)
	l.mu.Unlock()
}

// newestFirst returns retained entries with the most recent first.
func (l *actionLog) newestFirst() []actionEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]actionEntry, 0, l.count)
	for offset := 1; offset <= l.count; offset++ {
		entries = append(entries, l.entries[(l.next-offset+actionLogCapacity)%actionLogCapacity])
	}
	return entries
}

func (s *WebUIServer) recordAction(action string, err error, detail string) {
	if err != nil {
		s.actions.record(action, actionOutcomeError, err.Error())
		return
	}
	s.actions.record(action, actionOutcomeOK, detail)
}

func (s *WebUIServer) recordHistory(now time.Time, snapshot ivnpObservabilitySnapshot) {
	s.trafficMu.RLock()
	traffic := s.traffic
	s.trafficMu.RUnlock()
	s.history.add(historySample{
		T: now.UnixMilli(), InRateBPS: traffic.inRate, OutRateBPS: traffic.outRate,
		ActiveTunnels: snapshot.Tunnel.Active, BuildSuccesses: snapshot.Tunnel.BuildSuccesses,
		BuildFailures: snapshot.Tunnel.BuildFailures, NetDBRouters: snapshot.NetDB.Routers,
		Floodfills: snapshot.NetDB.Floodfills, Goroutines: snapshot.Process.Goroutines,
		HeapInuseBytes: snapshot.Process.HeapInuseBytes,
	})
}

func (s *WebUIServer) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSONResponse(w, http.StatusOK, historyResponse{
		IntervalSeconds: int(historyInterval / time.Second),
		Samples:         s.history.since(0),
	})
}

func (s *WebUIServer) handleActionsLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSONResponse(w, http.StatusOK, actionsLogResponse{Entries: s.actions.newestFirst()})
}
