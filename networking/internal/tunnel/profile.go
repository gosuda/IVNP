package tunnel

import (
	"gosuda.org/ivnp/foundation"
	"sync"
)

const (
	defaultProfilePeers   = 512
	defaultProfileWindow  = 32
	maxProfileWindow      = 64
	profileSuccessWeight  = 10_000
	profileFailurePenalty = 20_000
	profileLatencyCap     = 10_000
)

// ObservationKind identifies the authenticated tunnel outcome being scored.
type ObservationKind uint8

const (
	BuildObservation ObservationKind = iota + 1
	DeliveryObservation
)

// Observation is the only production profile input. AtMillis is retained for
// callers that need an audit timestamp; rolling score arithmetic uses only the
// authenticated terminal outcome and measured latency.
type Observation struct {
	Kind          ObservationKind
	Success       bool
	LatencyMillis uint64
	AtMillis      uint64
}

// PeerProfilesConfig bounds the retained outcome history for tunnel peers.
// A window contains the most recent success, failure, and latency observations
// for one peer; no unbounded aggregate is retained.
type PeerProfilesConfig struct {
	MaxPeers int
	Window   int
}

// PeerProfile is a stable snapshot of a peer's recent tunnel-test outcomes.
type PeerProfile struct {
	Successes   int
	Failures    int
	MeanLatency uint64
	Samples     int
}

type profileSample struct {
	kind    ObservationKind
	success bool
	latency uint64
}

type peerProfileState struct {
	samples [maxProfileWindow]profileSample
	next    int
	count   int
}

// PeerProfiles retains a bounded rolling outcome history per peer. Its score
// is intentionally integral and deterministic: successful probes improve a
// score, failures cost twice as much, and lower mean latency wins ties.
type PeerProfiles struct {
	mu       sync.RWMutex
	maxPeers int
	window   int
	peers    map[foundation.Hash]peerProfileState
}

func NewPeerProfiles(config PeerProfilesConfig) *PeerProfiles {
	if config.MaxPeers <= 0 {
		config.MaxPeers = defaultProfilePeers
	}
	if config.Window <= 0 {
		config.Window = defaultProfileWindow
	}
	if config.Window > maxProfileWindow {
		config.Window = maxProfileWindow
	}
	return &PeerProfiles{maxPeers: config.MaxPeers, window: config.Window, peers: make(map[foundation.Hash]peerProfileState)}
}

// Record stores one terminal authenticated build or delivery observation.
func (p *PeerProfiles) Record(peer foundation.Hash, observation Observation) {
	recordRejected := p == nil || peer == (foundation.Hash{})
	if !recordRejected {
		recordRejected = (observation.Kind != BuildObservation && observation.Kind != DeliveryObservation)
	}
	if recordRejected {
		return
	}
	p.record(peer, profileSample{kind: observation.Kind, success: observation.Success, latency: observation.LatencyMillis})
}

// RecordSuccess preserves the pre-observation API for callers outside the
// tunnel control plane.
func (p *PeerProfiles) RecordSuccess(peer foundation.Hash, latency uint64) {
	p.Record(peer, Observation{Kind: DeliveryObservation, Success: true, LatencyMillis: latency})
}

// RecordFailure preserves the pre-observation API for callers outside the
// tunnel control plane.
func (p *PeerProfiles) RecordFailure(peer foundation.Hash) {
	p.Record(peer, Observation{Kind: DeliveryObservation})
}

func (p *PeerProfiles) record(peer foundation.Hash, sample profileSample) {
	p.mu.Lock()
	state, exists := p.peers[peer]
	if !exists && len(p.peers) >= p.maxPeers {
		p.evictLocked()
	}
	state.samples[state.next] = sample
	if state.count < p.window {
		state.count++
	}
	state.next = (state.next + 1) % p.window
	p.peers[peer] = state
	p.mu.Unlock()
}

// Snapshot returns the recent outcome summary for peer.
func (p *PeerProfiles) Snapshot(peer foundation.Hash) (PeerProfile, bool) {
	if p == nil {
		return PeerProfile{}, false
	}
	p.mu.RLock()
	state, ok := p.peers[peer]
	if !ok {
		p.mu.RUnlock()
		return PeerProfile{}, false
	}
	profile := profileFromState(state)
	p.mu.RUnlock()
	return profile, true
}

// Eligible reports whether a peer may be selected for a new tunnel. Unknown
// verified peers remain eligible so a profile can be established. Authenticated
// build outcomes decide build compatibility when present; an end-to-end
// delivery timeout is retained for scoring but cannot identify which peer in a
// multi-hop pair failed and therefore cannot override successful build proof.
func (p *PeerProfiles) Eligible(peer foundation.Hash) bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	state, ok := p.peers[peer]
	if !ok {
		p.mu.RUnlock()
		return true
	}
	buildSuccesses, buildFailures := 0, 0
	for _, sample := range state.samples[:state.count] {
		if sample.kind != BuildObservation {
			continue
		}
		if sample.success {
			buildSuccesses++
		} else {
			buildFailures++
		}
	}
	profile := profileFromState(state)
	p.mu.RUnlock()
	if buildSuccesses+buildFailures != 0 {
		return buildSuccesses >= buildFailures
	}
	return profile.Successes >= profile.Failures
}

// Score returns peer's deterministic build preference. Higher values are
// preferred; hash order is the required tie-breaker for callers selecting a
// path. Unknown peers score zero.
func (p *PeerProfiles) Score(peer foundation.Hash) int64 {
	profile, ok := p.Snapshot(peer)
	if !ok {
		return 0
	}
	latency := min(profile.MeanLatency, profileLatencyCap)
	return int64(profile.Successes*profileSuccessWeight-profile.Failures*profileFailurePenalty) - int64(latency)
}

func (p *PeerProfiles) evictLocked() {
	var victim foundation.Hash
	var victimScore int64
	first := true
	for peer, state := range p.peers {
		score := scoreProfile(profileFromState(state))
		evictLockedSelected := first || score < victimScore
		if !evictLockedSelected {
			evictLockedSelected = (score == victimScore && hashLess(victim, peer))
		}
		if evictLockedSelected {
			victim, victimScore, first = peer, score, false
		}
	}
	delete(p.peers, victim)
}

func profileFromState(state peerProfileState) PeerProfile {
	profile := PeerProfile{Samples: state.count}
	var total uint64
	for _, sample := range state.samples[:state.count] {
		if sample.success {
			profile.Successes++
			if ^uint64(0)-total < sample.latency {
				total = ^uint64(0)
			} else {
				total += sample.latency
			}
		} else {
			profile.Failures++
		}
	}
	if profile.Successes != 0 {
		profile.MeanLatency = total / uint64(profile.Successes)
	}
	return profile
}

func scoreProfile(profile PeerProfile) int64 {
	latency := min(profile.MeanLatency, profileLatencyCap)
	return int64(profile.Successes*profileSuccessWeight-profile.Failures*profileFailurePenalty) - int64(latency)
}

func hashLess(left, right foundation.Hash) bool {
	for index := range left {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return false
}
