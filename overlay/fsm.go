package overlay

import (
	"sync"
)

// ConnState is the serialized connection-controller state.
type ConnState uint8

const (
	ConnNew ConnState = iota + 1
	ConnResolving
	ConnConnecting
	ConnActiveIVNP
	ConnActiveI2P
	ConnPathLost
	ConnResuming
	ConnReconnectRequired
	ConnDraining
	ConnClosed
	ConnFailed
)

// Terminal reports whether the state ends this connection attempt.
func (s ConnState) Terminal() bool {
	return s == ConnFailed || s == ConnReconnectRequired || s == ConnClosed
}

// connFSM serializes state for one connection attempt. All fields are guarded
// by mu; winner commitment and the state transition are one critical section,
// so a stale completion can never activate a route or observe a torn state.
type connFSM struct {
	mu               sync.Mutex
	state            ConnState
	winner           bool
	mayHaveDelivered bool
}

func newConnFSM() *connFSM { return &connFSM{state: ConnNew} }

func (f *connFSM) State() ConnState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *connFSM) deliveredPossible() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mayHaveDelivered
}

// transition moves the state under the caller-held lock.
func (f *connFSM) transition(to ConnState, from ...ConnState) error {
	for _, s := range from {
		if f.state == s {
			f.state = to
			return nil
		}
	}
	return CodeContextScopeMismatch.Wrap("illegal connection state transition")
}

// Begin starts the attempt; target/policy validation precedes it.
func (f *connFSM) Begin() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transition(ConnResolving, ConnNew)
}

// ContactFound launches a permitted setup.
func (f *connFSM) ContactFound() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transition(ConnConnecting, ConnResolving)
}

// ResolveExhausted fails with the exact lookup limitation.
func (f *connFSM) ResolveExhausted() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transition(ConnFailed, ConnResolving)
}

// CandidateRejected drops one candidate; alternatives may keep connecting.
func (f *connFSM) CandidateRejected(alternatesRemain bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if alternatesRemain {
		return f.transition(ConnConnecting, ConnConnecting)
	}
	return f.transition(ConnFailed, ConnConnecting)
}

// Winner-slot markers for the single-commit protocol.
const (
	slotFree    = false
	slotClaimed = true
)

// Commit atomically wins a fully authenticated candidate. Only the first
// commit transitions; late successes drain without exposing application I/O.
func (f *connFSM) Commit(class RouteClass) (ConnState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != ConnConnecting {
		return f.state, CodeContextScopeMismatch.Wrap("commit outside connecting state")
	}
	if f.winner {
		// A second commit must not report the active state: the caller would
		// bind a session to the losing channel as if it had won.
		return f.state, CodeContextScopeMismatch.Wrap("winner already committed")
	}
	switch class {
	case RouteDirect, RouteRouted:
		f.winner = slotClaimed
		f.state = ConnActiveIVNP
	case RouteNativeI2P:
		f.winner = slotClaimed
		f.state = ConnActiveI2P
	default:
		return f.state, CodeInvalidConfig.Wrap("unknown route class")
	}
	return f.state, nil
}

// PathLost stops new submissions and classifies possibly delivered data.
func (f *connFSM) PathLost(deliveredPossible bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.transition(ConnPathLost, ConnActiveIVNP, ConnActiveI2P); err != nil {
		return err
	}
	f.mayHaveDelivered = deliveredPossible
	return nil
}

// BeginResume requires a negotiated compatible resumption contract.
func (f *connFSM) BeginResume(contractAvailable bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.mayHaveDelivered {
		if err := f.transition(ConnConnecting, ConnPathLost); err != nil {
			return err
		}
		f.winner = slotFree
		return nil
	}
	if !contractAvailable {
		return f.transition(ConnReconnectRequired, ConnPathLost)
	}
	return f.transition(ConnResuming, ConnPathLost)
}

// ResumeCommitted reconciles onto the actual path.
func (f *connFSM) ResumeCommitted(class RouteClass) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	to := ConnActiveIVNP
	if class == RouteNativeI2P {
		to = ConnActiveI2P
	}
	return f.transition(to, ConnResuming)
}

// ResumeFailed never fabricates accepted offsets.
func (f *connFSM) ResumeFailed() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transition(ConnReconnectRequired, ConnResuming)
}

// Revoke stops newly forbidden work and drains.
func (f *connFSM) Revoke() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.state {
	case ConnFailed, ConnReconnectRequired, ConnClosed, ConnDraining:
		return nil
	}
	f.state = ConnDraining
	return nil
}

// Drained finalizes accounting once all owned work joined.
func (f *connFSM) Drained() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transition(ConnClosed, ConnDraining)
}
