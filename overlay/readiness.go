package overlay

// HostState is the dual-stack context readiness state.
type HostState uint8

const (
	HostStarting HostState = iota + 1
	HostI2POnlyReady
	HostIVNPOnlyReady
	HostDualReady
	HostDegraded
	HostStopping
	HostStopped
)

// Evidence is independent readiness proof for one axis. Each field comes from
// its own measurement; none may borrow another's result.
type Evidence struct {
	I2PConnectivity  bool
	IVNPConnectivity bool
	PublicLookup     bool
	IVNPLookup       bool
	MembershipFresh  bool
	PublicationFresh bool
	NativePathReady  bool
	FastPathReady    bool
	PolicySatisfied  bool
}

// DualReadyEvidence is the minimum for DUAL_READY: both contexts ready and an
// independent native lookup path maintained. Individual endpoint readiness
// still depends on leases, contact, and policy.
func (e Evidence) DualReadyEvidence() bool {
	return e.I2PConnectivity && e.IVNPConnectivity && e.PublicLookup && e.IVNPLookup
}

// Readiness is the multidimensional service view: each axis reports
// separately, never collapsed into one healthy bit.
type Readiness struct {
	LocalConnectivity    bool
	MembershipFresh      bool
	PublicLookup         bool
	PublicationCurrent   bool
	ServiceAccepting     bool
	RoutePolicySatisfied bool
	FallbackReady        bool
}

// Evaluate maps evidence and lifecycle intent to a host state. A previously
// ready host with stale required evidence degrades rather than tearing down
// still-authorized flows.
func EvaluateHostState(e Evidence, stopping, previouslyReady bool) HostState {
	switch {
	case stopping:
		return HostStopping
	case e.DualReadyEvidence():
		return HostDualReady
	case e.I2PConnectivity:
		if previouslyReady {
			return HostDegraded
		}
		return HostI2POnlyReady
	case e.IVNPConnectivity:
		if previouslyReady {
			return HostDegraded
		}
		return HostIVNPOnlyReady
	default:
		if previouslyReady {
			return HostDegraded
		}
		return HostStarting
	}
}
