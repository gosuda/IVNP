package overlay

import (
	"context"
	"sync"
	"time"
)

// setupPlan carries the per-dial material every setup attempt shares: the
// effective policy, the verified admission request, the trust snapshot for
// peer membership verification, the release for the admission lease, and an
// optional resumption contract.
type setupPlan struct {
	target  ServiceTarget
	policy  DialPolicy
	eff     *effectivePolicy
	request *AdmissionRequest
	trust   *TrustState
	release func()
	resume  *ResumeContract
}

// dial executes the connection FSM over eligible candidates: resolve, admit,
// race at most MaxSetupCandidateLimit authenticated setups, commit one winner.
// No application data ever travels a losing candidate.
func dial(ctx context.Context, svc *Service, target ServiceTarget, policy DialPolicy, eff *effectivePolicy, resume *ResumeContract) (*Connection, error) {
	fsm := newConnFSM()
	if err := fsm.Begin(); err != nil {
		return nil, err
	}
	candidates, err := svc.realm.resolveCandidates(ctx, target, eff)
	if err != nil {
		fsm.ResolveExhausted()
		return nil, err
	}
	candidates = orderSetups(eligibleSetups(svc, candidates))
	attempts := expandAttempts(candidates, eff)
	if len(attempts) == 0 {
		fsm.ResolveExhausted()
		return nil, CodeUnreachable.Wrap("no eligible route candidate")
	}
	if err := fsm.ContactFound(); err != nil {
		return nil, err
	}
	if s := svc.realm.DiscoveryState(); s == DiscoveryPublicResolving || s == DiscoveryContactRevalidated {
		svc.realm.setDiscovery(ctx, DiscoveryReconnecting)
	}
	request, trust, release, err := svc.realm.admissionMaterial(ctx)
	if err != nil {
		_ = fsm.CandidateRejected(false)
		return nil, err
	}
	conn, err := raceSetups(ctx, svc, fsm, setupPlan{
		target: target, policy: policy, eff: eff,
		request: request, trust: trust, release: release, resume: resume,
	}, attempts)
	if err != nil {
		return nil, err
	}
	if svc.realm.DiscoveryState() == DiscoveryReconnecting {
		svc.realm.setDiscovery(ctx, DiscoveryHealthy)
	}
	if err := svc.registerConn(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

// orderSetups places IVNP route classes ahead of the native candidate: the
// eligible fast path launches first and the I2P native setup is the path
// hedge, never the reverse.
func orderSetups(in []RouteCandidate) []RouteCandidate {
	out := make([]RouteCandidate, 0, len(in))
	for _, c := range in {
		if c.Class != RouteNativeI2P {
			out = append(out, c)
		}
	}
	for _, c := range in {
		if c.Class == RouteNativeI2P {
			out = append(out, c)
		}
	}
	return out
}

// eligibleSetups keeps only candidates whose carrier has a registered provider
// with the required binding capability. The input may be shared across
// singleflight followers; it is never mutated.
func eligibleSetups(svc *Service, candidates []RouteCandidate) []RouteCandidate {
	providers := svc.realm.host.transportProviders()
	out := make([]RouteCandidate, 0, len(candidates))
	for _, c := range candidates {
		if carrierFor(providers, c) != nil {
			out = append(out, c)
		}
	}
	return out
}

func carrierFor(providers []TransportProvider, c RouteCandidate) TransportProvider {
	for _, p := range providers {
		if p.Carrier() != c.Carrier {
			continue
		}
		caps := p.Capabilities()
		switch c.Class {
		case RouteDirect:
			if caps.DirectBinding {
				return p
			}
		case RouteRouted:
			if caps.RoutedBinding {
				return p
			}
		case RouteNativeI2P:
			if caps.Exporter {
				return p
			}
		}
	}
	return nil
}

// setupAttempt is one bounded channel setup: a route candidate bound to one
// declared endpoint protocol. The protocol is authenticated inside the
// channel binding, so each allowed protocol is a distinct attempt.
type setupAttempt struct {
	candidate RouteCandidate
	protocol  EndpointProtocol
}

// expandAttempts emits one attempt per allowed endpoint protocol, preferred
// protocol first across every candidate. ivnp_preferred therefore tries IVNP
// on all routes before falling back to legacy; the fallback attempt binds the
// fallback protocol into its own authenticated scope rather than relabeling a
// channel negotiated under another protocol. The first native attempt is moved
// to position one so the hedge delay always launches the I2P setup — with
// several IVNP candidates a candidate-ordered list would hedge IVNP against
// IVNP instead of racing the public fallback.
func expandAttempts(candidates []RouteCandidate, eff *effectivePolicy) []setupAttempt {
	order := []EndpointProtocol{eff.protocol}
	for _, p := range []EndpointProtocol{EndpointProtocolIVNPStream, EndpointProtocolLegacyStream} {
		if p != eff.protocol && eff.allowsProtocol(p) {
			order = append(order, p)
		}
	}
	out := make([]setupAttempt, 0, len(candidates)*len(order))
	for _, protocol := range order {
		for _, c := range candidates {
			out = append(out, setupAttempt{candidate: c, protocol: protocol})
		}
	}
	for i := 1; i < len(out); i++ {
		if out[i].candidate.Class == RouteNativeI2P {
			out[1], out[i] = out[i], out[1]
			break
		}
	}
	return out
}

// raceSetups races setup attempts with at most MaxSetupCandidates in flight.
// The winner is the first fully authenticated attempt whose channel binding
// equals the requested scope, whose policy generation is still current, and
// whose peer membership verifies. A carrier that does not declare
// Capabilities().Speculative is never launched speculatively: it runs only
// when nothing else is in flight. In-flight losers are canceled; a setup that
// completes anyway is drained and its channel closed without exposing
// application I/O. The admission lease is released only after every launched
// attempt returns.
func raceSetups(ctx context.Context, svc *Service, fsm *connFSM, plan setupPlan, attempts []setupAttempt) (*Connection, error) {
	type outcome struct {
		channel Channel
		attempt setupAttempt
		scope   ChannelScope
		err     error
	}
	concurrency := min(plan.policy.MaxSetupCandidates, len(attempts))
	results := make(chan outcome, len(attempts))
	inner, cancel := context.WithCancel(ctx)
	defer cancel()
	deadline := time.NewTimer(plan.policy.SetupDeadline)
	defer deadline.Stop()

	var wg sync.WaitGroup
	// finish drains outcomes still in flight, waits for the launched attempts
	// to return, then releases the admission lease a setup may still hold.
	finish := func(inflight int) {
		go func() {
			for i := 0; i < inflight; i++ {
				if res := <-results; res.channel != nil {
					res.channel.Close()
				}
			}
			wg.Wait()
			plan.release()
		}()
	}

	providers := svc.realm.host.transportProviders()
	// speculative reports whether the attempt's carrier declares its setup
	// safe to race; a non-speculative carrier runs only once nothing else is
	// in flight.
	speculative := func(a setupAttempt) bool {
		provider := carrierFor(providers, a.candidate)
		return provider != nil && provider.Capabilities().Speculative
	}
	// nonSpecInFlight marks the in-flight set as containing a non-speculative
	// setup. At most one can be in flight: it launches only after every other
	// attempt finished, and while it runs no concurrent launch is permitted —
	// a handshake that can trigger remote application acceptance is never
	// raced, even as the already-running side of the pair.
	nonSpecInFlight := false
	launch := func(a setupAttempt) {
		if !speculative(a) {
			nonSpecInFlight = true
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			provider := carrierFor(providers, a.candidate)
			if provider == nil {
				results <- outcome{err: CodeUnsupportedCapability.Wrap("no carrier for candidate")}
				return
			}
			// PolicyGen carries the generation the eligibility intersection
			// was computed under — not a fresh read at launch. Stamping a
			// newer generation would let a route filtered under a superseded
			// policy pass the staleness check below.
			scope := ChannelScope{
				Fabric: a.candidate.Fabric, NetworkID: a.candidate.NetworkID, Realm: a.candidate.Realm,
				Endpoint: plan.target.Endpoint.ID, Port: plan.target.Port,
				Selector: plan.target.Protocol,
				Protocol: a.protocol, Class: a.candidate.Class,
				Exposure: a.candidate.Exposure, PolicyGen: plan.eff.gen,
			}
			channel, err := provider.Setup(inner, a.candidate, scope, plan.request)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			got, key := channel.Binding()
			// The channel's proven peer key must equal the candidate's
			// owner-authorized contact key whenever one is pinned; admission
			// requires a nonzero key for every non-native class, so only a
			// native candidate may reach setup unpinned.
			if got != scope || (key != a.candidate.ContactKey && a.candidate.ContactKey != ([32]byte{})) {
				channel.Close()
				results <- outcome{err: CodeEndpointBindingInvalid.Wrap("channel binding does not match the authorized scope")}
				return
			}
			// A completion carrying a policy generation the realm has since
			// replaced is stale and cannot activate a route.
			if scope.PolicyGen != svc.realm.PolicyGen() {
				channel.Close()
				results <- outcome{err: CodeRevisionConflict.Wrap("policy generation changed during setup")}
				return
			}
			if err := svc.realm.verifyPeerMembership(inner, channel, scope, key, plan.trust, a.candidate.CredentialDigest); err != nil {
				channel.Close()
				results <- outcome{err: err}
				return
			}
			results <- outcome{channel: channel, attempt: a, scope: scope}
		}()
	}

	launch(attempts[0])
	launched := 1
	hedge := time.NewTimer(plan.policy.HedgeDelay)
	defer hedge.Stop()
	hedgeFired := false
	var last error
	finished := 0
	// mayLaunch reports whether the next attempt may start: anything may
	// start once nothing is in flight, while a concurrent launch requires
	// both the next attempt and every in-flight attempt to be speculative.
	mayLaunch := func() bool {
		return launched < len(attempts) &&
			(launched == finished || (speculative(attempts[launched]) && !nonSpecInFlight))
	}
	for finished < len(attempts) {
		var hedgeC <-chan time.Time
		if launched < len(attempts) && !hedgeFired && launched-finished < concurrency {
			hedgeC = hedge.C
		}
		select {
		case <-ctx.Done():
			finish(launched - finished)
			return nil, ctx.Err()
		case <-deadline.C:
			finish(launched - finished)
			return nil, CodePublicUnavailable.Wrap("setup deadline exhausted")
		case <-hedgeC:
			hedgeFired = true
			if mayLaunch() {
				launch(attempts[launched])
				launched++
			}
		case res := <-results:
			finished++
			// While the flag is set the in-flight set is exactly one
			// non-speculative attempt, so any arriving result is its
			// completion.
			nonSpecInFlight = false
			if res.err != nil {
				if last == nil {
					last = res.err
				}
				if mayLaunch() {
					launch(attempts[launched])
					launched++
				}
				_ = fsm.CandidateRejected(finished < len(attempts) || launched < len(attempts))
				continue
			}
			state, err := fsm.Commit(res.attempt.candidate.Class)
			if err != nil {
				res.channel.Close()
				if last == nil {
					last = err
				}
				if mayLaunch() {
					launch(attempts[launched])
					launched++
				}
				continue
			}
			if state != ConnActiveIVNP && state != ConnActiveI2P {
				res.channel.Close()
				continue
			}
			cancel()
			finish(launched - finished)
			return bindSession(ctx, svc, fsm, res.channel, res.attempt, res.scope, plan)
		}
	}
	if last == nil {
		last = CodeUnreachable.Wrap("all setup candidates failed")
	}
	finish(launched - finished)
	return nil, last
}

// bindSession attaches the negotiated endpoint protocol to the committed
// channel. The negotiated protocol must equal the protocol declared in this
// attempt's channel binding and satisfy the effective policy; a missing
// session provider fails the dial rather than fabricating a protocol. With a
// resumption contract the session must come from a ResumableSessionProvider
// whose returned contract advances the fence; anything else is a resume
// mismatch.
func bindSession(ctx context.Context, svc *Service, fsm *connFSM, channel Channel, attempt setupAttempt, scope ChannelScope, plan setupPlan) (*Connection, error) {
	fail := func(err error) (*Connection, error) {
		_ = channel.Close()
		_ = fsm.Revoke()
		_ = fsm.Drained()
		return nil, err
	}
	sessions := svc.realm.host.sessionProvider()
	if sessions == nil {
		return fail(CodeUnsupportedCapability.Wrap("no session provider for endpoint protocol"))
	}
	var session Session
	if plan.resume != nil {
		resumable, ok := sessions.(ResumableSessionProvider)
		if !ok {
			return fail(CodeResumeNotSupported.Wrap("session provider cannot continue a negotiated session"))
		}
		resumed, err := resumable.Resume(ctx, channel, plan.target, *plan.resume)
		if err != nil {
			return fail(err)
		}
		next, err := resumed.Resume()
		if err != nil || !next.Supported || next.FenceToken <= plan.resume.FenceToken {
			_ = resumed.Close()
			return fail(CodeResumeStateMismatch.Wrap("resumed session did not reconcile and advance the fence"))
		}
		session = resumed
	} else {
		opened, err := sessions.Open(ctx, channel, plan.target)
		if err != nil {
			return fail(err)
		}
		session = opened
	}
	protocol := session.Protocol()
	if protocol != attempt.protocol || !plan.eff.allowsProtocol(protocol) {
		_ = session.Close()
		return fail(CodeEndpointBindingInvalid.Wrap("negotiated protocol outside the bound scope"))
	}
	candidate := attempt.candidate
	var contextID ContextID
	if nctx := svc.realm.boundFabric(candidate.Fabric); nctx != nil {
		contextID = nctx.id
	}
	conn := &Connection{
		Channel: channel, Session: session, owner: svc, fsm: fsm,
		dialTarget: plan.target, dialPolicy: plan.policy, eff: plan.eff,
		policyGen: scope.PolicyGen,
		route: RouteInfo{
			Endpoint: candidate.Endpoint, Port: plan.target.Port,
			Context: contextID,
			Fabric:  candidate.Fabric, NetworkID: candidate.NetworkID,
			Class: candidate.Class, Carrier: candidate.Carrier,
			Protocol: protocol, Exposure: candidate.Exposure,
			Provenance:    candidate.Provenance,
			FallbackReady: svc.realm.nativeFallbackReady(ctx),
		},
	}
	return conn, nil
}
