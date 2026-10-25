package tunnel

type creatorClaim struct {
	direction Direction
	retire    Entry
	target    int
	cutoff    uint64
	busy      *creatorAttempt
	refs      int
	done      bool
}

type creatorAttempt struct {
	manager    *BuildManager
	direction  Direction
	claim      *creatorClaim
	active     bool
	finished   bool
	maintained bool
	retire     Entry
}

// reserveCreator reserves a logical target before source selection or preflight.
// A timed-out attempt retains its claim but yields the active slot to a retry.
// +checklocksexclude:m.mu
func (m *BuildManager) reserveCreator(direction Direction, target, limit int, now, cutoff uint64) (*creatorAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := 0
	for attempt := range m.creators {
		if attempt.direction == direction {
			active++
		}
	}
	if active >= limit {
		return nil, nil
	}
	usable := m.pool.Count(direction, cutoff)
	reserved := 0
	var retry *creatorClaim
	retirements := make(map[uint32]struct{})
	for claim := range m.claims {
		if claim.direction != direction {
			continue
		}
		if claim.retire.ID != 0 {
			retirements[claim.retire.ID] = struct{}{}
		}
		if claim.done {
			continue
		}
		reserved++
		if claim.busy == nil && retry == nil {
			retry = claim
		}
	}
	if usable >= target || retry == nil && usable+reserved >= target {
		return nil, nil
	}
	if err := m.creatorAdmissionErrorLocked(); err != nil {
		m.creatorBudget.cancelWait(m)
		return nil, err
	}
	if !m.creatorBudget.acquireOrWait(m) {
		return nil, ErrBuildPending
	}
	attempt := m.newCreatorLocked(direction)
	attempt.maintained = true
	if retry == nil {
		retry = &creatorClaim{direction: direction, target: target, cutoff: cutoff}
		for _, id := range m.pool.renewalIDs(direction, now, cutoff) {
			if _, used := retirements[id]; !used {
				retry.retire, _ = m.pool.Get(id, now)
				break
			}
		}
		m.claims[retry] = struct{}{}
	}
	// Grace and retry attempts share retirement identity, but use the current window.
	retry.target, retry.cutoff = target, cutoff
	retry.busy = attempt
	retry.refs++
	attempt.claim = retry
	attempt.retire = retry.retire
	return attempt, nil
}

// +checklocksexclude:m.mu
func (m *BuildManager) acquireCreator(direction Direction, retireID uint32) (*creatorAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.creatorAdmissionErrorLocked(); err != nil {
		return nil, err
	}
	if !m.creatorBudget.tryAcquire(m) {
		return nil, ErrBuildPending
	}
	attempt := m.newCreatorLocked(direction)
	if m.pool != nil {
		if retireID != 0 {
			attempt.retire, _ = m.pool.Get(retireID, m.now())
		}
		attempt.claim = &creatorClaim{direction: direction, retire: attempt.retire, busy: attempt, refs: 1}
		m.claims[attempt.claim] = struct{}{}
	}
	return attempt, nil
}

// +checklocks:m.mu
func (m *BuildManager) creatorAdmissionErrorLocked() error {
	if m.released || m.ctx.Err() != nil {
		return ErrBuildConfig
	}
	active := m.pendingDirectionLocked(Inbound) + m.pendingDirectionLocked(Outbound)
	if active >= m.maxPending || len(m.recent)+active >= BuildReplyKeyCapacity(m.maxPending) {
		return ErrBuildPending
	}
	return nil
}

// +checklocks:m.mu
func (m *BuildManager) newCreatorLocked(direction Direction) *creatorAttempt {
	attempt := &creatorAttempt{manager: m, direction: direction, active: true}
	m.creators[attempt] = struct{}{}
	return attempt
}

// +checklocks:m.mu
func (m *BuildManager) timeoutCreatorLocked(a *creatorAttempt) {
	if a == nil || !a.active {
		return
	}
	a.active = false
	delete(m.creators, a)
	if a.claim != nil && a.claim.busy == a {
		a.claim.busy = nil
	}
	m.creatorBudget.release()
}

// +checklocks:m.mu
func (m *BuildManager) finishCreatorLocked(a *creatorAttempt) {
	if a == nil || a.finished {
		return
	}
	m.timeoutCreatorLocked(a)
	a.finished = true
	if a.claim != nil {
		a.claim.refs--
		if a.claim.refs == 0 && (!a.claim.done || a.claim.retire.ID == 0) {
			delete(m.claims, a.claim)
		}
	}
}

// +checklocksexclude:a.manager.mu
func (a *creatorAttempt) finish() {
	if a == nil {
		return
	}
	m := a.manager
	m.mu.Lock()
	m.finishCreatorLocked(a)
	m.mu.Unlock()
}

// +checklocksexclude:a.manager.mu
func (a *creatorAttempt) failPreparation() {
	if a == nil {
		return
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.finished {
		return
	}
	// A failed preparation cannot consume the capacity its own release exposes.
	if a.maintained {
		m.creatorBudget.cancelWait(m)
	}
	m.finishCreatorLocked(a)
}

// Replacement retires pool selection, not the runtime circuit: peers may still
// send to its advertised lease until ExpiresAt. Runtime.Expire owns that deadline.
// +checklocksexclude:m.mu
func (m *BuildManager) installCreatorEntry(entry Entry, attempt *creatorAttempt, retireID uint32, now uint64) (Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if attempt == nil {
		return m.pool.Replace(entry, retireID, now)
	}
	claim := attempt.claim
	if claim != nil && claim.done {
		return Entry{}, false, ErrBuildPending
	}
	target, cutoff := 0, uint64(0)
	if claim != nil {
		target, cutoff = claim.target, claim.cutoff
	}
	retired, replaced, err := m.pool.replaceCreator(entry, attempt.retire, target, cutoff, now)
	if err == nil && claim != nil {
		claim.done = true
		if claim.retire.ID == 0 {
			delete(m.claims, claim)
		}
	}
	return retired, replaced, err
}

// +checklocks:m.mu
func (m *BuildManager) finishRecentCreatorLocked(recent recentCreatorBuild) {
	if recent.outbound != nil {
		m.finishCreatorLocked(recent.outbound.build.attempt)
	}
	if recent.inbound != nil {
		m.finishCreatorLocked(recent.inbound.build.attempt)
	}
	if recent.variable != nil {
		m.finishCreatorLocked(recent.variable.build.attempt)
	}
}

// +checklocksexclude:p.mu
func (p *Pool) replaceCreator(entry, retire Entry, target int, cutoff, now uint64) (Entry, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if entry.ID == 0 || entry.Owner != p.owner {
		return Entry{}, false, ErrPoolOwner
	}
	if _, exists := p.tunnels[entry.ID]; exists {
		return Entry{}, false, ErrTunnelID
	}
	if current, exists := p.tunnels[retire.ID]; exists && current != retire {
		return Entry{}, false, ErrBuildPending
	}
	if target > 0 {
		usable := 0
		for _, current := range p.tunnels {
			if current.Direction == entry.Direction && current.Expires > max(now, cutoff) {
				usable++
			}
		}
		if usable >= target {
			return Entry{}, false, ErrBuildPending
		}
	}
	if len(p.tunnels) < p.max {
		p.tunnels[entry.ID] = entry
		return Entry{}, false, nil
	}
	if current, exists := p.tunnels[retire.ID]; exists && current == retire {
		delete(p.tunnels, retire.ID)
		p.tunnels[entry.ID] = entry
		return retire, true, nil
	}
	return Entry{}, false, ErrPoolFull
}
