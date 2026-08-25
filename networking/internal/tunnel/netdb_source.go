package tunnel

import (
	"bytes"
	"context"
	"errors"
	ivnp "gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/network_database"
	"net/netip"
	"slices"
	"sync/atomic"
)

var (
	ErrNetDBBuildSourceConfig = errors.New("tunnel: invalid netdb build source configuration")
	ErrNoEligiblePeers        = errors.New("tunnel: insufficient eligible netdb peers")
)

const preferredRecoveryProbeInterval uint64 = 4

// NetDBOutboundBuildSourceConfig supplies deterministic control-plane inputs
// for selecting an outbound build path from already verified netdb entries.
type NetDBOutboundBuildSourceConfig struct {
	Table          *netdb.Table
	Profiles       *PeerProfiles
	LocalRouter    ivnp.Hash
	ReplyRouter    ivnp.Hash
	ReplyTunnelID  uint32
	Hops           int
	PreferredPeers []ivnp.Hash
	CandidateLimit int
	Lifetime       uint64
	CircuitID      func() uint32
	TunnelID       func() uint32
	Target         func(nowMillis uint64) ivnp.Hash
	Eligible       func(ivnp.Hash) bool
}

// NetDBOutboundBuildSource selects distinct ECIES-X25519 routers that were
// verified during netdb admission. It deliberately has no network I/O and is
// invoked only by Rotator maintenance.
type NetDBOutboundBuildSource struct {
	table            *netdb.Table
	profiles         *PeerProfiles
	local            ivnp.Hash
	replyRouter      ivnp.Hash
	replyTunnelID    uint32
	hops             int
	candidateLimit   int
	lifetime         uint64
	preferred        []netdb.RouterRef
	circuitID        func() uint32
	tunnelID         func() uint32
	target           func(uint64) ivnp.Hash
	eligible         func(ivnp.Hash) bool
	sequence         atomic.Uint64
	recoverySequence atomic.Uint64
}

func NewNetDBOutboundBuildSource(config NetDBOutboundBuildSourceConfig) (*NetDBOutboundBuildSource, error) {
	newNetDBOutboundBuildSourceRejected := config.Table == nil || config.Profiles == nil || (config.ReplyRouter == (ivnp.Hash{})) != (config.ReplyTunnelID == 0) || config.Hops < 1 || config.Hops > i2np.MaxVariableBuildRecords || config.Lifetime == 0 || config.CircuitID == nil
	if !newNetDBOutboundBuildSourceRejected {
		newNetDBOutboundBuildSourceRejected = config.TunnelID == nil
	}
	if newNetDBOutboundBuildSourceRejected {
		return nil, ErrNetDBBuildSourceConfig
	}
	if config.CandidateLimit == 0 {
		config.CandidateLimit = max(config.Hops, 128)
	}
	if config.CandidateLimit < config.Hops {
		return nil, ErrNetDBBuildSourceConfig
	}
	return &NetDBOutboundBuildSource{
		table: config.Table, profiles: config.Profiles, local: config.LocalRouter,
		replyRouter: config.ReplyRouter, replyTunnelID: config.ReplyTunnelID,
		hops: config.Hops, candidateLimit: config.CandidateLimit, lifetime: config.Lifetime,
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target, eligible: config.Eligible,
		preferred: retainPreferred(config.Table, config.PreferredPeers),
	}, nil
}

// NextOutbound returns a fresh path whose routers and receive tunnel IDs are
// distinct. Candidates with an unsupported static key or a recent profile
// failure majority are excluded before deterministic score ordering.
func (s *NetDBOutboundBuildSource) NextOutbound(ctx context.Context, nowMillis uint64) (OutboundBuild, error) {
	return s.NextOutboundForReply(ctx, nowMillis, ReplyRoute{Gateway: s.replyRouter, TunnelID: s.replyTunnelID})
}

// NextOutboundForReply selects a path using the supplied live inbound reply
// route. It is used by paired maintenance; callers cannot build an outbound
// tunnel without a concrete inbound route for its encrypted reply.
func (s *NetDBOutboundBuildSource) NextOutboundForReply(ctx context.Context, nowMillis uint64, route ReplyRoute) (OutboundBuild, error) {
	if route.Gateway == (ivnp.Hash{}) || route.TunnelID == 0 {
		return OutboundBuild{}, ErrNetDBBuildSourceConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return OutboundBuild{}, err
	}
	target := s.selectionTarget(nowMillis)
	candidates := s.table.ClosestInto(make([]netdb.RouterRef, s.candidateLimit), target)
	if s.eligible != nil {
		eligible := candidates[:0]
		for _, candidate := range candidates {
			if s.eligible(candidate.Hash) {
				eligible = append(eligible, candidate)
			}
		}
		candidates = eligible
	}
	hops := preferredHops(s.table, s.preferred, s.profiles, s.local, route.Gateway, s.hops, nowMillis)
	// Failure-majority profiles quarantine preferred peers without making the
	// quarantine permanent. Probe that bounded set periodically; on intervening
	// attempts use healthy verified routers so one broken explicit peer cannot
	// create a tight rebuild loop.
	if len(hops) < s.hops && s.recoverySequence.Add(1)%preferredRecoveryProbeInterval == 1 {
		hops = preferredHops(s.table, s.preferred, nil, s.local, route.Gateway, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, s.profiles, s.local, route.Gateway, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, nil, s.local, route.Gateway, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		return OutboundBuild{}, ErrNoEligiblePeers
	}
	for index := range hops {
		id := s.tunnelID()
		if id == 0 {
			return OutboundBuild{}, ErrNetDBBuildSourceConfig
		}
		for previous := range hops[:index] {
			if hops[previous].ReceiveTunnelID == id {
				return OutboundBuild{}, ErrNetDBBuildSourceConfig
			}
		}
		hops[index].ReceiveTunnelID = id
	}
	circuitID := s.circuitID()
	if circuitID == 0 {
		return OutboundBuild{}, ErrNetDBBuildSourceConfig
	}
	expiresAt := nowMillis + s.lifetime
	if expiresAt < nowMillis {
		expiresAt = ^uint64(0)
	}
	return OutboundBuild{
		CircuitID: circuitID, Hops: hops, ReplyRouter: route.Gateway,
		ReplyTunnelID: route.TunnelID, ExpiresAt: expiresAt,
	}, nil
}

func (s *NetDBOutboundBuildSource) selectionTarget(nowMillis uint64) ivnp.Hash {
	if s.target != nil {
		return s.target(nowMillis)
	}
	sequence := s.sequence.Add(1)
	var target ivnp.Hash
	for index := range 8 {
		target[24+index] = byte(sequence >> (56 - 8*index))
		target[16+index] = byte(nowMillis >> (56 - 8*index))
	}
	return target
}

// InboundBuildSource selects one inbound path and binds it to the outbound
// tunnel that carries its build request. An outbound tunnel ID of zero is the
// explicit startup-only fake zero-hop route.
type InboundBuildSource interface {
	NextInbound(context.Context, uint64, uint32) (InboundBuild, error)
}

// NetDBInboundBuildSourceConfig supplies deterministic control-plane inputs
// for selecting a new inbound path from verified netdb entries.
type NetDBInboundBuildSourceConfig struct {
	Table          *netdb.Table
	Profiles       *PeerProfiles
	LocalRouter    ivnp.Hash
	Hops           int
	PreferredPeers []ivnp.Hash
	CandidateLimit int
	Lifetime       uint64
	CircuitID      func() uint32
	TunnelID       func() uint32
	Target         func(nowMillis uint64) ivnp.Hash
	Eligible       func(ivnp.Hash) bool
}

// NetDBInboundBuildSource selects distinct ECIES-X25519 routers for an
// inbound path. Selection is synchronous and has no transport side effects.
type NetDBInboundBuildSource struct {
	table            *netdb.Table
	profiles         *PeerProfiles
	local            ivnp.Hash
	hops             int
	preferred        []netdb.RouterRef
	candidateLimit   int
	lifetime         uint64
	circuitID        func() uint32
	tunnelID         func() uint32
	target           func(uint64) ivnp.Hash
	eligible         func(ivnp.Hash) bool
	sequence         atomic.Uint64
	recoverySequence atomic.Uint64
}

func NewNetDBInboundBuildSource(config NetDBInboundBuildSourceConfig) (*NetDBInboundBuildSource, error) {
	newNetDBInboundBuildSourceRejected := config.Table == nil || config.Profiles == nil || config.LocalRouter == (ivnp.Hash{}) || config.Hops < 1 || config.Hops >= i2np.MaxVariableBuildRecords || config.Lifetime == 0 || config.CircuitID == nil
	if !newNetDBInboundBuildSourceRejected {
		newNetDBInboundBuildSourceRejected = config.TunnelID == nil
	}
	if newNetDBInboundBuildSourceRejected {
		return nil, ErrNetDBBuildSourceConfig
	}
	if config.CandidateLimit == 0 {
		config.CandidateLimit = max(config.Hops, 128)
	}
	if config.CandidateLimit < config.Hops {
		return nil, ErrNetDBBuildSourceConfig
	}
	return &NetDBInboundBuildSource{
		table: config.Table, profiles: config.Profiles, local: config.LocalRouter,
		hops: config.Hops, candidateLimit: config.CandidateLimit, lifetime: config.Lifetime,
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target, eligible: config.Eligible,
		preferred: retainPreferred(config.Table, config.PreferredPeers),
	}, nil
}

func (s *NetDBInboundBuildSource) NextInbound(ctx context.Context, nowMillis uint64, outboundTunnelID uint32) (InboundBuild, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return InboundBuild{}, err
	}
	target := s.selectionTarget(nowMillis)
	candidates := s.table.ClosestInto(make([]netdb.RouterRef, s.candidateLimit), target)
	if s.eligible != nil {
		eligible := candidates[:0]
		for _, candidate := range candidates {
			if s.eligible(candidate.Hash) {
				eligible = append(eligible, candidate)
			}
		}
		candidates = eligible
	}
	hops := preferredHops(s.table, s.preferred, s.profiles, s.local, ivnp.Hash{}, s.hops, nowMillis)
	// Keep a full pool expiry recoverable without retrying a quarantined
	// preferred peer on every maintenance tick.
	if len(hops) < s.hops && s.recoverySequence.Add(1)%preferredRecoveryProbeInterval == 1 {
		hops = preferredHops(s.table, s.preferred, nil, s.local, ivnp.Hash{}, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, s.profiles, s.local, ivnp.Hash{}, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, nil, s.local, ivnp.Hash{}, s.hops, nowMillis)
	}
	if len(hops) < s.hops {
		return InboundBuild{}, ErrNoEligiblePeers
	}
	for index := range hops {
		id := s.tunnelID()
		if id == 0 {
			return InboundBuild{}, ErrNetDBBuildSourceConfig
		}
		for previous := range hops[:index] {
			if hops[previous].ReceiveTunnelID == id {
				return InboundBuild{}, ErrNetDBBuildSourceConfig
			}
		}
		hops[index].ReceiveTunnelID = id
	}
	circuitID := s.circuitID()
	if circuitID == 0 {
		return InboundBuild{}, ErrNetDBBuildSourceConfig
	}
	expiresAt := nowMillis + s.lifetime
	if expiresAt < nowMillis {
		expiresAt = ^uint64(0)
	}
	return InboundBuild{
		CircuitID: circuitID, OutboundTunnelID: outboundTunnelID, Hops: hops, ExpiresAt: expiresAt,
	}, nil
}

func (s *NetDBInboundBuildSource) selectionTarget(nowMillis uint64) ivnp.Hash {
	if s.target != nil {
		return s.target(nowMillis)
	}
	sequence := s.sequence.Add(1)
	var target ivnp.Hash
	for index := range 8 {
		target[24+index] = byte(sequence >> (56 - 8*index))
		target[16+index] = byte(nowMillis >> (56 - 8*index))
	}
	return target
}

// NewNetDBBuildStaticKeyLookup binds BuildManager validation to retained,
// signature-verified RouterInfo identity encryption keys.
func NewNetDBBuildStaticKeyLookup(table *netdb.Table) BuildStaticKeyLookup {
	if table == nil {
		return nil
	}
	return func(peer ivnp.Hash) ([32]byte, bool) {
		ref, ok := table.Get(peer)
		if !ok {
			return [32]byte{}, false
		}
		return x25519StaticKey(ref.Info)
	}
}

func x25519StaticKey(info netdb.RouterInfo) ([32]byte, bool) {
	if info.Identity.CryptoKeyType() != ivnp.CryptoX25519 {
		return [32]byte{}, false
	}
	first, rest := info.Identity.CryptoKeyParts()
	if len(first) != 32 || len(rest) != 0 {
		return [32]byte{}, false
	}
	var key [32]byte
	copy(key[:], first)
	return key, true
}

type hopCandidate struct {
	hop    ShortBuildHop
	family string
	v4     []uint16
	v6     [][6]byte
	score  int64
}

func preferredHops(table *netdb.Table, preferred []netdb.RouterRef, profiles *PeerProfiles, local, excluded ivnp.Hash, wanted int, nowMillis uint64) []ShortBuildHop {
	if len(preferred) == 0 {
		return nil
	}
	refs := make([]netdb.RouterRef, 0, len(preferred))
	for _, retained := range preferred {
		ref := retained
		if current, ok := table.Get(retained.Hash); ok && current.Info.Published >= retained.Info.Published {
			ref = current
		}
		refs = append(refs, ref)
		if wanted == 1 {
			if hops := selectDiverseHops(refs[len(refs)-1:], profiles, local, excluded, 1, nowMillis); len(hops) == 1 {
				return hops
			}
		}
	}
	if wanted == 1 {
		return nil
	}
	return selectDiverseHops(refs, profiles, local, excluded, wanted, nowMillis)
}

func retainPreferred(table *netdb.Table, hashes []ivnp.Hash) []netdb.RouterRef {
	refs := make([]netdb.RouterRef, 0, len(hashes))
	for _, hash := range hashes {
		if ref, ok := table.Get(hash); ok {
			refs = append(refs, ref)
		}
	}
	return refs
}

// selectDiverseHops makes strict correlation avoidance win over score. It
// relaxes address-prefix conflicts first, then the signed router family only
// when the bounded candidate set cannot fill the requested path.
func selectDiverseHops(refs []netdb.RouterRef, profiles *PeerProfiles, local, excluded ivnp.Hash, wanted int, nowMillis uint64) []ShortBuildHop {
	candidates := make([]hopCandidate, 0, len(refs))
	for _, ref := range refs {
		if ref.Hash == local || ref.Hash == excluded || !profiles.Eligible(ref.Hash) || netdb.RouterInfoFresh(ref.Info, nowMillis) != nil {
			continue
		}
		key, ok := x25519StaticKey(ref.Info)
		if !ok {
			continue
		}
		family, v4, v6 := routerMetadata(ref.Info)
		candidates = append(candidates, hopCandidate{hop: ShortBuildHop{Router: ref.Hash, StaticKey: key}, family: family, v4: v4, v6: v6, score: profiles.Score(ref.Hash)})
	}
	slices.SortFunc(candidates, func(left, right hopCandidate) int {
		if left.score > right.score {
			return -1
		}
		if left.score < right.score {
			return 1
		}
		if hashLess(left.hop.Router, right.hop.Router) {
			return -1
		}
		if hashLess(right.hop.Router, left.hop.Router) {
			return 1
		}
		return 0
	})
	selected := make([]hopCandidate, 0, wanted)
	for tier := range 3 {
		for len(selected) < wanted {
			choice := -1
			choiceAddsFamily := false
			haveV4, haveV6 := selectedAddressFamilies(selected)
			for index, candidate := range candidates {
				if selectedContains(selected, candidate.hop.Router) {
					continue
				}
				if tier < 2 && familyConflict(selected, candidate) {
					continue
				}
				if tier == 0 && prefixConflict(selected, candidate) {
					continue
				}
				addsFamily := len(candidate.v4) != 0 && !haveV4 || len(candidate.v6) != 0 && !haveV6
				if choice == -1 || addsFamily && !choiceAddsFamily {
					choice, choiceAddsFamily = index, addsFamily
				}
			}
			if choice == -1 {
				break
			}
			selected = append(selected, candidates[choice])
		}
		if len(selected) == wanted {
			break
		}
	}
	hops := make([]ShortBuildHop, len(selected))
	for index := range selected {
		hops[index] = selected[index].hop
	}
	return hops
}

func selectedContains(selected []hopCandidate, hash ivnp.Hash) bool {
	for _, candidate := range selected {
		if candidate.hop.Router == hash {
			return true
		}
	}
	return false
}

func familyConflict(selected []hopCandidate, candidate hopCandidate) bool {
	if candidate.family == "" {
		return false
	}
	for _, current := range selected {
		if current.family == candidate.family {
			return true
		}
	}
	return false
}

func prefixConflict(selected []hopCandidate, candidate hopCandidate) bool {
	for _, current := range selected {
		for _, prefix := range candidate.v4 {
			if slices.Contains(current.v4, prefix) {
				return true
			}
		}
		for _, prefix := range candidate.v6 {
			if slices.Contains(current.v6, prefix) {
				return true
			}
		}
	}
	return false
}

func selectedAddressFamilies(selected []hopCandidate) (hasV4, hasV6 bool) {
	for _, candidate := range selected {
		hasV4 = hasV4 || len(candidate.v4) != 0
		hasV6 = hasV6 || len(candidate.v6) != 0
	}
	return hasV4, hasV6
}

func routerMetadata(info netdb.RouterInfo) (string, []uint16, [][6]byte) {
	var family string
	options := info.Options.Iterator()
	for {
		key, value, ok, err := options.Next()
		if err != nil || !ok {
			break
		}
		if bytes.Equal(key, []byte("family")) {
			family = string(value)
			break
		}
	}
	var v4 []uint16
	var v6 [][6]byte
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			break
		}
		options := address.Options.Iterator()
		for {
			key, value, ok, err := options.Next()
			if err != nil || !ok {
				break
			}
			if !bytes.Equal(key, []byte("host")) {
				continue
			}
			address, err := netip.ParseAddr(string(value))
			if err != nil {
				continue
			}
			if address.Is4() {
				raw := address.As4()
				v4 = append(v4, uint16(raw[0])<<8|uint16(raw[1]))
			} else if address.Is6() {
				raw := address.As16()
				v6 = append(v6, [6]byte(raw[:6]))
			}
		}
	}
	return family, v4, v6
}
