package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
	"gosuda.org/ivnp/networking/internal/netdb"
)

var (
	ErrNetDBBuildSourceConfig = errors.New("tunnel: invalid netdb build source configuration")
	ErrNoEligiblePeers        = errors.New("tunnel: insufficient eligible netdb peers")
)

// NetDBOutboundBuildSourceConfig supplies deterministic control-plane inputs
// for selecting an outbound build path from already verified netdb entries.
type NetDBOutboundBuildSourceConfig struct {
	Table          *netdb.Table
	Profiles       *PeerProfiles
	LocalRouter    foundation.Hash
	ReplyRouter    foundation.Hash
	ReplyTunnelID  uint32
	Hops           int
	CandidateLimit int
	Lifetime       uint64
	CircuitID      func() uint32
	TunnelID       func() uint32
	Target         func(nowMillis uint64) foundation.Hash
	Eligible       func(foundation.Hash) bool
	Reservations   *BuildReservations
}

// NetDBOutboundBuildSource selects distinct ECIES-X25519 routers that were
// verified during netdb admission. It deliberately has no network I/O and is
// invoked only by Rotator maintenance.
type NetDBOutboundBuildSource struct {
	table          *netdb.Table
	profiles       *PeerProfiles
	local          foundation.Hash
	replyRouter    foundation.Hash
	replyTunnelID  uint32
	hops           int
	candidateLimit int
	lifetime       uint64
	circuitID      func() uint32
	tunnelID       func() uint32
	target         func(uint64) foundation.Hash
	eligible       func(foundation.Hash) bool
	reservations   *BuildReservations
	sequence       atomic.Uint64
}

func NewNetDBOutboundBuildSource(config NetDBOutboundBuildSourceConfig) (*NetDBOutboundBuildSource, error) {
	newNetDBOutboundBuildSourceRejected := config.Table == nil || config.Profiles == nil || (config.ReplyRouter == (foundation.Hash{})) != (config.ReplyTunnelID == 0) || config.Hops < 1 || config.Hops > i2np.MaxVariableBuildRecords || config.Lifetime == 0 || config.CircuitID == nil
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
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target, eligible: config.Eligible, reservations: config.Reservations,
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
	if route.Gateway == (foundation.Hash{}) || route.TunnelID == 0 {
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
	if s.eligible != nil || s.reservations != nil {
		eligible := candidates[:0]
		for _, candidate := range candidates {
			if buildCandidateAvailable(candidate.Hash, s.eligible, s.reservations) {
				eligible = append(eligible, candidate)
			}
		}
		candidates = eligible
	}
	hops := selectDiverseHops(candidates, s.profiles, s.local, route.Gateway, s.hops, nowMillis, s.eligible != nil)
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, nil, s.local, route.Gateway, s.hops, nowMillis, s.eligible != nil)
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
	build := OutboundBuild{
		CircuitID: circuitID, Hops: hops, ReplyRouter: route.Gateway,
		ReplyTunnelID: route.TunnelID, ExpiresAt: expiresAt,
	}
	if s.reservations != nil {
		build.reservation = s.reservations.Reserve(hops)
		if build.reservation == nil {
			return OutboundBuild{}, ErrNoEligiblePeers
		}
	}
	return build, nil
}

func (s *NetDBOutboundBuildSource) selectionTarget(nowMillis uint64) foundation.Hash {
	if s.target != nil {
		return s.target(nowMillis)
	}
	sequence := s.sequence.Add(1)
	var target foundation.Hash
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
	LocalRouter    foundation.Hash
	Hops           int
	CandidateLimit int
	Lifetime       uint64
	CircuitID      func() uint32
	TunnelID       func() uint32
	Target         func(nowMillis uint64) foundation.Hash
	Eligible       func(foundation.Hash) bool
	Reservations   *BuildReservations
}

// NetDBInboundBuildSource selects distinct ECIES-X25519 routers for an
// inbound path. Selection is synchronous and has no transport side effects.
type NetDBInboundBuildSource struct {
	table          *netdb.Table
	profiles       *PeerProfiles
	local          foundation.Hash
	hops           int
	candidateLimit int
	lifetime       uint64
	circuitID      func() uint32
	tunnelID       func() uint32
	target         func(uint64) foundation.Hash
	eligible       func(foundation.Hash) bool
	reservations   *BuildReservations
	sequence       atomic.Uint64
}

func NewNetDBInboundBuildSource(config NetDBInboundBuildSourceConfig) (*NetDBInboundBuildSource, error) {
	newNetDBInboundBuildSourceRejected := config.Table == nil || config.Profiles == nil || config.LocalRouter == (foundation.Hash{}) || config.Hops < 1 || config.Hops >= i2np.MaxVariableBuildRecords || config.Lifetime == 0 || config.CircuitID == nil
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
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target, eligible: config.Eligible, reservations: config.Reservations,
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
	if s.eligible != nil || s.reservations != nil {
		eligible := candidates[:0]
		for _, candidate := range candidates {
			if buildCandidateAvailable(candidate.Hash, s.eligible, s.reservations) {
				eligible = append(eligible, candidate)
			}
		}
		candidates = eligible
	}
	hops := selectDiverseHops(candidates, s.profiles, s.local, foundation.Hash{}, s.hops, nowMillis, s.eligible != nil)
	if len(hops) < s.hops {
		hops = selectDiverseHops(candidates, nil, s.local, foundation.Hash{}, s.hops, nowMillis, s.eligible != nil)
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
	build := InboundBuild{
		CircuitID: circuitID, OutboundTunnelID: outboundTunnelID, Hops: hops, ExpiresAt: expiresAt,
	}
	if s.reservations != nil {
		build.reservation = s.reservations.Reserve(hops)
		if build.reservation == nil {
			return InboundBuild{}, ErrNoEligiblePeers
		}
	}
	return build, nil
}

func (s *NetDBInboundBuildSource) selectionTarget(nowMillis uint64) foundation.Hash {
	if s.target != nil {
		return s.target(nowMillis)
	}
	sequence := s.sequence.Add(1)
	var target foundation.Hash
	for index := range 8 {
		target[24+index] = byte(sequence >> (56 - 8*index))
		target[16+index] = byte(nowMillis >> (56 - 8*index))
	}
	return target
}

func buildCandidateAvailable(peer foundation.Hash, eligible func(foundation.Hash) bool, reservations *BuildReservations) bool {
	if eligible != nil && !eligible(peer) {
		return false
	}
	return reservations == nil || reservations.Available(peer)
}

func availablePreferred(preferred []netdb.RouterRef, reservations *BuildReservations) []netdb.RouterRef {
	if reservations == nil {
		return preferred
	}
	available := make([]netdb.RouterRef, 0, len(preferred))
	for _, candidate := range preferred {
		if reservations.Available(candidate.Hash) {
			available = append(available, candidate)
		}
	}
	return available
}

// NewNetDBBuildStaticKeyLookup binds BuildManager validation to retained,
// signature-verified RouterInfo identity encryption keys.
func NewNetDBBuildStaticKeyLookup(table *netdb.Table) BuildStaticKeyLookup {
	if table == nil {
		return nil
	}
	return func(peer foundation.Hash) ([32]byte, bool) {
		ref, ok := table.Get(peer)
		if !ok {
			return [32]byte{}, false
		}
		return x25519StaticKey(ref.Info)
	}
}

func x25519StaticKey(info netdb.RouterInfo) ([32]byte, bool) {
	if info.Identity.CryptoKeyType() != foundation.CryptoX25519 {
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

type tunnelTransportMask uint8

const (
	tunnelNTCP2V4 tunnelTransportMask = 1 << iota
	tunnelNTCP2V6
	tunnelSSU2V4
	tunnelSSU2V6
)

type hopCandidate struct {
	hop        ShortBuildHop
	family     string
	v4         []uint16
	v6         [][6]byte
	transports tunnelTransportMask
	score      int64
}

// selectDiverseHops makes strict correlation avoidance win over score. It
// relaxes address-prefix conflicts first, then the signed router family only
// when the bounded candidate set cannot fill the requested path. An injected
// eligibility policy is authoritative when test or embedded transports do not
// publish an address mask.
func selectDiverseHops(refs []netdb.RouterRef, profiles *PeerProfiles, local, excluded foundation.Hash, wanted int, nowMillis uint64, allowUnknownTransports bool) []ShortBuildHop {
	candidates := make([]hopCandidate, 0, len(refs))
	for _, ref := range refs {
		if ref.Hash == local || ref.Hash == excluded || !profiles.EligibleAt(ref.Hash, nowMillis) || netdb.RouterInfoFresh(ref.Info, nowMillis) != nil || !tunnelPeerCapsAllowed(ref.Info) {
			continue
		}
		key, ok := x25519StaticKey(ref.Info)
		if !ok {
			continue
		}
		transports := tunnelPeerTransportMask(ref.Info)
		if transports == 0 && !allowUnknownTransports {
			continue
		}
		family, v4, v6 := routerMetadata(ref.Info)
		candidates = append(candidates, hopCandidate{
			hop: ShortBuildHop{Router: ref.Hash, StaticKey: key}, family: family,
			v4: v4, v6: v6, transports: transports, score: profiles.Score(ref.Hash),
		})
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
				if !tunnelPathCompatible(selected, candidate) {
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

func tunnelPathCompatible(selected []hopCandidate, candidate hopCandidate) bool {
	if len(selected) == 0 || selected[len(selected)-1].transports == 0 || candidate.transports == 0 {
		return true
	}
	return selected[len(selected)-1].transports&candidate.transports != 0
}

func tunnelPeerCapsAllowed(info netdb.RouterInfo) bool {
	options := info.Options.Iterator()
	for {
		key, value, ok, err := options.Next()
		if err != nil || !ok {
			return err == nil
		}
		if !bytes.Equal(key, []byte("caps")) {
			continue
		}
		for _, capability := range value {
			switch capability {
			case 'H', 'U', 'K', 'E', 'G':
				return false
			}
		}
		return true
	}
}

func tunnelPeerTransportMask(info netdb.RouterInfo) tunnelTransportMask {
	var mask tunnelTransportMask
	addresses := info.Addresses()
	for {
		address, ok, err := addresses.Next()
		if err != nil || !ok {
			return mask
		}
		var host, caps, version []byte
		options := address.Options.Iterator()
		for {
			key, value, optionOK, optionErr := options.Next()
			if optionErr != nil || !optionOK {
				break
			}
			switch {
			case bytes.Equal(key, []byte("host")):
				host = value
			case bytes.Equal(key, []byte("caps")):
				caps = value
			case bytes.Equal(key, []byte("v")):
				version = value
			}
		}
		v4, v6 := tunnelAddressFamilies(host, caps)
		switch {
		case bytes.Equal(address.TransportStyle, []byte("NTCP2")):
			if v4 {
				mask |= tunnelNTCP2V4
			}
			if v6 {
				mask |= tunnelNTCP2V6
			}
		case bytes.Equal(address.TransportStyle, []byte("SSU2")) ||
			bytes.Equal(address.TransportStyle, []byte("SSU")) && bytes.IndexByte(version, '2') >= 0:
			if v4 {
				mask |= tunnelSSU2V4
			}
			if v6 {
				mask |= tunnelSSU2V6
			}
		}
	}
}

func tunnelAddressFamilies(host, caps []byte) (v4, v6 bool) {
	if len(host) != 0 {
		if bytes.IndexByte(host, ':') >= 0 {
			return false, true
		}
		return true, false
	}
	return bytes.IndexByte(caps, '4') >= 0, bytes.IndexByte(caps, '6') >= 0
}

func selectedContains(selected []hopCandidate, hash foundation.Hash) bool {
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
