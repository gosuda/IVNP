package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"

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
	Table                  *netdb.Table
	Profiles               *PeerProfiles
	LocalRouter            foundation.Hash
	ReplyRouter            foundation.Hash
	ReplyTunnelID          uint32
	Hops                   int
	CandidateLimit         int
	Lifetime               uint64
	CircuitID              func() uint32
	TunnelID               func() uint32
	Target                 func(nowMillis uint64) foundation.Hash
	Eligible               func(foundation.Hash) bool
	Exploratory            bool
	AllowUnknownTransports bool
}

// NetDBOutboundBuildSource selects distinct ECIES-X25519 routers that were
// verified during netdb admission. It deliberately has no network I/O and is
// invoked only by Rotator maintenance.
type NetDBOutboundBuildSource struct {
	table                  *netdb.Table
	profiles               *PeerProfiles
	local                  foundation.Hash
	replyRouter            foundation.Hash
	replyTunnelID          uint32
	hops                   int
	candidateLimit         int
	lifetime               uint64
	circuitID              func() uint32
	tunnelID               func() uint32
	target                 func(uint64) foundation.Hash
	eligible               func(foundation.Hash) bool
	exploratory            bool
	allowUnknownTransports bool
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
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target,
		eligible: config.Eligible, exploratory: config.Exploratory,
		allowUnknownTransports: config.AllowUnknownTransports,
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
	target, err := s.selectionTarget(nowMillis)
	if err != nil {
		return OutboundBuild{}, err
	}
	candidates := s.table.ClosestInto(make([]netdb.RouterRef, s.candidateLimit), target)
	var endpointMask tunnelTransportMask
	if reply, ok := s.table.Get(route.Gateway); ok {
		endpointMask = tunnelPeerTransportMask(reply.Info)
	}
	policy := peerSelectionPolicy{
		direction: Outbound, exploratory: s.exploratory, directFirst: true,
		eligible: s.eligible, endpointMask: endpointMask, chance: target[0],
		allowUnknownTransports: s.allowUnknownTransports,
	}
	hops := selectDiverseHops(candidates, s.profiles, s.local, route.Gateway, s.hops, nowMillis, policy)
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
	return build, nil
}

func (s *NetDBOutboundBuildSource) selectionTarget(nowMillis uint64) (foundation.Hash, error) {
	if s.target != nil {
		return s.target(nowMillis), nil
	}
	var target foundation.Hash
	_, err := rand.Read(target[:])
	return target, err
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
	Table                  *netdb.Table
	Profiles               *PeerProfiles
	LocalRouter            foundation.Hash
	Hops                   int
	CandidateLimit         int
	Lifetime               uint64
	CircuitID              func() uint32
	TunnelID               func() uint32
	Target                 func(nowMillis uint64) foundation.Hash
	Eligible               func(foundation.Hash) bool
	Exploratory            bool
	AllowUnknownTransports bool
}

// NetDBInboundBuildSource selects distinct ECIES-X25519 routers for an
// inbound path. Selection is synchronous and has no transport side effects.
type NetDBInboundBuildSource struct {
	table                  *netdb.Table
	profiles               *PeerProfiles
	local                  foundation.Hash
	hops                   int
	candidateLimit         int
	lifetime               uint64
	circuitID              func() uint32
	tunnelID               func() uint32
	target                 func(uint64) foundation.Hash
	eligible               func(foundation.Hash) bool
	exploratory            bool
	allowUnknownTransports bool
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
		circuitID: config.CircuitID, tunnelID: config.TunnelID, target: config.Target,
		eligible: config.Eligible, exploratory: config.Exploratory,
		allowUnknownTransports: config.AllowUnknownTransports,
	}, nil
}

func (s *NetDBInboundBuildSource) NextInbound(ctx context.Context, nowMillis uint64, outboundTunnelID uint32) (InboundBuild, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return InboundBuild{}, err
	}
	target, err := s.selectionTarget(nowMillis)
	if err != nil {
		return InboundBuild{}, err
	}
	candidates := s.table.ClosestInto(make([]netdb.RouterRef, s.candidateLimit), target)
	policy := peerSelectionPolicy{
		direction: Inbound, exploratory: s.exploratory, directFirst: outboundTunnelID == 0,
		eligible: s.eligible, chance: target[0], allowUnknownTransports: s.allowUnknownTransports,
	}
	hops := selectDiverseHops(candidates, s.profiles, s.local, foundation.Hash{}, s.hops, nowMillis, policy)
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
	return build, nil
}

func (s *NetDBInboundBuildSource) selectionTarget(nowMillis uint64) (foundation.Hash, error) {
	if s.target != nil {
		return s.target(nowMillis), nil
	}
	var target foundation.Hash
	_, err := rand.Read(target[:])
	return target, err
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
	tier       uint8
	reachable  bool
}

type peerSelectionPolicy struct {
	direction              Direction
	exploratory            bool
	directFirst            bool
	allowUnknownTransports bool
	eligible               func(foundation.Hash) bool
	endpointMask           tunnelTransportMask
	chance                 byte
}

// selectDiverseHops makes strict correlation avoidance win over score. It
// relaxes address-prefix conflicts first, then the signed router family only
// when the bounded candidate set cannot fill the requested path. An injected
// eligibility policy is authoritative when test or embedded transports do not
// publish an address mask.
func selectDiverseHops(refs []netdb.RouterRef, profiles *PeerProfiles, local, excluded foundation.Hash, wanted int, nowMillis uint64, policy peerSelectionPolicy) []ShortBuildHop {
	candidates := make([]hopCandidate, 0, len(refs))
	allowRestricted := policy.chance&3 == 0
	for _, ref := range refs {
		caps, allowed := tunnelPeerCapabilitiesAllowed(ref.Info, policy.exploratory, allowRestricted)
		if ref.Hash == local || ref.Hash == excluded || !profiles.EligibleAt(ref.Hash, nowMillis) || netdb.RouterInfoFresh(ref.Info, nowMillis) != nil || !allowed {
			continue
		}
		key, ok := x25519StaticKey(ref.Info)
		if !ok {
			continue
		}
		transports := tunnelPeerTransportMask(ref.Info)
		if transports == 0 && !policy.allowUnknownTransports {
			continue
		}
		family, v4, v6 := routerMetadata(ref.Info)
		score := profiles.Score(ref.Hash)
		tier := uint8(2)
		if policy.exploratory {
			if caps.highCapacity {
				tier = 0
			} else if score > 0 {
				tier = 1
			}
		} else if score > 0 {
			tier = 0
		} else if caps.highCapacity {
			tier = 1
		}
		candidates = append(candidates, hopCandidate{
			hop: ShortBuildHop{Router: ref.Hash, StaticKey: key}, family: family,
			v4: v4, v6: v6, transports: transports, tier: tier, reachable: caps.reachable,
		})
	}
	selected := make([]hopCandidate, 0, wanted)
	for relaxation := range 3 {
		for len(selected) < wanted {
			choice := selectDiverseHop(candidates, selected, wanted, relaxation, policy)
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
func selectDiverseHop(candidates, selected []hopCandidate, wanted, relaxation int, policy peerSelectionPolicy) int {
	haveV4, haveV6 := selectedAddressFamilies(selected)
	for peerTier := uint8(0); peerTier < 3; peerTier++ {
		choice := selectHopFromTier(candidates, selected, wanted, relaxation, peerTier, haveV4, haveV6, policy)
		if choice != -1 {
			return choice
		}
	}
	return -1
}

func selectHopFromTier(candidates, selected []hopCandidate, wanted, relaxation int, peerTier uint8, haveV4, haveV6 bool, policy peerSelectionPolicy) int {
	choice := -1
	choiceAddsFamily := false
	choiceFutureOptions := -1
	needsFuture := len(selected)+1 < wanted
	for index, candidate := range candidates {
		if !hopCandidateAllowed(candidate, selected, wanted, relaxation, peerTier, policy) {
			continue
		}
		futureOptions := hopFutureOptions(candidates, selected, candidate, wanted, policy)
		if needsFuture && futureOptions == 0 {
			continue
		}
		addsFamily := len(candidate.v4) != 0 && !haveV4 || len(candidate.v6) != 0 && !haveV6
		if choice == -1 {
			choice, choiceAddsFamily, choiceFutureOptions = index, addsFamily, futureOptions
			continue
		}
		if addsFamily && !choiceAddsFamily {
			choice, choiceAddsFamily, choiceFutureOptions = index, addsFamily, futureOptions
			continue
		}
		if addsFamily == choiceAddsFamily && futureOptions > choiceFutureOptions {
			choice, choiceAddsFamily, choiceFutureOptions = index, addsFamily, futureOptions
		}
	}
	return choice
}

func hopFutureOptions(candidates, selected []hopCandidate, candidate hopCandidate, wanted int, policy peerSelectionPolicy) int {
	options := 0
	for _, next := range candidates {
		if next.hop.Router == candidate.hop.Router || selectedContains(selected, next.hop.Router) {
			continue
		}
		if !peerAllowedAtPosition(next, len(selected)+1, wanted, policy) {
			continue
		}
		if candidate.transports == 0 || next.transports == 0 || candidate.transports&next.transports != 0 {
			options++
		}
	}
	return options
}

func hopCandidateAllowed(candidate hopCandidate, selected []hopCandidate, wanted, relaxation int, peerTier uint8, policy peerSelectionPolicy) bool {
	if candidate.tier != peerTier || selectedContains(selected, candidate.hop.Router) {
		return false
	}
	if !peerAllowedAtPosition(candidate, len(selected), wanted, policy) {
		return false
	}
	if !tunnelPathCompatible(selected, candidate) {
		return false
	}
	if relaxation < 2 && familyConflict(selected, candidate) {
		return false
	}
	return relaxation != 0 || !prefixConflict(selected, candidate)
}

func peerAllowedAtPosition(candidate hopCandidate, selected, wanted int, policy peerSelectionPolicy) bool {
	v4 := candidate.transports&(tunnelNTCP2V4|tunnelSSU2V4) != 0 || candidate.transports == 0 && policy.allowUnknownTransports
	if selected == 0 {
		if policy.direction == Inbound && (!candidate.reachable || !v4) {
			return false
		}
		if policy.directFirst && policy.eligible != nil && !policy.eligible(candidate.hop.Router) {
			return false
		}
	}
	if selected+1 == wanted && policy.direction == Outbound {
		if !v4 {
			return false
		}
		if policy.endpointMask != 0 && candidate.transports&policy.endpointMask == 0 {
			return false
		}
	}
	return true
}

func tunnelPathCompatible(selected []hopCandidate, candidate hopCandidate) bool {
	if len(selected) == 0 || selected[len(selected)-1].transports == 0 || candidate.transports == 0 {
		return true
	}
	return selected[len(selected)-1].transports&candidate.transports != 0
}

type tunnelPeerCapabilities struct {
	reachable    bool
	highCapacity bool
}

func tunnelPeerCapabilitiesAllowed(info netdb.RouterInfo, exploratory, allowRestricted bool) (tunnelPeerCapabilities, bool) {
	if info.Identity.SigningKeyType() == foundation.SigningDSASHA1 {
		return tunnelPeerCapabilities{}, false
	}
	version, caps, ok := tunnelPeerMetadata(info)
	if !ok {
		return tunnelPeerCapabilities{}, false
	}
	result, hasCapacity, floodfill, unreachable, allowed := parseTunnelPeerCapabilities(caps, allowRestricted)
	if !allowed || !hasCapacity {
		return tunnelPeerCapabilities{}, false
	}
	if floodfill && unreachable {
		return tunnelPeerCapabilities{}, false
	}
	if exploratory && floodfill && !allowRestricted {
		return tunnelPeerCapabilities{}, false
	}
	if unreachable && (!exploratory || !allowRestricted) {
		return tunnelPeerCapabilities{}, false
	}
	return result, i2pVersionAtLeast(version, 0, 9, 62)
}

func tunnelPeerMetadata(info netdb.RouterInfo) (version, caps []byte, ok bool) {
	options := info.Options.Iterator()
	for {
		key, value, next, err := options.Next()
		if err != nil {
			return nil, nil, false
		}
		if !next {
			return version, caps, true
		}
		if bytes.Equal(key, []byte("router.version")) {
			version = value
		}
		if bytes.Equal(key, []byte("caps")) {
			caps = value
		}
	}
}

func parseTunnelPeerCapabilities(caps []byte, allowRestricted bool) (result tunnelPeerCapabilities, hasCapacity, floodfill, unreachable, allowed bool) {
	for _, capability := range caps {
		if capability == 'K' || capability == 'G' {
			return tunnelPeerCapabilities{}, false, false, false, false
		}
		if capability == 'E' && !allowRestricted {
			return tunnelPeerCapabilities{}, false, false, false, false
		}
		switch capability {
		case 'F':
			floodfill = true
		case 'R':
			result.reachable = true
		case 'U':
			unreachable = true
		case 'O', 'P', 'X':
			result.highCapacity = true
		}
		if capability != 'F' && capability != 'R' && capability != 'U' {
			hasCapacity = true
		}
	}
	return result, hasCapacity, floodfill, unreachable, true
}

func i2pVersionAtLeast(version []byte, major, minor, patch uint64) bool {
	minimum := [...]uint64{major, minor, patch}
	offset := 0
	for component, required := range minimum {
		if offset >= len(version) || version[offset] < '0' || version[offset] > '9' {
			return false
		}
		var current uint64
		for offset < len(version) && version[offset] >= '0' && version[offset] <= '9' {
			current = current*10 + uint64(version[offset]-'0')
			offset++
		}
		if current != required {
			return current > required
		}
		if component < len(minimum)-1 {
			if offset >= len(version) || version[offset] != '.' {
				return false
			}
			offset++
		}
	}
	return true
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
