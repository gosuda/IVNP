package overlay

// Topology selects the context composition of a host profile.
type Topology uint8

const (
	TopologyNativeI2P Topology = iota + 1
	TopologyIsolated
	TopologyPublicDualStack
)

func (t Topology) valid() bool {
	return t >= TopologyNativeI2P && t <= TopologyPublicDualStack
}

// AdmissionMode is the realm admission requirement. Individual proof of key is
// mandatory in every mode.
type AdmissionMode uint8

const (
	AdmissionOpen AdmissionMode = iota + 1
	AdmissionCredential
	AdmissionPSK
	AdmissionCredentialPSK
)

func (a AdmissionMode) valid() bool {
	return a >= AdmissionOpen && a <= AdmissionCredentialPSK
}

func (a AdmissionMode) token() string {
	switch a {
	case AdmissionOpen:
		return "open"
	case AdmissionCredential:
		return "credential"
	case AdmissionPSK:
		return "psk"
	case AdmissionCredentialPSK:
		return "credential_psk"
	}
	return ""
}

func admissionFromToken(token string) (AdmissionMode, bool) {
	switch token {
	case "open":
		return AdmissionOpen, true
	case "credential":
		return AdmissionCredential, true
	case "psk":
		return AdmissionPSK, true
	case "credential_psk":
		return AdmissionCredentialPSK, true
	}
	return 0, false
}

// SybilAssurance reports what an admission mode proves about identity
// multiplication. It is reported, never negotiated.
type SybilAssurance uint8

const (
	// SybilUnboundedOpen: open mode permits arbitrary identity generation.
	SybilUnboundedOpen SybilAssurance = iota + 1
	// SybilSharedSecret: PSK mode proves shared-secret access, not one device
	// per identity.
	SybilSharedSecret
	// SybilConstrainedIssuer: credential issuance and simultaneous member slots
	// are bounded by a trusted issuer.
	SybilConstrainedIssuer
)

// admissionAtLeast reports whether an offered admission requirement tightens
// or equals the realm's mode — never weakens it. credential_psk is the strict
// combination; psk and credential both tighten open and are incomparable with
// each other.
func admissionAtLeast(offered, required AdmissionMode) bool {
	if offered == required {
		return true
	}
	switch required {
	case AdmissionOpen:
		return offered.valid()
	case AdmissionPSK, AdmissionCredential:
		return offered == AdmissionCredentialPSK
	}
	return false
}

// Assurance maps an admission mode to its identity-multiplication bound.
func (a AdmissionMode) Assurance() SybilAssurance {
	switch a {
	case AdmissionCredential, AdmissionCredentialPSK:
		return SybilConstrainedIssuer
	case AdmissionPSK:
		return SybilSharedSecret
	}
	return SybilUnboundedOpen
}

// DiscoveryMode selects sources for resolving an already identified peer.
type DiscoveryMode uint8

const (
	DiscoveryLocalOnly DiscoveryMode = iota + 1
	DiscoveryPublicPrimary
	DiscoveryHedged
	DiscoveryPublicFallback
)

func (d DiscoveryMode) valid() bool {
	return d >= DiscoveryLocalOnly && d <= DiscoveryPublicFallback
}

// PublicationMode is the owner-controlled native record projection.
type PublicationMode uint8

const (
	PublicationNone PublicationMode = iota + 1
	PublicationNativeRI
	PublicationLS2
	PublicationEncryptedLS2
)

func (p PublicationMode) valid() bool {
	return p >= PublicationNone && p <= PublicationEncryptedLS2
}

// DataRouting selects the endpoint path class.
type DataRouting uint8

const (
	RoutingNativeI2P DataRouting = iota + 1
	RoutingOverlayDirect
	RoutingOverlayRouted
	// RoutingOpportunistic chooses among an explicit allowed route set, never
	// an unrestricted shortest path.
	RoutingOpportunistic
)

func (d DataRouting) valid() bool {
	return d >= RoutingNativeI2P && d <= RoutingOpportunistic
}

// PrivacyClass is a hard constraint on exposure and hop topology. It filters
// candidates; it is never a score weight.
type PrivacyClass uint8

const (
	PrivacyI2PCompatible PrivacyClass = iota + 1
	PrivacyExplicitDirect
	PrivacyPrivateConfined
)

func (p PrivacyClass) valid() bool {
	return p >= PrivacyI2PCompatible && p <= PrivacyPrivateConfined
}

// PublicParticipation describes actual native connectivity behavior.
type PublicParticipation uint8

const (
	ParticipationOnDemand PublicParticipation = iota + 1
	ParticipationWarm
	ParticipationContributor
)

func (p PublicParticipation) valid() bool {
	return p >= ParticipationOnDemand && p <= ParticipationContributor
}

// ProtocolFallback is end-to-end endpoint protocol selection, independent of
// the network path.
type ProtocolFallback uint8

const (
	ProtocolIVNPOnly ProtocolFallback = iota + 1
	ProtocolIVNPPreferred
	ProtocolLegacyOnly
)

func (p ProtocolFallback) valid() bool {
	return p >= ProtocolIVNPOnly && p <= ProtocolLegacyOnly
}

// SessionFailover is the post-failure continuation contract.
type SessionFailover uint8

const (
	// FailoverReconnect opens a new connection; delivery of in-flight data is
	// classified, never silently replayed.
	FailoverReconnect SessionFailover = iota + 1
	// FailoverNegotiatedResume requires a compatible proven resumption
	// protocol negotiated on both endpoints.
	FailoverNegotiatedResume
)

func (f SessionFailover) valid() bool {
	return f >= FailoverReconnect && f <= FailoverNegotiatedResume
}

// RouteClass is the forwarding class of a candidate path.
type RouteClass uint8

const (
	RouteNativeI2P RouteClass = iota + 1
	RouteDirect
	RouteRouted
)

// EndpointProtocol is the endpoint-to-endpoint protocol selection.
type EndpointProtocol uint8

const (
	EndpointProtocolLegacyStream EndpointProtocol = iota + 1
	EndpointProtocolIVNPStream
)
