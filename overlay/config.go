package overlay

import (
	"time"
)

// FabricDescriptor pins a routing domain. It is distributed with the
// implementation or through an explicitly trusted configuration update; peer
// metadata cannot replace it. A descriptor signature proves configuration
// provenance only.
type FabricDescriptor struct {
	ID        FabricID
	NetworkID WireNetworkID
	// Protocols lists supported protocol/profile identifiers.
	Protocols []string
	// ContactCodecs lists supported capability/contact codecs.
	ContactCodecs []string
	// Bootstrap carries configured trust/provenance references.
	Bootstrap []PeerRef
	// Reviewed marks a descriptor provisioned by the operator or project.
	Reviewed bool
	// Production claims production deployment; it requires a reviewed
	// descriptor with an explicit configured network number, never the
	// illustrative test number.
	Production bool
	// Public marks an open public fabric. A private_confined realm may not
	// bind a public context or carry data over it.
	Public bool
	// MaxPeers bounds the routing table of the context.
	MaxPeers int
}

// IllustrativeNetworkID is the unallocated test configuration number. It is
// not an assigned public IVNP network number.
const IllustrativeNetworkID WireNetworkID = 42

// Validate enforces wire-ID range rules. The illustrative network number 42 is
// an unallocated test value, never an assigned public IVNP number.
func (d FabricDescriptor) Validate() error {
	if d.ID == (FabricID{}) {
		return CodeInvalidConfig.Wrap("fabric descriptor requires an id")
	}
	switch {
	case d.NetworkID == WireNetworkIDPublicI2P:
		return CodeNetworkIDConflict.Wrap("descriptor with netId 2 is the native I2P context, not an IVNP fabric")
	case d.NetworkID < WireNetworkIDIVNPMin || d.NetworkID > WireNetworkIDIVNPMax:
		return CodeNetworkIDConflict.Wrap("ivnp fabric netId must be in 16..254")
	}
	if d.Production && (!d.Reviewed || d.NetworkID == IllustrativeNetworkID) {
		return CodeNetworkIDConflict.Wrap("production descriptor requires reviewed provisioning and an explicit netId")
	}
	if d.MaxPeers <= 0 {
		return CodeInvalidConfig.Wrap("fabric descriptor requires a finite peer bound")
	}
	return nil
}

// empty reports whether the descriptor carries no fabric-specific fields; the
// native I2P context must stay descriptor-free.
func (d FabricDescriptor) empty() bool {
	switch {
	case d.ID != (FabricID{}), d.NetworkID != 0,
		len(d.Protocols) != 0, len(d.ContactCodecs) != 0,
		len(d.Bootstrap) != 0, d.Reviewed, d.Production, d.Public, d.MaxPeers != 0:
		return false
	}
	return true
}

// ContextKind distinguishes the two wire-level context implementations.
type ContextKind uint8

const (
	// ContextNativeI2P is the genuine public I2P context with netId 2.
	ContextNativeI2P ContextKind = iota + 1
	// ContextIVNP is a separately scoped IVNP routing context.
	ContextIVNP
)

// FabricConfig opens one NetworkContext.
type FabricConfig struct {
	Kind ContextKind
	// Descriptor is required for ContextIVNP and forbidden for ContextNativeI2P;
	// the native fabric is fixed by the I2P specification at netId 2.
	Descriptor FabricDescriptor
	// IdentityRef names the router identity/private-key handle in the local
	// secret store. Two contexts never share a reference.
	IdentityRef string
	// StateDir is the persistence namespace; it must differ across contexts.
	StateDir string
	// Participation describes native connectivity for public contexts.
	Participation PublicParticipation
	// Listeners are owned socket bindings; one listener has one owner context.
	Listeners []string
}

// Validate checks one fabric configuration in isolation; cross-context rules
// run in Host.OpenFabric.
func (c FabricConfig) Validate() error {
	switch c.Kind {
	case ContextNativeI2P:
		if !c.Descriptor.empty() {
			return CodeInvalidConfig.Wrap("native i2p context carries no fabric descriptor")
		}
		if !c.Participation.valid() {
			return CodeInvalidConfig.Wrap("native context requires a participation mode")
		}
	case ContextIVNP:
		if err := c.Descriptor.Validate(); err != nil {
			return err
		}
		if c.Participation != 0 {
			return CodeInvalidConfig.Wrap("participation applies only to the native public context")
		}
	default:
		return CodeInvalidConfig.Wrap("unknown context kind")
	}
	if c.IdentityRef == "" {
		return CodeInvalidConfig.Wrap("context requires an identity reference")
	}
	seen := make(map[string]struct{}, len(c.Listeners))
	for _, l := range c.Listeners {
		if _, dup := seen[l]; dup {
			return CodeInvalidConfig.Wrap("listener appears twice in one context")
		}
		seen[l] = struct{}{}
	}
	return nil
}

// PrefixMode is a per-policy failure-domain diversity mode.
type PrefixMode uint8

const (
	// PrefixStrict fails resolution when candidates concentrate beyond the
	// per-prefix bound; observed over-concentration is a diversity failure.
	PrefixStrict PrefixMode = iota + 1
	// PrefixBestEffort caps each prefix and proceeds with the reduced set.
	PrefixBestEffort
	PrefixDisabled
)

// PrefixPolicy scopes IP-prefix diversity. Disabling it never disables unique
// MemberID checks, authentication, loop prevention, or quotas.
type PrefixPolicy struct {
	Mode         PrefixMode
	IPv4Prefix   int
	IPv6Prefix   int
	MaxPerPrefix int
}

func (p PrefixPolicy) validate() error {
	if p.Mode < PrefixStrict || p.Mode > PrefixDisabled {
		return CodeInvalidConfig.Wrap("unknown prefix mode")
	}
	if p.Mode == PrefixDisabled {
		return nil
	}
	if p.IPv4Prefix < 0 || p.IPv4Prefix > 32 || p.IPv6Prefix < 0 || p.IPv6Prefix > 128 {
		return CodeInvalidConfig.Wrap("prefix length out of range")
	}
	if p.MaxPerPrefix <= 0 {
		return CodeInvalidConfig.Wrap("prefix policy requires a finite per-prefix bound")
	}
	return nil
}

// RealmConfig opens a Realm over one or more bound contexts.
type RealmConfig struct {
	ID RealmID
	// Contexts names the bound NetworkContext handles. Dual-stack realms bind
	// exactly one native and one IVNP context.
	Contexts    []ContextID
	Admission   AdmissionMode
	Discovery   DiscoveryMode
	Privacy     PrivacyClass
	Routing     DataRouting
	Publication PublicationMode
	Prefix      PrefixPolicy
	// AcknowledgeOpen explicitly accepts unbounded-open Sybil assurance.
	AcknowledgeOpen bool
	// AcknowledgeExposure explicitly accepts direct endpoint location
	// correlation for services in this realm.
	AcknowledgeExposure bool
}

// RealmProfile is the single realm configuration over configured networks.
// Fabrics selects which IVNP entries join; IncludeNative adds the netId=2 context.
type RealmProfile struct {
	ID                  RealmID
	Admission           AdmissionMode
	Discovery           DiscoveryMode
	Privacy             PrivacyClass
	Routing             DataRouting
	Publication         PublicationMode
	Prefix              PrefixPolicy
	Fabrics             []string
	IncludeNative       bool
	PSK                 []byte
	AcknowledgeOpen     bool
	AcknowledgeExposure bool
}

// ServiceSpec opens a Service under a Realm. The service owns its canonical
// Destination and publication lifecycle.
type ServiceSpec struct {
	// Destination is the owned canonical serialized Destination. Nil creates
	// an outbound-only service with no endpoint identity: it can dial but can
	// never publish, project presence, or accept inbound channels.
	Destination []byte
	Publication PublicationMode
	Privacy     PrivacyClass
	Routing     DataRouting
	// Protocols lists the endpoint protocols this service accepts.
	Protocols []EndpointProtocol
	// DualPresence authorizes an x-ivnp.* projection in the service's native
	// record. It requires AcknowledgeExposure on the owning realm when the
	// record is cleartext.
	DualPresence bool
	// Port is the logical I2CP control port advertised in contact metadata.
	Port uint16
	// PublicationFloor carries the durably persisted (incarnation, sequence)
	// position from a previous run. The next reservation is strictly above it;
	// restart never reuses a position and triggers remote rollback rejection.
	PublicationFloor PublicationCursor
}

// PublicationCursor is a durable (incarnation, sequence) reservation position.
type PublicationCursor struct {
	Incarnation uint64
	Sequence    uint64
}

// DialPolicy independently constrains fabrics, route classes, endpoint
// protocols, minimum security, privacy, race budgets, and failover. A
// preference never widens the allowed set.
type DialPolicy struct {
	Fabrics           []FabricID
	RouteClasses      []RouteClass
	EndpointProtocols []EndpointProtocol
	Privacy           PrivacyClass
	Fallback          ProtocolFallback
	Failover          SessionFailover
	// HedgeDelay is the launch delay between setup candidates, not a latency
	// claim. Zero selects the 200 ms default.
	HedgeDelay time.Duration
	// DiscoveryHedgeDelay separates lookup hedging; zero selects 150 ms.
	DiscoveryHedgeDelay time.Duration
	// MaxSetupCandidates bounds simultaneous setups; default and ceiling is 2.
	MaxSetupCandidates int
	// SetupDeadline bounds the native path realistically; zero selects 60 s.
	SetupDeadline time.Duration
}

const (
	DefaultHedgeDelay          = 200 * time.Millisecond
	DefaultDiscoveryHedgeDelay = 150 * time.Millisecond
	DefaultSetupDeadline       = 60 * time.Second
	MaxSetupCandidateLimit     = 2
	DefaultMinContactUpdate    = 60 * time.Second
)

func (p *DialPolicy) normalize() {
	if p.HedgeDelay <= 0 {
		p.HedgeDelay = DefaultHedgeDelay
	}
	if p.DiscoveryHedgeDelay <= 0 {
		p.DiscoveryHedgeDelay = DefaultDiscoveryHedgeDelay
	}
	if p.MaxSetupCandidates <= 0 || p.MaxSetupCandidates > MaxSetupCandidateLimit {
		p.MaxSetupCandidates = MaxSetupCandidateLimit
	}
	if p.SetupDeadline <= 0 {
		p.SetupDeadline = DefaultSetupDeadline
	}
}
