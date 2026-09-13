package overlay

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"strconv"

	"gosuda.org/ivnp/foundation"
)

const (
	presenceVersion   = "1"
	presenceDigestTag = "ivnp-dual-presence/v1"
	// dualPresenceBudget covers all x-ivnp.* plus x-ov.* entries in one record.
	dualPresenceBudget = 1024
)

// Dual-presence capability tokens. Advertise only implemented capabilities.
const (
	CapDirect       = "direct"
	CapRouted       = "routed"
	CapStreamV1     = "stream-v1"
	CapLegacyStream = "legacy-stream"
	CapResumeV1     = "resume-v1"
)

var presenceCapabilityTokens = map[string]struct{}{
	CapDirect: {}, CapRouted: {}, CapStreamV1: {}, CapLegacyStream: {}, CapResumeV1: {},
}

// DualPresence is the x-ivnp.* format-1 owner authorization projecting minimal
// IVNP contact information for the LS2's EndpointID. The native outer
// signature is authoritative; the semantic digest is not a signature.
type DualPresence struct {
	FabricID     FabricID
	NetworkID    WireNetworkID
	RealmID      RealmID
	ContactKey   [32]byte
	RouterHint   *RouterID
	Incarnation  uint64
	Sequence     uint64
	NotAfter     int64
	Port         uint16
	Capabilities []string
	Endpoints    []Endpoint
	// Emergency marks a bounded security/reachability update exempt from the
	// minimum semantic-update interval. It is a local request flag, never
	// marshaled into the record.
	Emergency bool
	// digest is the verified semantic digest set by ParseDualPresence.
	digest [32]byte
}

// Digest returns the verified semantic digest. It is zero for a presence built
// locally rather than parsed.
func (p *DualPresence) Digest() [32]byte { return p.digest }

// presenceEntries builds sorted x-ivnp.* entries excluding the digest key.
func (p *DualPresence) presenceEntries() ([]foundation.MappingEntry, error) {
	if p.NetworkID < WireNetworkIDIVNPMin || p.NetworkID > WireNetworkIDIVNPMax {
		return nil, CodeNetworkIDConflict.Wrap("presence netId must be in 16..254")
	}
	if p.Port == 0 {
		return nil, CodeInvalidConfig.Wrap("presence requires a logical service port")
	}
	if p.ContactKey == ([32]byte{}) {
		return nil, CodeEndpointBindingInvalid.Wrap("presence requires a nonzero contact key")
	}
	if p.NotAfter < 0 {
		return nil, CodeInvalidConfig.Wrap("presence expiry precedes epoch")
	}
	if len(p.Endpoints) > 2 {
		return nil, CodeInvalidConfig.Wrap("presence allows at most two endpoints")
	}
	entries := []foundation.MappingEntry{
		{Key: []byte("x-ivnp.f"), Value: []byte(encode32(p.FabricID))},
		{Key: []byte("x-ivnp.g"), Value: []byte(strconv.FormatUint(p.Incarnation, 10))},
		{Key: []byte("x-ivnp.k"), Value: []byte(encode32(p.ContactKey))},
		{Key: []byte("x-ivnp.n"), Value: []byte(strconv.Itoa(int(p.NetworkID)))},
		{Key: []byte("x-ivnp.p"), Value: []byte(strconv.Itoa(int(p.Port)))},
		{Key: []byte("x-ivnp.r"), Value: []byte(encode32(p.RealmID))},
		{Key: []byte("x-ivnp.s"), Value: []byte(strconv.FormatUint(p.Sequence, 10))},
		{Key: []byte("x-ivnp.u"), Value: []byte(strconv.FormatInt(p.NotAfter, 10))},
		{Key: []byte("x-ivnp.v"), Value: []byte(presenceVersion)},
	}
	if p.RouterHint != nil {
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ivnp.i"), Value: []byte(encode32(*p.RouterHint))})
	}
	if len(p.Capabilities) > 0 {
		joined, err := joinCapabilities(p.Capabilities, presenceCapabilityTokens)
		if err != nil {
			return nil, err
		}
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ivnp.c"), Value: joined})
	}
	for i, ep := range p.Endpoints {
		key := "x-ivnp.e" + strconv.Itoa(i)
		entries = append(entries, foundation.MappingEntry{Key: []byte(key), Value: []byte(ep.String())})
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Key, entries[j].Key) < 0 })
	return entries, nil
}

func joinCapabilities(tokens []string, known map[string]struct{}) ([]byte, error) {
	sorted := append([]string(nil), tokens...)
	sort.Strings(sorted)
	for i, token := range sorted {
		if _, ok := known[token]; !ok {
			return nil, CodeUnsupportedCapability.Wrap("unknown presence capability " + token)
		}
		if i > 0 && sorted[i] == sorted[i-1] {
			return nil, CodeInvalidConfig.Wrap("duplicate capability token")
		}
	}
	joined := bytes.Join(tokenBytes(sorted), []byte(","))
	if len(joined) > 96 {
		return nil, CodeInvalidConfig.Wrap("capability field exceeds 96 bytes")
	}
	return joined, nil
}

func presenceDigest(entries []foundation.MappingEntry) ([32]byte, error) {
	n, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, len(presenceDigestTag)+1+n)
	copy(buf, presenceDigestTag)
	if _, err := foundation.MarshalMappingTo(buf[len(presenceDigestTag)+1:], entries); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(buf), nil
}

// MarshalEntries returns the complete sorted x-ivnp.* entry set including the
// semantic digest, enforcing the combined 1024-byte extension budget.
func (p *DualPresence) MarshalEntries() ([]foundation.MappingEntry, error) {
	if p.hasCapability(CapDirect) && len(p.Endpoints) == 0 {
		return nil, CodeEndpointBindingInvalid.Wrap("direct capability requires a concrete first contact")
	}
	entries, err := p.presenceEntries()
	if err != nil {
		return nil, err
	}
	digest, err := presenceDigest(entries)
	if err != nil {
		return nil, err
	}
	entries = append(entries, foundation.MappingEntry{Key: []byte("x-ivnp.h"), Value: []byte(encode32(digest))})
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Key, entries[j].Key) < 0 })
	if err := enforceBudget(entries, dualPresenceBudget); err != nil {
		return nil, err
	}
	return entries, nil
}

// HasCapability reports whether the presence advertises a token.
func (p *DualPresence) HasCapability(token string) bool { return p.hasCapability(token) }

func (p *DualPresence) hasCapability(token string) bool {
	for _, c := range p.Capabilities {
		if c == token {
			return true
		}
	}
	return false
}

// ParseDualPresence extracts and verifies the x-ivnp.* extension from a
// canonical LS2 options Mapping already matched to its expected Destination and
// signature-verified natively. Unknown x-ivnp.* keys join the digest but carry
// no authority. Cleartext public records may carry public addresses only.
func ParseDualPresence(m foundation.Mapping, descriptor FabricDescriptor) (*DualPresence, error) {
	return parseDualPresence(m, descriptor, true)
}

// parseDualPresence is ParseDualPresence with the cleartext endpoint rule
// parameterized: encrypted inner records may carry private addresses.
func parseDualPresence(m foundation.Mapping, descriptor FabricDescriptor, requirePublic bool) (*DualPresence, error) {
	if err := m.ValidateCanonical(); err != nil {
		return nil, err
	}
	fields := make(map[string][]byte)
	var extensionTotal int
	it := m.Iterator()
	for {
		key, value, ok, err := it.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if !bytes.HasPrefix(key, []byte("x-ivnp.")) && !bytes.HasPrefix(key, []byte("x-ov.")) {
			continue
		}
		extensionTotal += len(key) + len(value) + 4
		if bytes.HasPrefix(key, []byte("x-ivnp.")) {
			if _, dup := fields[string(key)]; dup {
				return nil, foundation.ErrInvalidMapping
			}
			fields[string(key)] = append([]byte(nil), value...)
		}
	}
	if len(fields) == 0 {
		return nil, nil
	}
	if extensionTotal > dualPresenceBudget {
		return nil, CodeRecordTooLarge.Wrap("combined extension entries exceed 1024 bytes")
	}
	if version := string(fields["x-ivnp.v"]); version != presenceVersion {
		return nil, CodeUnsupportedCapability.Wrap("unsupported x-ivnp version " + version)
	}
	var hashed []foundation.MappingEntry
	it = m.Iterator()
	for {
		key, value, ok, err := it.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		if bytes.HasPrefix(key, []byte("x-ivnp.")) && !bytes.Equal(key, []byte("x-ivnp.h")) {
			hashed = append(hashed, foundation.MappingEntry{Key: key, Value: value})
		}
	}
	want, err := presenceDigest(hashed)
	if err != nil {
		return nil, err
	}
	got, err := decode32(fields["x-ivnp.h"])
	if err != nil || got != want {
		return nil, CodeEndpointBindingInvalid.Wrap("x-ivnp digest mismatch")
	}
	p, err := bindPresence(fields, requirePublic)
	if err != nil {
		return nil, err
	}
	p.digest = want
	if p.FabricID != descriptor.ID || p.NetworkID != descriptor.NetworkID {
		return nil, CodeFabricMismatch.Wrap("presence does not match the pinned fabric descriptor")
	}
	if p.hasCapability(CapDirect) && len(p.Endpoints) == 0 {
		return nil, CodeEndpointBindingInvalid.Wrap("direct capability requires a concrete first contact")
	}
	return p, nil
}

func bindPresence(f map[string][]byte, requirePublic bool) (*DualPresence, error) {
	var p DualPresence
	var err error
	if p.FabricID, err = decode32Req(f, "x-ivnp.f"); err != nil {
		return nil, err
	}
	if p.RealmID, err = decode32Req(f, "x-ivnp.r"); err != nil {
		return nil, err
	}
	if p.ContactKey, err = decode32Req(f, "x-ivnp.k"); err != nil {
		return nil, err
	}
	if p.ContactKey == ([32]byte{}) {
		return nil, CodeEndpointBindingInvalid.Wrap("x-ivnp.k must be a nonzero ed25519 key")
	}
	networkID, err := decimalReq(f, "x-ivnp.n", 8)
	if err != nil {
		return nil, err
	}
	p.NetworkID = WireNetworkID(networkID)
	if p.NetworkID < WireNetworkIDIVNPMin || p.NetworkID > WireNetworkIDIVNPMax {
		return nil, CodeNetworkIDConflict.Wrap("presence netId must be in 16..254")
	}
	if raw, present := f["x-ivnp.i"]; present {
		hint, err := decode32(raw)
		if err != nil {
			return nil, err
		}
		p.RouterHint = (*RouterID)(&hint)
	}
	if p.Incarnation, err = decimalReq(f, "x-ivnp.g", 64); err != nil {
		return nil, err
	}
	if p.Sequence, err = decimalReq(f, "x-ivnp.s", 64); err != nil {
		return nil, err
	}
	notAfter, err := decimalReq(f, "x-ivnp.u", 64)
	if err != nil {
		return nil, err
	}
	p.NotAfter = int64(notAfter)
	port, err := decimalReq(f, "x-ivnp.p", 16)
	if err != nil || port == 0 {
		return nil, CodeInvalidConfig.Wrap("x-ivnp.p requires a logical port")
	}
	p.Port = uint16(port)
	if raw, present := f["x-ivnp.c"]; present {
		if len(raw) > 96 {
			return nil, CodeInvalidConfig.Wrap("x-ivnp.c exceeds 96 bytes")
		}
		tokens, err := parseCapabilities(raw)
		if err != nil {
			return nil, err
		}
		p.Capabilities = tokens
	}
	if _, second := f["x-ivnp.e1"]; second {
		if _, first := f["x-ivnp.e0"]; !first {
			return nil, CodeEndpointBindingInvalid.Wrap("x-ivnp.e1 requires x-ivnp.e0")
		}
	}
	for _, key := range []string{"x-ivnp.e0", "x-ivnp.e1"} {
		raw, present := f[key]
		if !present {
			continue
		}
		ep, err := ParseEndpoint(string(raw))
		if err != nil {
			return nil, err
		}
		// Cleartext public records must not carry non-public addresses even
		// when signed; confidential presence belongs in an encrypted record.
		if requirePublic && !ep.Public() {
			return nil, CodeEndpointBindingInvalid.Wrap("cleartext presence endpoint is not a public address")
		}
		p.Endpoints = append(p.Endpoints, ep)
	}
	return &p, nil
}
