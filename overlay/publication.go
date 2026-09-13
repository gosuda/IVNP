package overlay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"
	"sync"
	"time"

	"gosuda.org/ivnp/foundation"
)

// PublicationState is the publication lifecycle. Store acknowledgements and
// read-back are observations, not durable-storage receipts or a quorum.
type PublicationState uint8

const (
	PublicationPrepared PublicationState = iota + 1
	PublicationQueued
	PublicationSubmitted
	PublicationAcknowledged
	PublicationReadBack
	PublicationFresh
	PublicationExpired
	PublicationFailed
	PublicationWithdrawn
)

// PublicationDriver performs the actual native store for one owned record.
// The single fenced publisher owns the native netDB key; other contexts never
// write it. Publish obtains the driver only from the bound netId=2 context's
// runtime, so an IVNP context can never overwrite the key.
type PublicationDriver interface {
	// Store assembles the owned native record around the verified option
	// entries — the publisher signs and serializes the record itself — and
	// submits it under its native key.
	Store(ctx context.Context, options []foundation.MappingEntry) (PublicationObservation, error)
	// ReadBack retrieves the stored record for observation.
	ReadBack(ctx context.Context) (DestinationRecord, error)
}

// Publication tracks one owned projection's lifecycle.
type Publication struct {
	mu      sync.Mutex
	state   PublicationState
	service *Service
	driver  PublicationDriver
	last    PublicationObservation
}

// State reports the current lifecycle position.
func (p *Publication) State() PublicationState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *Publication) advance(to PublicationState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == PublicationFailed || p.state == PublicationWithdrawn {
		return
	}
	p.state = to
}

func (p *Publication) fail() {
	p.mu.Lock()
	p.state = PublicationFailed
	p.mu.Unlock()
	p.service.realm.host.broadcast(HostEvent{Kind: EventPublicationFailed, Realm: p.service.realm.realmID()})
}

// Publish assembles the service's native record projection and submits it
// through the bound native context's publication driver — the only path that
// may write the owned public key, so an IVNP context can never overwrite it.
// Publication requires an owned live-lease record; the extension entries are
// appended to the publisher's own options. base must not carry x-ov.* or
// x-ivnp.* keys: extension material enters only through the verified path.
// The realm's current configuration must still permit the projection —
// ApplyPolicy may have forbidden it since the service opened.
func (s *Service) Publish(ctx context.Context, base []foundation.MappingEntry) (*Publication, error) {
	return s.publish(ctx, base, nil)
}

// PublishContact is Publish carrying a caller-declared x-ov.* contact
// envelope in the same record. The envelope's realm, position, and logical
// port are overwritten with the verified scope; its admission mode may
// tighten the realm's requirement but never weaken it, and in an open realm
// the member slot is bound to the service's own endpoint identity.
func (s *Service) PublishContact(ctx context.Context, base []foundation.MappingEntry, contact ContactEnvelope) (*Publication, error) {
	return s.publish(ctx, base, &contact)
}

func (s *Service) publish(ctx context.Context, base []foundation.MappingEntry, contact *ContactEnvelope) (*Publication, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, CodeClosed.Wrap("service closed")
	}
	s.realm.mu.Lock()
	realmClosed := s.realm.closed
	s.realm.mu.Unlock()
	if realmClosed {
		return nil, CodeClosed.Wrap("realm closed")
	}
	if s.spec.Publication != PublicationLS2 && s.spec.Publication != PublicationEncryptedLS2 {
		return nil, CodeInvalidConfig.Wrap("service publication mode does not emit a lease set")
	}
	if err := s.realm.projectionPermitted(s.spec); err != nil {
		return nil, err
	}
	driver, err := s.publicationDriver()
	if err != nil {
		return nil, err
	}
	for _, e := range base {
		if isExtensionKey(e.Key) {
			return nil, CodeInvalidConfig.Wrap("base options must not carry unverified extension entries")
		}
	}
	options := append([]foundation.MappingEntry(nil), base...)
	// Every position-independent check precedes position handling; a rejected
	// request must not consume a durable cursor position.
	if contact != nil {
		if err := s.validateContact(*contact); err != nil {
			return nil, err
		}
	}
	if s.spec.DualPresence {
		if s.realm.host.bindingProvider() == nil {
			return nil, CodeUnsupportedCapability.Wrap("dual presence requires an endpoint binding provider")
		}
	}
	var extFP [32]byte
	hasExt := s.spec.DualPresence || contact != nil
	if hasExt {
		// Build the projection at the current durable position first: a
		// republication carrying byte-identical semantic fields is a lease
		// renewal and reuses that position instead of consuming a new one.
		incarnation, sequence := s.arbiter.Renew()
		ext, err := s.extensionEntries(ctx, contact, incarnation, sequence)
		if err != nil {
			return nil, err
		}
		extFP = extensionFingerprint(ext)
		if !s.unchangedExtension(extFP) {
			// A semantic change consumes a fresh position; one reservation
			// covers every projection the record carries so the envelope and
			// the presence share a single fenced (incarnation, sequence).
			incarnation, sequence, err = s.arbiter.Reserve(false)
			if err != nil {
				return nil, err
			}
			ext, err = s.extensionEntries(ctx, contact, incarnation, sequence)
			if err != nil {
				return nil, err
			}
			// The stored fingerprint must describe the content actually
			// submitted; a provider may vary its output between calls.
			extFP = extensionFingerprint(ext)
		}
		options = append(options, ext...)
	}
	if err := enforceBudget(extensionOnly(options), contactBudgetLS2); err != nil {
		return nil, err
	}
	// The driver receives canonical option order; it must not infer meaning
	// from caller ordering.
	sort.Slice(options, func(i, j int) bool { return bytes.Compare(options[i].Key, options[j].Key) < 0 })
	p := &Publication{state: PublicationPrepared, service: s, driver: driver}
	if !s.trackPublication(p) {
		return nil, CodeClosed.Wrap("service closed")
	}
	if err := p.submit(ctx, options); err != nil {
		return p, err
	}
	if hasExt {
		s.notePublishedExtension(extFP)
	}
	return p, nil
}

// extensionEntries builds the record's verified extension entries at one
// durable position: the stamped x-ov.* envelope and the provider-signed
// x-ivnp.* presence. The provider may return only the projection's own keys;
// the signed projection is re-verified against a bound fabric and the
// service's scope before the record may carry it. A cleartext record must
// carry only public addresses; an encrypted inner record may carry private
// ones.
func (s *Service) extensionEntries(ctx context.Context, contact *ContactEnvelope, incarnation, sequence uint64) ([]foundation.MappingEntry, error) {
	var out []foundation.MappingEntry
	if contact != nil {
		extra, err := s.contactEntries(*contact, incarnation, sequence)
		if err != nil {
			return nil, err
		}
		out = append(out, extra...)
	}
	if s.spec.DualPresence {
		binding := s.realm.host.bindingProvider()
		presence := DualPresence{
			RealmID: s.realm.realmID(), Incarnation: incarnation,
			Sequence: sequence, Port: s.spec.Port,
		}
		extra, err := binding.SignPresence(ctx, presence, s.endpoint.Destination)
		if err != nil {
			return nil, err
		}
		for _, e := range extra {
			if !isPresenceKey(e.Key) {
				return nil, CodeEndpointBindingInvalid.Wrap("signed presence carries foreign extension entries")
			}
		}
		parsed, err := s.verifySignedPresence(extra, s.spec.Publication == PublicationLS2)
		if err != nil {
			return nil, err
		}
		if err := s.checkPresenceScope(parsed, incarnation, sequence); err != nil {
			return nil, err
		}
		out = append(out, extra...)
	}
	return out, nil
}

// extensionFingerprint hashes the non-position extension fields of a
// projection. Incarnation, sequence, and the position-covering digest keys
// are excluded so byte-identical semantic content yields one fingerprint at
// any position; entries are canonically sorted, so iteration order is fixed.
func extensionFingerprint(entries []foundation.MappingEntry) [32]byte {
	h := sha256.New()
	for _, e := range entries {
		switch string(e.Key) {
		case "x-ov.g", "x-ov.s", "x-ov.h", "x-ivnp.g", "x-ivnp.s", "x-ivnp.h":
			continue
		}
		h.Write(e.Key)
		h.Write([]byte{0})
		h.Write(e.Value)
		h.Write([]byte{0xff})
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// unchangedExtension reports whether the projected semantic content equals
// what the service last successfully published; identical content renews at
// the reserved position instead of consuming a new one.
func (s *Service) unchangedExtension(fp [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.extFPSet && s.extFP == fp
}

// notePublishedExtension records the semantic fingerprint of a successfully
// submitted projection.
func (s *Service) notePublishedExtension(fp [32]byte) {
	s.mu.Lock()
	s.extFP = fp
	s.extFPSet = true
	s.mu.Unlock()
}

// validateContact enforces the caller-declared envelope's
// position-independent rules before a cursor position is consumed. The
// admission requirement may tighten the realm's mode but never weaken it; in
// an open realm a declared member slot must be the endpoint's own identity.
// Cleartext records carry public addresses only; an encrypted inner record
// may carry private ones.
func (s *Service) validateContact(contact ContactEnvelope) error {
	// The stamped port is what inbound listeners and dial targets match on; a
	// service without one would publish an envelope nobody can reach.
	if s.spec.Port == 0 {
		return CodeInvalidConfig.Wrap("contact publication requires a service port")
	}
	admission := s.realm.admissionMode()
	if admission == AdmissionOpen {
		if contact.MemberID != (MemberID{}) && contact.MemberID != MemberID(s.endpoint.ID) {
			return CodeEndpointBindingInvalid.Wrap("open-realm member slot is the endpoint's own identity")
		}
	} else if contact.MemberID == (MemberID{}) {
		return CodeInvalidConfig.Wrap("contact envelope requires the member slot")
	}
	if !admissionAtLeast(contact.Admission, admission) {
		return CodePrivacyPolicyConflict.Wrap("contact admission weakens the realm requirement")
	}
	if contact.NotAfter <= time.Now().Unix() {
		return CodeRecordStale.Wrap("contact envelope is already expired")
	}
	for _, ep := range contact.Endpoints {
		if !ep.Address.IsValid() || ep.Transport == "" {
			return CodeInvalidConfig.Wrap("contact endpoint is not a parsed endpoint")
		}
		if s.spec.Publication == PublicationLS2 && !ep.Public() {
			return CodeEndpointBindingInvalid.Wrap("cleartext contact endpoint is not a public address")
		}
	}
	return nil
}

// contactEntries stamps the service scope onto the envelope — realm,
// reserved position, and logical port — and returns its canonical x-ov.*
// entries. The open-realm member slot is bound to the endpoint's identity.
func (s *Service) contactEntries(contact ContactEnvelope, incarnation, sequence uint64) ([]foundation.MappingEntry, error) {
	contact.RealmID = s.realm.realmID()
	contact.Incarnation, contact.Sequence = incarnation, sequence
	contact.Port = s.spec.Port
	if s.realm.admissionMode() == AdmissionOpen {
		contact.MemberID = MemberID(s.endpoint.ID)
	}
	if contact.NotAfter <= time.Now().Unix() {
		return nil, CodeRecordStale.Wrap("contact envelope is already expired")
	}
	entries, err := contact.MarshalEntries(RecordLS2)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !bytes.HasPrefix(e.Key, []byte("x-ov.")) {
			return nil, CodeEndpointBindingInvalid.Wrap("contact projection carries foreign extension entries")
		}
	}
	return entries, nil
}

// publicationDriver resolves the owned-record driver from the realm's bound
// native context. The driver is only ever sourced from the netId=2 runtime's
// own contract, binding the published key to the correct context.
func (s *Service) publicationDriver() (PublicationDriver, error) {
	for _, nctx := range s.realm.boundContexts() {
		if nctx.kind != ContextNativeI2P {
			continue
		}
		nctx.mu.Lock()
		runtime := nctx.runtime
		nctx.mu.Unlock()
		src, ok := runtime.(PublicationDriverSource)
		if !ok {
			return nil, CodeUnsupportedCapability.Wrap("bound native context cannot publish owned records")
		}
		driver := src.PublicationDriver(s.endpoint)
		if driver == nil {
			return nil, CodeUnsupportedCapability.Wrap("bound native context cannot publish owned records")
		}
		return driver, nil
	}
	return nil, CodeUnsupportedCapability.Wrap("publication requires a bound native context")
}

// verifySignedPresence re-parses the provider-signed entries against every
// bound IVNP descriptor; the projection must match a bound fabric before the
// record may carry it. requirePublic additionally enforces cleartext
// endpoint rules (public addresses only). On success it returns the verified
// projection for the caller's scope check.
func (s *Service) verifySignedPresence(entries []foundation.MappingEntry, requirePublic bool) (*DualPresence, error) {
	m, err := mappingFromEntries(entries)
	if err != nil {
		return nil, err
	}
	s.realm.mu.Lock()
	bound := append([]*NetworkContext(nil), s.realm.bound...)
	s.realm.mu.Unlock()
	for _, nctx := range bound {
		if nctx.kind != ContextIVNP {
			continue
		}
		presence, err := parseDualPresence(m, nctx.fabric, requirePublic)
		if err != nil {
			continue
		}
		if presence != nil {
			return presence, nil
		}
	}
	return nil, CodeEndpointBindingInvalid.Wrap("signed presence does not verify against a bound ivnp fabric")
}

// checkPresenceScope binds a signed projection to this service's realm,
// logical port, and the reserved (incarnation, sequence): the provider must
// carry the arbiter's exact reservation, never a substituted position. An
// already-expired record is rejected.
func (s *Service) checkPresenceScope(p *DualPresence, incarnation, sequence uint64) error {
	if p.RealmID != s.realm.realmID() || p.Port != s.spec.Port {
		return CodeEndpointBindingInvalid.Wrap("signed presence does not match the service scope")
	}
	if p.Incarnation != incarnation || p.Sequence != sequence {
		return CodeEndpointBindingInvalid.Wrap("signed presence does not carry the reserved position")
	}
	if p.NotAfter <= time.Now().Unix() {
		return CodeRecordStale.Wrap("signed presence is already expired")
	}
	return nil
}

func mappingFromEntries(entries []foundation.MappingEntry) (foundation.Mapping, error) {
	sorted := append([]foundation.MappingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].Key, sorted[j].Key) < 0 })
	n, err := foundation.MappingEncodedLen(sorted)
	if err != nil {
		return foundation.Mapping{}, CodeInvalidConfig.Wrap("presence entries exceed wire encoding")
	}
	buf := make([]byte, n)
	if _, err := foundation.MarshalMappingTo(buf, sorted); err != nil {
		return foundation.Mapping{}, CodeInvalidConfig.Wrap("presence entries failed wire encoding")
	}
	m, consumed, err := foundation.ParseMapping(buf)
	if err != nil || consumed != n {
		return foundation.Mapping{}, foundation.ErrInvalidMapping
	}
	return m, nil
}

// extensionOnly copies the x-ov.* and x-ivnp.* entries for the combined
// budget. It must allocate: filtering into the caller's backing array would
// destroy unrelated options that precede the first extension key.
func extensionOnly(entries []foundation.MappingEntry) []foundation.MappingEntry {
	out := make([]foundation.MappingEntry, 0, len(entries))
	for _, e := range entries {
		if isExtensionKey(e.Key) {
			out = append(out, e)
		}
	}
	return out
}

func isExtensionKey(key []byte) bool {
	return bytes.HasPrefix(key, []byte("x-ov.")) || bytes.HasPrefix(key, []byte("x-ivnp."))
}

func isPresenceKey(key []byte) bool {
	return bytes.HasPrefix(key, []byte("x-ivnp."))
}

// submit hands the verified options to the driver and tracks observations
// honestly: a store ack is not freshness; read-back of the verified record
// moves the publication toward fresh.
func (p *Publication) submit(ctx context.Context, options []foundation.MappingEntry) error {
	p.advance(PublicationQueued)
	obs, err := p.driver.Store(ctx, options)
	if err != nil {
		p.fail()
		return err
	}
	p.mu.Lock()
	p.last = obs
	p.mu.Unlock()
	p.advance(PublicationSubmitted)
	if obs.Accepted {
		p.advance(PublicationAcknowledged)
	}
	if obs.ReadBack {
		p.advance(PublicationReadBack)
	}
	return nil
}

// Refresh marks the publication fresh after a read-back that parses, verifies
// its native signature, and matches the owned record. A cleartext LS2 must
// hash to the service's endpoint; an encrypted record's blinded lookup key
// rotates daily, so it is bound to the hash the driver reported at store time
// when one was reported. When the driver reported the stored record's
// ContentHash, the read-back bytes must hash to it — an older signed version
// of the same record is not evidence the projection is live.
func (p *Publication) Refresh(ctx context.Context) error {
	p.mu.Lock()
	if p.state == PublicationWithdrawn || p.state == PublicationFailed {
		p.mu.Unlock()
		return CodePublicationNotFresh.Wrap("publication is not active")
	}
	stored := p.last.RecordHash
	content := p.last.ContentHash
	p.mu.Unlock()
	record, err := p.driver.ReadBack(ctx)
	if err != nil {
		return err
	}
	if len(record.Raw) == 0 {
		return CodePublicationNotFresh.Wrap("read-back returned no record")
	}
	if content != (foundation.Hash{}) && foundation.Hash(sha256.Sum256(record.Raw)) != content {
		return CodePublicationNotFresh.Wrap("read-back record is not the stored projection")
	}
	if p.service.spec.Publication == PublicationEncryptedLS2 {
		els2, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(record.Raw)
		if err != nil {
			return CodePublicationNotFresh.Wrap("read-back record does not parse")
		}
		valid, err := els2.Verify()
		if err != nil || !valid {
			return CodePublicationNotFresh.Wrap("read-back record signature invalid")
		}
		if stored != (foundation.Hash{}) && els2.Hash() != stored {
			return CodePublicationNotFresh.Wrap("read-back record is not the stored projection")
		}
		if int64(els2.Published)+int64(els2.Expires) < time.Now().Unix() {
			return CodePublicationNotFresh.Wrap("read-back record is expired")
		}
		p.advance(PublicationFresh)
		return nil
	}
	ls2, err := foundation.NetworkDatabaseParseLeaseSet2(record.Raw)
	if err != nil {
		return CodePublicationNotFresh.Wrap("read-back record does not parse")
	}
	if EndpointID(ls2.Hash()) != p.service.endpoint.ID {
		return CodePublicationNotFresh.Wrap("read-back record is not the owned endpoint")
	}
	valid, err := ls2.Verify()
	if err != nil || !valid {
		return CodePublicationNotFresh.Wrap("read-back record signature invalid")
	}
	// A record past its own usable window is not evidence the projection is
	// live, even with a valid signature.
	if int64(ls2.Header.Published)+int64(ls2.Header.Expires) < time.Now().Unix() {
		return CodePublicationNotFresh.Wrap("read-back record is expired")
	}
	if _, live := minLiveLease(ls2, time.Now().Unix()); !live {
		return CodePublicationNotFresh.Wrap("read-back record carries no live lease")
	}
	p.advance(PublicationFresh)
	return nil
}

// Withdraw stops renewal and local acceptance. It cannot promise immediate
// remote deletion; public netDB is not an instant-delete log.
func (p *Publication) Withdraw() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = PublicationWithdrawn
}
