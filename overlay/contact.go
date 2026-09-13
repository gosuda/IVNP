package overlay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sort"
	"strconv"

	"gosuda.org/ivnp/foundation"
)

// RecordKind selects the extension budget of the enclosing native record.
type RecordKind uint8

const (
	// RecordRI is a public RouterInfo: 768-byte extension budget, no port key.
	RecordRI RecordKind = iota + 1
	// RecordLS2 is a public or encrypted-inner LeaseSet2: 1024-byte budget.
	RecordLS2
)

const (
	contactBudgetRI  = 768
	contactBudgetLS2 = 1024
	// localContactMax bounds the version-2 local contact record mapping,
	// including its native two-byte length.
	localContactMax = 4096

	contactVersion   = "2"
	contactDigestTag = "overlay-contact/v2"
	localContactTag  = "overlay-local-contact/v2"
)

var contactCapabilityTokens = map[string]struct{}{
	"i2np": {}, "control": {}, "stream": {}, "datagram": {}, "fast": {},
}

// ContactEnvelope is the version-2 x-ov.* contact profile. The enclosing native
// signature authenticates it; the unkeyed semantic digest supports equality,
// channel binding, and equivocation detection only.
type ContactEnvelope struct {
	RealmID     RealmID
	MemberID    MemberID
	ChannelKey  [32]byte
	Incarnation uint64
	Sequence    uint64
	// NotAfter is the envelope expiry in Unix seconds. It never extends the
	// native record or lease lifetime.
	NotAfter  int64
	Admission AdmissionMode
	// CredentialDigest is a hint until the credential itself verifies.
	CredentialDigest *[32]byte
	// Capabilities are self-advertised tokens, not authorization.
	Capabilities []string
	// Port is the integrated endpoint's logical I2CP control port; valid only
	// in an LS2 record. Zero means absent.
	Port      uint16
	Endpoints []Endpoint
	// digest is the verified semantic digest set by ParseContactEnvelope.
	digest [32]byte
}

// Digest returns the verified semantic digest. It is zero for an envelope
// built locally rather than parsed.
func (e *ContactEnvelope) Digest() [32]byte { return e.digest }

// contactEntries builds the sorted x-ov.* entries excluding the digest key.
// Output order is fixed by encoding; callers must not reorder.
func (e *ContactEnvelope) contactEntries(kind RecordKind) ([]foundation.MappingEntry, error) {
	if e.Admission == 0 {
		return nil, CodeInvalidConfig.Wrap("contact envelope requires an admission mode")
	}
	if e.NotAfter < 0 {
		return nil, CodeInvalidConfig.Wrap("contact expiry precedes epoch")
	}
	if e.ChannelKey == ([32]byte{}) {
		return nil, CodeEndpointBindingInvalid.Wrap("contact requires a nonzero channel key")
	}
	if len(e.Endpoints) > 2 {
		return nil, CodeInvalidConfig.Wrap("contact envelope allows at most two endpoints")
	}
	entries := []foundation.MappingEntry{
		{Key: []byte("x-ov.a"), Value: []byte(e.Admission.token())},
		{Key: []byte("x-ov.g"), Value: []byte(strconv.FormatUint(e.Incarnation, 10))},
		{Key: []byte("x-ov.k"), Value: []byte(encode32(e.ChannelKey))},
		{Key: []byte("x-ov.m"), Value: []byte(encode32(e.MemberID))},
		{Key: []byte("x-ov.r"), Value: []byte(encode32(e.RealmID))},
		{Key: []byte("x-ov.s"), Value: []byte(strconv.FormatUint(e.Sequence, 10))},
		{Key: []byte("x-ov.u"), Value: []byte(strconv.FormatInt(e.NotAfter, 10))},
		{Key: []byte("x-ov.v"), Value: []byte(contactVersion)},
	}
	if e.CredentialDigest != nil {
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ov.q"), Value: []byte(encode32(*e.CredentialDigest))})
	}
	if len(e.Capabilities) > 0 {
		tokens := append([]string(nil), e.Capabilities...)
		sort.Strings(tokens)
		for i, token := range tokens {
			if _, ok := contactCapabilityTokens[token]; !ok {
				return nil, CodeUnsupportedCapability.Wrap("unknown contact capability " + token)
			}
			if i > 0 && tokens[i] == tokens[i-1] {
				return nil, CodeInvalidConfig.Wrap("duplicate capability token")
			}
		}
		joined := bytes.Join(tokenBytes(tokens), []byte(","))
		if len(joined) > 96 {
			return nil, CodeInvalidConfig.Wrap("capability field exceeds 96 bytes")
		}
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ov.c"), Value: joined})
	}
	if e.Port != 0 {
		if kind != RecordLS2 {
			return nil, CodeInvalidConfig.Wrap("x-ov.p is valid only in an ls2 record")
		}
		entries = append(entries, foundation.MappingEntry{Key: []byte("x-ov.p"), Value: []byte(strconv.Itoa(int(e.Port)))})
	}
	for i, ep := range e.Endpoints {
		key := "x-ov.e" + strconv.Itoa(i)
		entries = append(entries, foundation.MappingEntry{Key: []byte(key), Value: []byte(ep.String())})
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Key, entries[j].Key) < 0 })
	return entries, nil
}

func tokenBytes(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

// contactDigest computes the unkeyed semantic digest over the canonical
// Mapping of all supplied x-ov.* entries except x-ov.h.
func contactDigest(entries []foundation.MappingEntry) ([32]byte, error) {
	n, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, len(contactDigestTag)+1+n)
	copy(buf, contactDigestTag)
	if _, err := foundation.MarshalMappingTo(buf[len(contactDigestTag)+1:], entries); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(buf), nil
}

// MarshalEntries returns the complete sorted x-ov.* entry set including the
// semantic digest, enforcing the enclosing record's extension budget.
func (e *ContactEnvelope) MarshalEntries(kind RecordKind) ([]foundation.MappingEntry, error) {
	entries, err := e.contactEntries(kind)
	if err != nil {
		return nil, err
	}
	digest, err := contactDigest(entries)
	if err != nil {
		return nil, err
	}
	entries = append(entries, foundation.MappingEntry{Key: []byte("x-ov.h"), Value: []byte(encode32(digest))})
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Key, entries[j].Key) < 0 })
	if err := enforceBudget(entries, extensionBudget(kind)); err != nil {
		return nil, err
	}
	return entries, nil
}

func extensionBudget(kind RecordKind) int {
	if kind == RecordRI {
		return contactBudgetRI
	}
	return contactBudgetLS2
}

// enforceBudget sums serialized entry sizes (delimiters included, enclosing
// Mapping length excluded) against the extension budget.
func enforceBudget(entries []foundation.MappingEntry, budget int) error {
	total := 0
	for _, entry := range entries {
		if len(entry.Key) > 255 || len(entry.Value) > 255 {
			return CodeRecordTooLarge.Wrap("mapping field exceeds 255 bytes")
		}
		total += len(entry.Key) + len(entry.Value) + 4
	}
	if total > budget {
		return CodeRecordTooLarge.Wrap("extension entries exceed record budget")
	}
	return nil
}

// ParseContactEnvelope extracts and verifies the x-ov.* extension from a
// canonical Mapping taken from a record of the given kind, enforcing that
// record kind's extension budget. Unknown x-ov.* keys participate in the
// digest but are not interpreted. A digest mismatch or malformed required
// field makes only the extension unusable; the caller decides the native
// record's fate.
func ParseContactEnvelope(m foundation.Mapping, kind RecordKind) (*ContactEnvelope, error) {
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
		// An LS2 record shares one extension budget between x-ov.* and
		// x-ivnp.*; an RI record carries x-ov.* alone.
		if kind == RecordLS2 && bytes.HasPrefix(key, []byte("x-ivnp.")) {
			extensionTotal += len(key) + len(value) + 4
		}
		if bytes.HasPrefix(key, []byte("x-ov.")) {
			if _, dup := fields[string(key)]; dup {
				return nil, foundation.ErrInvalidMapping
			}
			fields[string(key)] = append([]byte(nil), value...)
			extensionTotal += len(key) + len(value) + 4
		}
	}
	if len(fields) == 0 {
		return nil, nil
	}
	if extensionTotal > extensionBudget(kind) {
		return nil, CodeRecordTooLarge.Wrap("contact extension exceeds the record budget")
	}
	version := string(fields["x-ov.v"])
	if version != contactVersion {
		return nil, CodeUnsupportedCapability.Wrap("unsupported x-ov version " + version)
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
		if bytes.HasPrefix(key, []byte("x-ov.")) && !bytes.Equal(key, []byte("x-ov.h")) {
			hashed = append(hashed, foundation.MappingEntry{Key: key, Value: value})
		}
	}
	want, err := contactDigest(hashed)
	if err != nil {
		return nil, err
	}
	got, err := decode32(fields["x-ov.h"])
	if err != nil || got != want {
		return nil, CodeEndpointBindingInvalid.Wrap("x-ov digest mismatch")
	}
	env, err := bindContact(fields, kind)
	if err != nil {
		return nil, err
	}
	env.digest = want
	return env, nil
}

func bindContact(f map[string][]byte, kind RecordKind) (*ContactEnvelope, error) {
	var e ContactEnvelope
	var err error
	if e.RealmID, err = decode32Req(f, "x-ov.r"); err != nil {
		return nil, err
	}
	if e.MemberID, err = decode32Req(f, "x-ov.m"); err != nil {
		return nil, err
	}
	if e.ChannelKey, err = decode32Req(f, "x-ov.k"); err != nil {
		return nil, err
	}
	if e.ChannelKey == ([32]byte{}) {
		return nil, CodeEndpointBindingInvalid.Wrap("x-ov.k must be a nonzero ed25519 key")
	}
	if e.Incarnation, err = decimalReq(f, "x-ov.g", 64); err != nil {
		return nil, err
	}
	if e.Sequence, err = decimalReq(f, "x-ov.s", 64); err != nil {
		return nil, err
	}
	notAfter, err := decimalReq(f, "x-ov.u", 64)
	if err != nil {
		return nil, err
	}
	e.NotAfter = int64(notAfter)
	admission, ok := admissionFromToken(string(f["x-ov.a"]))
	if !ok {
		return nil, CodeInvalidConfig.Wrap("unknown x-ov.a admission")
	}
	e.Admission = admission
	if raw, present := f["x-ov.q"]; present {
		digest, err := decode32(raw)
		if err != nil {
			return nil, err
		}
		e.CredentialDigest = &digest
	}
	if raw, present := f["x-ov.c"]; present {
		if len(raw) > 96 {
			return nil, CodeInvalidConfig.Wrap("x-ov.c exceeds 96 bytes")
		}
		tokens, err := parseCapabilities(raw)
		if err != nil {
			return nil, err
		}
		e.Capabilities = tokens
	}
	if raw, present := f["x-ov.p"]; present {
		if kind != RecordLS2 {
			return nil, CodeInvalidConfig.Wrap("x-ov.p is valid only in an ls2 record")
		}
		port, err := parseCanonicalPort(string(raw))
		if err != nil {
			return nil, err
		}
		e.Port = port
	}
	if _, second := f["x-ov.e1"]; second {
		if _, first := f["x-ov.e0"]; !first {
			return nil, CodeEndpointBindingInvalid.Wrap("x-ov.e1 requires x-ov.e0")
		}
	}
	for _, key := range []string{"x-ov.e0", "x-ov.e1"} {
		raw, present := f[key]
		if !present {
			continue
		}
		ep, err := ParseEndpoint(string(raw))
		if err != nil {
			return nil, err
		}
		if !ep.Public() {
			return nil, CodeEndpointBindingInvalid.Wrap("cleartext contact endpoint is not a public address")
		}
		e.Endpoints = append(e.Endpoints, ep)
	}
	return &e, nil
}

// parseCapabilities decodes the canonical capability list: strictly
// ascending unique non-empty tokens. Unknown tokens parse — the digest
// already covers them and self-advertisement is not authorization — but
// carry no defined meaning and are never interpreted. Marshal paths keep the
// defined-token restriction so a record never advertises an undefined offer.
func parseCapabilities(raw []byte) ([]string, error) {
	parts := bytes.Split(raw, []byte(","))
	out := make([]string, 0, len(parts))
	for i, part := range parts {
		if len(part) == 0 {
			return nil, CodeInvalidConfig.Wrap("empty capability token")
		}
		if i > 0 && bytes.Compare(parts[i-1], part) >= 0 {
			return nil, CodeInvalidConfig.Wrap("capability tokens are not sorted unique")
		}
		out = append(out, string(part))
	}
	return out, nil
}

func encode32(v [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(v[:])
}

// decode32 requires canonical unpadded base64url over exactly 32 bytes.
func decode32(raw []byte) ([32]byte, error) {
	var out [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != 32 {
		return out, CodeInvalidConfig.Wrap("field is not canonical base64url-32")
	}
	copy(out[:], decoded)
	if encode32(out) != string(raw) {
		return out, CodeInvalidConfig.Wrap("field is not canonical base64url-32")
	}
	return out, nil
}

func decode32Req(f map[string][]byte, key string) ([32]byte, error) {
	raw, present := f[key]
	if !present {
		return [32]byte{}, CodeInvalidConfig.Wrap("missing " + key)
	}
	return decode32(raw)
}

func decimalReq(f map[string][]byte, key string, bits int) (uint64, error) {
	raw, present := f[key]
	if !present {
		return 0, CodeInvalidConfig.Wrap("missing " + key)
	}
	return parseCanonicalUint(string(raw), bits)
}

// ContactCapability reports whether a token names a defined offer.
func ContactCapability(token string) bool {
	_, ok := contactCapabilityTokens[token]
	return ok
}

// LocalContactRecord is the version-2 locally signed contact record. Its
// signature authorizes nothing by itself: a bootstrap pin, native publication
// binding, or issuer credential must independently authorize the key for the
// claimed realm/member before use.
func MarshalLocalContact(signer ed25519.PrivateKey, entries []foundation.MappingEntry) ([]byte, error) {
	n, err := foundation.MappingEncodedLen(entries)
	if err != nil {
		return nil, err
	}
	if n > localContactMax {
		return nil, CodeRecordTooLarge.Wrap("local contact mapping exceeds 4096 bytes")
	}
	out := make([]byte, 4+n+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(out[:4], uint32(n))
	if _, err := foundation.MarshalMappingTo(out[4:], entries); err != nil {
		return nil, err
	}
	msg := localContactMessage(out[:4+n])
	copy(out[4+n:], ed25519.Sign(signer, msg))
	return out, nil
}

func localContactMessage(record []byte) []byte {
	msg := make([]byte, len(localContactTag)+1+len(record))
	copy(msg, localContactTag)
	copy(msg[len(localContactTag)+1:], record)
	return msg
}

// VerifyLocalContact checks the record's self-signature under publicKey
// (x-ov.k) and returns the embedded mapping. The result is a candidate until
// the key's realm/member binding is independently authorized.
func VerifyLocalContact(record, publicKey []byte) (foundation.Mapping, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return foundation.Mapping{}, CodeEndpointBindingInvalid.Wrap("local contact key must be a 32-byte ed25519 key")
	}
	if len(record) < 4+ed25519.SignatureSize {
		return foundation.Mapping{}, foundation.ErrInvalidMapping
	}
	n := int(binary.BigEndian.Uint32(record[:4]))
	if n < 2 || n > localContactMax || 4+n+ed25519.SignatureSize != len(record) {
		return foundation.Mapping{}, foundation.ErrInvalidMapping
	}
	mapping, consumed, err := foundation.ParseMapping(record[4 : 4+n])
	if err != nil || consumed != n {
		return foundation.Mapping{}, foundation.ErrInvalidMapping
	}
	if err := mapping.ValidateCanonical(); err != nil {
		return foundation.Mapping{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), localContactMessage(record[:4+n]), record[4+n:]) {
		return foundation.Mapping{}, CodeEndpointBindingInvalid.Wrap("local contact signature invalid")
	}
	return mapping, nil
}
