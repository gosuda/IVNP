package overlay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// TLS exporter labels. The dual-admission label is distinct from the v2
// admission label because its bound inputs changed.
const (
	ExporterLabelAdmissionV2 = "EXPORTER-overlay-admission-v2"
	ExporterLabelDualV1      = "EXPORTER-ivnp-dual-admission-v1"
)

// Role identifies the admission transcript side.
type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// AdmissionTranscript is the field-ordered, length-delimited binding scope
// both parties authenticate before any post-handshake overlay traffic.
type AdmissionTranscript struct {
	ProtocolVersion uint16
	Realm           RealmID
	Initiator       [32]byte
	Responder       [32]byte
	InitiatorDigest [32]byte
	ResponderDigest [32]byte
	InitiatorNonce  [32]byte
	ResponderNonce  [32]byte
	Admission       AdmissionMode
	Features        []string
	PolicyGen       uint64
	CredentialGen   uint64
	Session         [32]byte
	// Dual-scope fields are zero in the version-2 profile.
	Fabric    FabricID
	NetworkID WireNetworkID
	Endpoint  EndpointID
	Selector  uint8
	Port      uint16
	Class     RouteClass
	Protocol  EndpointProtocol
}

// Marshal encodes the transcript canonically: fixed fields in declared order,
// variable fields length-delimited. Adapters must use this encoding or a
// reviewed equivalent; without one the capability is absent. An oversize
// feature list cannot be length-delimited and is rejected rather than
// truncated into an ambiguous encoding.
func (t AdmissionTranscript) Marshal() ([]byte, error) {
	var b bytes.Buffer
	put16(&b, t.ProtocolVersion)
	putRaw(&b, t.Realm)
	putRaw(&b, t.Initiator)
	putRaw(&b, t.Responder)
	putRaw(&b, t.InitiatorDigest)
	putRaw(&b, t.ResponderDigest)
	putRaw(&b, t.InitiatorNonce)
	putRaw(&b, t.ResponderNonce)
	b.WriteByte(byte(t.Admission))
	if err := putFeatures(&b, t.Features); err != nil {
		return nil, err
	}
	put64(&b, t.PolicyGen)
	put64(&b, t.CredentialGen)
	putRaw(&b, t.Session)
	putRaw(&b, t.Fabric)
	b.WriteByte(byte(t.NetworkID))
	putRaw(&b, t.Endpoint)
	b.WriteByte(t.Selector)
	put16(&b, t.Port)
	b.WriteByte(byte(t.Class))
	b.WriteByte(byte(t.Protocol))
	return b.Bytes(), nil
}

func putRaw(b *bytes.Buffer, v [32]byte) { b.Write(v[:]) }

func put16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func put64(b *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	b.Write(tmp[:])
}

func putFeatures(b *bytes.Buffer, features []string) error {
	joined := bytes.Join(tokenBytes(features), []byte(","))
	if len(joined) > 0xFFFF {
		return CodeInvalidConfig.Wrap("admission transcript feature list exceeds the length-delimited encoding")
	}
	put16(b, uint16(len(joined)))
	b.Write(joined)
	return nil
}

// Hash returns the transcript hash used as exporter context.
func (t AdmissionTranscript) Hash() ([32]byte, error) {
	raw, err := t.Marshal()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// AdmissionProof signs the v2 admission statement under the contact key:
// Ed25519 over SHA256("overlay-admission/v2\0" || exporter || transcript ||
// role). Both verified proofs precede AdmittedPeer creation.
func AdmissionProof(contact ed25519.PrivateKey, exporter []byte, transcript [32]byte, role Role) []byte {
	return ed25519.Sign(contact, admissionMessage("overlay-admission/v2", exporter, transcript, role))
}

// VerifyAdmissionProof checks a peer's admission statement.
func VerifyAdmissionProof(public [32]byte, proof, exporter []byte, transcript [32]byte, role Role) bool {
	return ed25519.Verify(ed25519.PublicKey(public[:]), admissionMessage("overlay-admission/v2", exporter, transcript, role), proof)
}

// DualProof signs the dual-scope admission statement under the endpoint
// contact key authorized by the verified native record.
func DualProof(contact ed25519.PrivateKey, exporter []byte, transcript [32]byte, role Role) []byte {
	return ed25519.Sign(contact, admissionMessage("ivnp-dual-admission/v1", exporter, transcript, role))
}

// VerifyDualProof checks a peer's dual-scope statement.
func VerifyDualProof(public [32]byte, proof, exporter []byte, transcript [32]byte, role Role) bool {
	return ed25519.Verify(ed25519.PublicKey(public[:]), admissionMessage("ivnp-dual-admission/v1", exporter, transcript, role), proof)
}

func admissionMessage(tag string, exporter []byte, transcript [32]byte, role Role) []byte {
	inner := make([]byte, 0, len(tag)+1+len(exporter)+32+1)
	inner = append(inner, tag...)
	inner = append(inner, 0)
	inner = append(inner, exporter...)
	inner = append(inner, transcript[:]...)
	inner = append(inner, byte(role))
	sum := sha256.Sum256(inner)
	return sum[:]
}

// PSKProof is HMAC-SHA256 over the shared network-epoch key binding channel
// and role to the current epoch.
func PSKProof(epochKey []byte, exporter []byte, transcript [32]byte, role Role, epoch uint64) []byte {
	mac := hmac.New(sha256.New, epochKey)
	mac.Write([]byte("overlay-psk/v2"))
	mac.Write([]byte{0})
	mac.Write(exporter)
	mac.Write(transcript[:])
	mac.Write([]byte{byte(role)})
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], epoch)
	mac.Write(tmp[:])
	return mac.Sum(nil)
}

// VerifyPSKProof checks a peer's PSK statement in constant time.
func VerifyPSKProof(epochKey, proof, exporter []byte, transcript [32]byte, role Role, epoch uint64) bool {
	want := PSKProof(epochKey, exporter, transcript, role, epoch)
	return hmac.Equal(want, proof)
}
