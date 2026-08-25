package datagram

import (
	"crypto/ed25519"
	"crypto/rand"
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestV1ParsesAndVerifiesEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ivnp.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(ivnp.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	payload := []byte("datagram")
	wire := append(identity, ed25519.Sign(private, payload)...)
	wire = append(wire, payload...)
	datagram, err := ParseV1(wire)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := datagram.Verify(); err != nil || !valid {
		t.Fatalf("Verify() = %t, %v", valid, err)
	}
}

func TestV1RoundTripsLegacyElGamalDestination(t *testing.T) {
	destination, err := ivnp.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer destination.ReleaseSensitive()
	identity, err := destination.Identity()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("legacy datagram")
	wire := make([]byte, identity.EncodedLen()+ed25519.SignatureSize+len(payload))
	n, err := MarshalV1To(wire, identity, payload, destination.Sign)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV1(wire[:n])
	if err != nil {
		t.Fatal(err)
	}
	if valid, verifyErr := parsed.Verify(); verifyErr != nil || !valid {
		t.Fatalf("legacy V1 verify = %t, %v", valid, verifyErr)
	}
}

func TestMarshalV1AndRaw(t *testing.T) {
	identity, private := testEd25519Identity(t)
	payload := []byte("outbound datagram")
	wire := make([]byte, identity.EncodedLen()+ed25519.SignatureSize+len(payload))
	n, err := MarshalV1To(wire, identity, payload, func(input []byte) ([]byte, error) {
		return ed25519.Sign(private, input), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(wire) {
		t.Fatalf("encoded length = %d, want %d", n, len(wire))
	}
	parsed, err := ParseV1(wire)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := parsed.Verify(); err != nil || !valid {
		t.Fatalf("parsed V1 verify = %t, %v", valid, err)
	}

	rawWire := make([]byte, len(payload))
	if n, err := MarshalRawTo(rawWire, payload); err != nil || n != len(payload) {
		t.Fatalf("MarshalRawTo = (%d, %v)", n, err)
	}
	raw, err := ParseRaw(rawWire)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'O'
	if rawWire[0] != 'O' {
		t.Fatal("raw datagram did not retain caller-owned alias")
	}
}

func TestDatagramVersionAndReservedFlagsReject(t *testing.T) {
	identity, _ := testEd25519Identity(t)
	for _, flags := range [][2]byte{{0, 1}, {0, 0x42}} {
		wire := append(append([]byte(nil), identity.Bytes()...), flags[:]...)
		if _, err := ParseV2(wire); err != ErrDatagram {
			t.Errorf("V2 flags %x error = %v, want ErrDatagram", flags, err)
		}
	}
	var hash ivnp.Hash
	for _, flags := range [][2]byte{{0, 2}, {0, 0x23}} {
		wire := append(append([]byte(nil), hash[:]...), flags[:]...)
		if _, err := ParseV3(wire); err != ErrDatagram {
			t.Errorf("V3 flags %x error = %v, want ErrDatagram", flags, err)
		}
	}
}

func TestV2OfflineAuthorizationAndTargetBinding(t *testing.T) {
	identity, offlinePrivate := testEd25519Identity(t)
	onlinePublic, onlinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const expires = uint32(100)
	offline := make([]byte, 4+2+len(onlinePublic))
	offline[3] = byte(expires)
	offline[5] = byte(ivnp.SigningEdDSASHA512Ed25519)
	copy(offline[6:], onlinePublic)
	offline = append(offline, ed25519.Sign(offlinePrivate, offline)...)
	flags := []byte{0, byte(flagOffline | 2)}
	payload := []byte("target-bound")
	var target ivnp.Hash
	target[0] = 42
	signedRest := append(append([]byte(nil), flags...), offline...)
	signedRest = append(signedRest, payload...)
	signed := append(append([]byte(nil), target[:]...), signedRest...)
	wire := append(append([]byte(nil), identity.Bytes()...), signedRest...)
	wire = append(wire, ed25519.Sign(onlinePrivate, signed)...)
	datagram, err := ParseV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := datagram.VerifyTargetAt(target, expires); err != nil || !valid {
		t.Fatalf("offline V2 verify = %t, %v", valid, err)
	}
	target[0]++
	if valid, err := datagram.VerifyTargetAt(target, expires); err != nil || valid {
		t.Fatalf("wrong target verify = %t, %v", valid, err)
	}
	target[0]--
	if valid, err := datagram.VerifyTargetAt(target, expires+1); err != ErrDatagram || valid {
		t.Fatalf("expired offline verify = %t, %v", valid, err)
	}
}

func testEd25519Identity(t *testing.T) (ivnp.Identity, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, ivnp.IdentityBaseLength+7)
	copy(raw[352:384], public)
	raw[384] = byte(ivnp.CertificateKey)
	raw[385], raw[386] = 0, 4
	raw[387], raw[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	identity, used, err := ivnp.ParseIdentity(raw)
	if err != nil || used != len(raw) {
		t.Fatalf("ParseIdentity = %#v, %d, %v", identity, used, err)
	}
	return identity, private
}

func TestParsePacketUsesProtocolMetadata(t *testing.T) {
	raw := []byte{0, 3, 0, 0}
	packet, err := ParsePacket(ProtocolRaw, raw)
	if err != nil || packet.Protocol != ProtocolRaw || string(packet.Raw) != string(raw) {
		t.Fatalf("raw packet = %#v, %v", packet, err)
	}
	if _, err := ParsePacket(6, raw); err != ErrProtocol {
		t.Fatalf("streaming protocol error = %v, want ErrProtocol", err)
	}
}

func TestDatagramWireAndI2PDPeerLimitsRemainSeparate(t *testing.T) {
	peerOversize := make([]byte, MaxI2PDSize+1)
	if _, err := MarshalRawTo(make([]byte, len(peerOversize)), peerOversize); err != ErrDatagram {
		t.Fatalf("i2pd-oversize raw marshal error = %v, want ErrDatagram", err)
	}
	if raw, err := ParseRaw(peerOversize); err != nil || len(raw) != len(peerOversize) {
		t.Fatalf("wire parse of i2pd-oversize raw = %d, %v", len(raw), err)
	}
	wireLimit := make([]byte, MaxWireSize)
	if raw, err := ParseRaw(wireLimit); err != nil || len(raw) != MaxWireSize {
		t.Fatalf("wire-limit raw = %d, %v", len(raw), err)
	}
	if _, err := ParseRaw(make([]byte, MaxWireSize+1)); err != ErrDatagram {
		t.Fatalf("oversize wire parse error = %v, want ErrDatagram", err)
	}
}
