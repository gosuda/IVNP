package datagram

import (
	"crypto/ed25519"
	"crypto/rand"
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestV2AndV3(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ivnp.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(ivnp.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(ivnp.SigningEdDSASHA512Ed25519)
	payload := []byte("v2")
	ident, _, err := ivnp.ParseIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	hash := ident.Hash()
	wire := make([]byte, ident.EncodedLen()+2+len(payload)+ed25519.SignatureSize)
	n, err := MarshalV2To(wire, hash, ident, 2, ivnp.Mapping{}, OfflineSignature{}, payload, func(input []byte) ([]byte, error) {
		return ed25519.Sign(private, input), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wire = wire[:n]
	v2, err := ParseV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := v2.VerifyTargetAt(hash, 0); err != nil || !valid {
		t.Fatalf("V2 verify=%t err=%v", valid, err)
	}
	v3wire := make([]byte, len(hash)+2+len("v3"))
	if _, err := MarshalV3To(v3wire, hash, 3, ivnp.Mapping{}, []byte("v3")); err != nil {
		t.Fatal(err)
	}
	v3, err := ParseV3(v3wire)
	if err != nil || string(v3.Payload) != "v3" {
		t.Fatalf("V3=%#v err=%v", v3, err)
	}
}
