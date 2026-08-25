package netdb

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestSignedRouterInfoCapsControlsFloodfillAdmission(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	options := make([]byte, 16)
	optionLen, err := foundation.MarshalMappingTo(options, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte("f")}})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append(identity, make([]byte, 10)...)
	unsigned = append(unsigned, options[:optionLen]...)
	infoWire := append(unsigned, ed25519.Sign(private, unsigned)...)
	info, err := ParseRouterInfo(infoWire)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := info.Verify(); err != nil || !valid {
		t.Fatalf("RouterInfo signature = %t, %v", valid, err)
	}
	database := NewDatabase(foundation.Hash{}, DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(info, false, 1); err != nil {
		t.Fatal(err)
	}
	if targets := database.FloodTargets(make([]RouterRef, 0, 1), info.Hash()); len(targets) != 1 || !targets[0].Floodfill {
		t.Fatalf("flood targets = %#v", targets)
	}
}
