package netdb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

// A DatabaseStore or transport handshake may carry a RouterInfo whose identity
// claims a GOST R 34.10 signing key. Admission must refuse it as unsupported
// instead of running the multi-millisecond curve verification.
func TestAdmitRouterInfoRefusesGOSTSigningIdentity(t *testing.T) {
	const now = uint64(1_000_000)
	gostY, err := hex.DecodeString("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4")
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	identity[256+63] = 3
	copy(identity[320:384], gostY)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningGOSTR3410_512)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	unsigned := append(identity, make([]byte, 12)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):len(identity)+8], now)
	info, err := foundation.NetworkDatabaseParseRouterInfo(append(unsigned, bytes.Repeat([]byte{0x11}, 128)...))
	if err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(foundation.Hash{}, 0)
	if err := database.AdmitRouterInfo(info, false, now); !errors.Is(err, foundation.ErrUnsupportedSignature) {
		t.Fatalf("AdmitRouterInfo(GOST identity) = %v, want %v", err, foundation.ErrUnsupportedSignature)
	}
	if database.Routers().Len() != 0 {
		t.Fatal("GOST RouterInfo was retained")
	}
}
