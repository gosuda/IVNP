package overlay

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestCanonicalIdentifiers(t *testing.T) {
	if got := PublicFastFabricID; got != FabricID(sha256.Sum256([]byte("ivnp-public-fast-fabric/v1"))) {
		t.Fatalf("PublicFastFabricID mismatch")
	}
	if got := PublicFastRealmID; got != RealmID(sha256.Sum256([]byte("ivnp-public-fast-realm/v1"))) {
		t.Fatalf("PublicFastRealmID mismatch")
	}
	const wantI2PRealm = "e9010588d49cef677ffe208b3315dd55b30aa6085957bd1a8ad4a6825c624a90"
	if got := hex.EncodeToString(PublicI2PRealmID[:]); got != wantI2PRealm {
		t.Fatalf("PublicI2PRealmID = %s, want %s", got, wantI2PRealm)
	}
}

func TestEndpointIDFromDestination(t *testing.T) {
	dest, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer dest.ReleaseSensitive()
	identity, err := dest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	canonical := identity.Bytes()
	id, err := EndpointIDFromDestination(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if EndpointID(dest.Hash()) != id {
		t.Fatalf("endpoint id does not match destination hash")
	}
	truncated := canonical[:len(canonical)-1]
	if _, err := EndpointIDFromDestination(truncated); err == nil {
		t.Fatalf("truncated destination accepted")
	}
}

func TestEndpointIDTextRoundTrip(t *testing.T) {
	var id EndpointID
	for i := range id {
		id[i] = byte(i)
	}
	parsed, err := ParseEndpointID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != id {
		t.Fatalf("round trip mismatch")
	}
	raw := endpointText(id)
	if got, err := ParseEndpointID(raw); err != nil || got != id {
		t.Fatalf("bare form: %v", err)
	}
	if _, err := ParseEndpointID("ivnp://" + raw + "AA"); err == nil {
		t.Fatalf("oversized form accepted")
	}
	if _, err := ParseEndpointID("ivnp://" + "AAAA"); err == nil {
		t.Fatalf("short form accepted")
	}
	upper := "ivnp://" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:])
	if _, err := ParseEndpointID(upper); err == nil {
		t.Fatalf("uppercase noncanonical form accepted")
	}
}
