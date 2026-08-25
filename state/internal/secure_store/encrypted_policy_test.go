package state

import (
	"bytes"
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestEncryptedLeaseSetPolicyPersistsForLegacyEd25519Destination(t *testing.T) {
	store := testStore(t)
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	address, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	bundle.Destinations["legacy"] = address
	var psk [32]byte
	for index := range psk {
		psk[index] = byte(index)
	}
	bundle.EncryptedLeaseSetPolicies = map[string]EncryptedLeaseSetPolicy{
		"legacy": {Secret: []byte("private lookup secret"), PSKClients: [][32]byte{psk}},
	}
	if err = store.Save(bundle); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := loaded.EncryptedLeaseSetPolicies["legacy"]
	if !ok || !bytes.Equal(policy.Secret, []byte("private lookup secret")) || len(policy.PSKClients) != 1 || policy.PSKClients[0] != psk {
		t.Fatalf("loaded policy = %#v", policy)
	}
}

func TestBundleReleaseSensitiveWipesAllPrivateMaterial(t *testing.T) {
	routerPrivate := bytes.Repeat([]byte{1}, 64)
	destinationPrivate := bytes.Repeat([]byte{2}, 64)
	secret := []byte("encrypted lease set secret")
	remoteSecret := []byte("remote encrypted lease set secret")
	remoteIdentity := bytes.Repeat([]byte{3}, 391)
	var client, dhPrivate, dhPublic, psk [32]byte
	client[0], dhPrivate[0], dhPublic[0], psk[0] = 4, 5, 6, 7
	bundle := Bundle{
		Router:                    ivnp.LocalRouterAddress{SigningPrivate: routerPrivate, X25519Private: [32]byte{8}},
		NTCP2StaticPrivate:        bytes.Repeat([]byte{9}, 32),
		SSU2StaticPrivate:         bytes.Repeat([]byte{10}, 32),
		DestinationPrivate:        map[string][]byte{"local": destinationPrivate},
		EncryptedLeaseSetPolicies: map[string]EncryptedLeaseSetPolicy{"local": {Secret: secret, DHClients: [][32]byte{client}}},
		DestinationAddressPolicies: map[string][]RemoteELSAuthorization{"local": {{
			Identity: remoteIdentity, Secret: remoteSecret, Kind: RemoteELSAuthorizationDH,
			DHPrivate: dhPrivate, DHPublic: dhPublic, PSK: psk,
		}}},
	}
	ntcp := bundle.NTCP2StaticPrivate
	ssu := bundle.SSU2StaticPrivate
	bundle.ReleaseSensitive()
	bundle.ReleaseSensitive()
	for _, retained := range [][]byte{routerPrivate, destinationPrivate, secret, remoteSecret, remoteIdentity, ntcp, ssu} {
		for _, value := range retained {
			if value != 0 {
				t.Fatal("bundle release retained sensitive bytes")
			}
		}
	}
	if bundle.Router.Hash != (ivnp.Hash{}) || bundle.DestinationPrivate != nil || bundle.EncryptedLeaseSetPolicies != nil || bundle.DestinationAddressPolicies != nil {
		t.Fatal("bundle release retained sensitive ownership graph")
	}
}
