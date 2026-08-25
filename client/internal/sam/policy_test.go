package sam

import (
	ivnp "gosuda.org/ivnp/foundation"
	"testing"
)

func TestSessionPolicyPreservesCryptoOrderAndAuthorizationMode(t *testing.T) {
	var client [32]byte
	for index := range client {
		client[index] = byte(index + 1)
	}
	policy, err := sessionPolicy(map[string]string{
		"I2CP.LEASESETTYPE":     "5",
		"I2CP.LEASESETENCTYPE":  "6,4,7",
		"I2CP.LEASESETAUTHTYPE": "1",
		"I2CP.LEASESETCLIENT.0": string(ivnp.EncodeI2PBase64(client[:])),
		"I2CP.LEASESETSECRET":   "not-returned-in-status",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLeaseSetPolicy(&policy)
	if !policy.Encrypted || len(policy.CryptoTypes) != 3 || policy.CryptoTypes[0] != 6 || policy.CryptoTypes[1] != 4 || policy.CryptoTypes[2] != 7 {
		t.Fatalf("crypto policy = %#v", policy.CryptoTypes)
	}
	if len(policy.DHClients) != 1 || policy.DHClients[0] != client || len(policy.PSKClients) != 0 {
		t.Fatal("DH authorization did not map to destination policy")
	}
	if string(policy.Secret) != "not-returned-in-status" {
		t.Fatal("LeaseSet secret was not retained for controller consumption")
	}
	for _, invalid := range []string{"7,7", "4,6,9", "6,,4", " 6,4"} {
		if _, err = sessionPolicy(map[string]string{"I2CP.LEASESETENCTYPE": invalid}); err == nil {
			t.Fatalf("accepted invalid crypto order %q", invalid)
		}
	}
}
