package registration

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestAuthenticationEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := Ed25519Signer(private)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := Authentication("Example.I2P", []byte("destination"), signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(auth, "#!sig=")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "example.i2p=") {
		t.Fatalf("auth=%q", auth)
	}
	signature, err := i2pBase64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, []byte(parts[0]), signature) {
		t.Fatal("registration signature invalid")
	}
}

func TestI2PBase64Alphabet(t *testing.T) {
	if got := i2pBase64.EncodeToString([]byte{0xfb, 0xff}); got != "-~8=" {
		t.Fatalf("I2P Base64 = %q", got)
	}
}
