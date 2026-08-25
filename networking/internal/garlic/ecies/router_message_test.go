package ecies

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"

	"gosuda.org/ivnp/networking/internal/i2np"
)

func TestRouterMessageNoiseNRoundTripAndTamperRejection(t *testing.T) {
	const now = uint64(1_700_000_000_000)
	privateBytes := bytes.Repeat([]byte{0x31}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	message := i2np.Message{
		Header:  i2np.Header{Type: i2np.ShortTunnelBuild, ID: 0x10203040, Expiration: now + 60_000},
		Payload: append([]byte{1}, make([]byte, i2np.ShortBuildRecordLen)...),
	}
	wire := make([]byte, 4096)
	sealed, err := SealRouterMessage(wire, private.PublicKey().Bytes(), message, now, bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 32+7+3+routerMessageHeader+len(message.Payload)+16 {
		t.Fatalf("Noise-N packet length = %d", len(sealed))
	}
	opened, err := OpenRouterMessage(make([]byte, len(sealed)), privateBytes, sealed, now)
	if err != nil || opened.Header != message.Header || !bytes.Equal(opened.Payload, message.Payload) {
		t.Fatalf("opened router message = %#v, %v", opened, err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err = OpenRouterMessage(make([]byte, len(tampered)), privateBytes, tampered, now); !errors.Is(err, ErrRouterMessage) {
		t.Fatalf("tampered router message error = %v", err)
	}
	if _, err = OpenRouterMessage(make([]byte, len(sealed)), privateBytes, sealed, now+routerMessageMaxSkew+1); !errors.Is(err, ErrRouterMessage) {
		t.Fatalf("stale router message error = %v", err)
	}
}
