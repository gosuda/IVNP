package garlic

import (
	"bytes"
	"testing"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
)

func TestSessionManagerSizedBuffersRoundTripMixedTraffic(t *testing.T) {
	public, private, err := cryptography.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, tags := range []int{1, 40, MaxSessionTags} {
		sender := NewSessionManager(SessionManagerConfig{TagsPerMessage: tags, MaxTagsPerPeer: MaxSessionTags})
		receiver := NewSessionManager(SessionManagerConfig{})
		t.Cleanup(func() {
			if err := sender.Close(); err != nil {
				t.Error(err)
			}
		})
		t.Cleanup(func() {
			if err := receiver.Close(); err != nil {
				t.Error(err)
			}
		})
		for index, size := range []int{128, 48 * 1024, 128} {
			payload := bytes.Repeat([]byte{byte(index + 1)}, size)
			capacity, err := sender.EncryptBufferSize(len(payload))
			if err != nil {
				t.Fatal(err)
			}
			packet, err := sender.Encrypt(make([]byte, capacity), foundation.Hash{1}, public, payload, 100)
			if err != nil {
				t.Fatalf("tags %d size %d: %v", tags, size, err)
			}
			decoded, _, isNew, err := receiver.Receive(make([]byte, capacity), packet, private, 100)
			if err != nil || !bytes.Equal(decoded, payload) || isNew != (index == 0) {
				t.Fatalf("tags %d size %d round trip: new %t, %v", tags, size, isNew, err)
			}
			sender.ConfirmOutboundTags(foundation.Hash{1}, 100)
		}
	}
}
