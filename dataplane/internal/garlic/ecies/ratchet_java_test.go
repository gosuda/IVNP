package garlicecies

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"gosuda.org/ivnp/foundation"
)

// Generated with Java I2P 2.13.0 RatchetTagSet and ChaChaPolyCipherState.
// Root bytes are 00..1f, directional key material is 20..3f, and the payload is
// a GarlicClove block containing the big-endian four-byte message index.
func TestRatchetWindowJavaI2P2130Vectors(t *testing.T) {
	vectors := []struct {
		index  uint32
		packet string
	}{
		{0, "fad4c17fbf19747fd54da3ef349ea7b825cb208478319914434412c426ebb1"},
		{23, "017f9228e5accf66508916ca22495b7ec6c3bbdf0a722899e24bcf9ecb15d0"},
		{31, "03293374a2df12524c91a17673d4aeb0c594e31b5ab0f92935d0092f8a449a"},
		{32, "e869a26a161dcc841c387e20d23e9a41be4187b4320af42710445781a7fb3e"},
		{63, "9378fdf754ba3d646756ee8484ed080b47c212b3488c2d1f50b1a124eb97b1"},
		{511, "c9654804c08ba22f34633041953a1e8d9fc3bbb55a0e7a5cc1cefd17f3259c"},
		{512, "3a6a3e5b05e0eb9ddf0fa11f775f693911b8c74289de4d8c27067b66870b0d"},
		{1023, "d82e0a039fff52515ec9f77f81971dc948889e3a47d342b6f8e662d856bf72"},
		{1535, "2b17a9c7548f45a1a07490ea03cf9129b7182cdcee104c53cd0ba57c4a4604"},
		{2047, "aa0ba1a116fad1e8237dfb5b8914f16f869d3691a547864c1fb529c4997253"},
	}
	local, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.ReleaseSensitive)
	manager, err := NewRatchetManager(local, RatchetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.ReleaseSensitive)
	var root, material [32]byte
	for index := range root {
		root[index], material[index] = byte(index), byte(index+32)
	}
	const now = uint64(1_800_000_000_000)
	inbound, err := newTagSet(0, root, material[:], now+defaultSessionLife)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := newTagSet(0, root, material[:], now+defaultSessionLife)
	if err != nil {
		t.Fatal(err)
	}
	peer := foundation.Hash{1}
	s := &session{peer: peer, inbound: inbound, outbound: outbound, created: now, expires: now + defaultSessionLife}
	inbound.owner, outbound.owner = s, s
	if err := manager.installSessionLocked(s, now); err != nil {
		releaseSession(s)
		t.Fatal(err)
	}
	var encrypted, scratch, plaintext [64]byte
	payload := []byte{ratchetGarlicClove, 0, 4, 0, 0, 0, 0}
	selected := 0
	for index := uint32(0); index <= vectors[len(vectors)-1].index; index++ {
		binary.BigEndian.PutUint32(payload[3:], index)
		packet, err := manager.EncryptExistingWithScratch(encrypted[:], scratch[:], peer, payload, RatchetOptions{}, now+1)
		if err != nil {
			t.Fatalf("encrypt index %d: %v", index, err)
		}
		if index != vectors[selected].index {
			continue
		}
		javaPacket, err := hex.DecodeString(vectors[selected].packet)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(packet, javaPacket) {
			t.Fatalf("index %d encrypted packet=%x, Java=%x", index, packet, javaPacket)
		}
		got, err := manager.Receive(plaintext[:], nil, javaPacket, now+1)
		if err != nil || !bytes.Equal(got.Payload, payload) {
			t.Fatalf("Java index %d payload=%x, want %x; error=%v", index, got.Payload, payload, err)
		}
		selected++
	}
}
