package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestShortBuildRequestAndReplyRoundTrip(t *testing.T) {
	privateBytes := make([]byte, 32)
	for i := range privateBytes {
		privateBytes[i] = byte(i + 1)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	local := sha256.Sum256([]byte("short-build-hop"))
	next := sha256.Sum256([]byte("next-hop"))
	request := ShortBuildRequest{
		ReceiveTunnelID: 1,
		NextTunnelID:    2,
		NextRouter:      next,
		Endpoint:        true,
		RequestMinutes:  28_333_333,
		LifetimeSeconds: shortBuildLifetime,
		NextMessageID:   3,
	}
	plaintext := make([]byte, ShortBuildRequestPlainSize)
	if err = marshalShortBuildRequest(plaintext, request, nil, bytes.NewReader(bytes.Repeat([]byte{0x29}, ShortBuildRequestPlainSize))); err != nil {
		t.Fatal(err)
	}

	record := make([]byte, ShortBuildRecordSize)
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	creatorKeys, err := encryptShortBuildRequest(record, local, private.PublicKey().Bytes(), plaintext, random)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record[:shortBuildPeerSize], local[:shortBuildPeerSize]) {
		t.Fatal("record is not addressed to the hop hash")
	}
	decrypted := make([]byte, ShortBuildRequestPlainSize)
	got, hopKeys, err := DecryptShortBuildRequest(decrypted, record, local, privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("short request plaintext mismatch")
	}
	parsed, err := ParseShortBuildRequest(got)
	if err != nil {
		t.Fatal(err)
	}
	shortBuildRequestAndReplyRoundTripRejected := parsed.ReceiveTunnelID != request.ReceiveTunnelID || parsed.NextTunnelID != request.NextTunnelID || parsed.NextRouter != request.NextRouter || !parsed.Endpoint || parsed.Gateway || parsed.RequestMinutes != request.RequestMinutes || parsed.LifetimeSeconds != shortBuildLifetime || parsed.NextMessageID != request.NextMessageID
	if !shortBuildRequestAndReplyRoundTripRejected {
		shortBuildRequestAndReplyRoundTripRejected = parsed.Options.EncodedLen() != 2
	}
	if shortBuildRequestAndReplyRoundTripRejected {
		t.Fatalf("parsed request = %#v", parsed)
	}
	if creatorKeys != hopKeys || !creatorKeys.HasGarlicKeys {
		t.Fatal("creator and hop derived different endpoint keys")
	}

	reply := make([]byte, ShortBuildReplyPlainSize)
	reply[0], reply[1], reply[len(reply)-1] = 0, 0, 0
	for i := 2; i < len(reply)-1; i++ {
		reply[i] = byte(255 - i)
	}
	encryptedReply := make([]byte, ShortBuildRecordSize)
	if _, err = SealShortBuildReply(encryptedReply, reply, creatorKeys, 3); err != nil {
		t.Fatal(err)
	}
	openedReply := make([]byte, ShortBuildReplyPlainSize)
	if _, err = OpenShortBuildReply(openedReply, encryptedReply, hopKeys, 3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(openedReply, reply) {
		t.Fatal("short reply plaintext mismatch")
	}

	layered := make([]byte, ShortBuildRecordSize)
	restored := make([]byte, ShortBuildRecordSize)
	if err = TransformShortBuildRecord(layered, encryptedReply, creatorKeys.ReplyKey, 3); err != nil {
		t.Fatal(err)
	}
	if err = TransformShortBuildRecord(restored, layered, creatorKeys.ReplyKey, 3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, encryptedReply) {
		t.Fatal("ChaCha record layer is not reversible")
	}
}

func TestShortBuildRecordRejectsTamperingAndWrongHop(t *testing.T) {
	privateBytes := bytes.Repeat([]byte{0x31}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	local := sha256.Sum256([]byte("local"))
	plaintext := make([]byte, ShortBuildRequestPlainSize)
	plaintext[43] = 0
	binary.BigEndian.PutUint32(plaintext[48:52], 600)
	record := make([]byte, ShortBuildRecordSize)
	if _, err = encryptShortBuildRequest(record, local, private.PublicKey().Bytes(), plaintext, bytes.NewReader(bytes.Repeat([]byte{0x73}, 32))); err != nil {
		t.Fatal(err)
	}

	wrong := sha256.Sum256([]byte("wrong"))
	if _, _, err = DecryptShortBuildRequest(make([]byte, ShortBuildRequestPlainSize), record, wrong, privateBytes); err != ErrShortBuildRecord {
		t.Fatalf("wrong-hop error = %v, want %v", err, ErrShortBuildRecord)
	}
	record[len(record)-1] ^= 1
	if _, _, err = DecryptShortBuildRequest(make([]byte, ShortBuildRequestPlainSize), record, local, privateBytes); err != ErrShortBuildRecord {
		t.Fatalf("tampered-record error = %v, want %v", err, ErrShortBuildRecord)
	}
}

func TestShortBuildRequestValidation(t *testing.T) {
	request := ShortBuildRequest{
		ReceiveTunnelID: 1,
		NextTunnelID:    2,
		NextRouter:      sha256.Sum256([]byte("next")),
		RequestMinutes:  28_333_333,
		LifetimeSeconds: shortBuildLifetime,
		NextMessageID:   3,
	}
	plaintext := make([]byte, ShortBuildRequestPlainSize)
	if err := marshalShortBuildRequest(plaintext, request, nil, bytes.NewReader(bytes.Repeat([]byte{1}, ShortBuildRequestPlainSize))); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"zero receive ID": func(p []byte) { clear(p[0:4]) },
		"both directions": func(p []byte) { p[shortBuildFlagOffset] = shortBuildGatewayFlag | shortBuildEndpointFlag },
		"reserved flag":   func(p []byte) { p[shortBuildFlagOffset] = 1 },
		"reserved bytes":  func(p []byte) { p[41] = 1 },
		"layer type":      func(p []byte) { p[43] = 1 },
		"lifetime":        func(p []byte) { binary.BigEndian.PutUint32(p[48:52], shortBuildLifetime-1) },
		"mapping length":  func(p []byte) { binary.BigEndian.PutUint16(p[56:58], shortBuildMaxOptionsSize) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), plaintext...)
			mutate(candidate)
			if _, err := ParseShortBuildRequest(candidate); err != ErrShortBuildRecord {
				t.Fatalf("error = %v, want %v", err, ErrShortBuildRecord)
			}
		})
	}
	request.Gateway, request.Endpoint = true, true
	if err := MarshalShortBuildRequest(plaintext, request, nil); err != ErrShortBuildRecord {
		t.Fatalf("conflicting direction error = %v, want %v", err, ErrShortBuildRecord)
	}
}

func TestShortBuildRecordSetThreeHopRoundTrip(t *testing.T) {
	const hops = 3
	positions := []uint8{2, 0, 3}
	records := bytes.Repeat([]byte{0xa5}, 4*ShortBuildRecordSize)
	keys := make([]ShortBuildKeys, hops)
	privateKeys := make([][]byte, hops)
	hashes := make([][32]byte, hops)
	requests := make([]ShortBuildRequest, hops)
	for hop := range hops {
		privateKeys[hop] = bytes.Repeat([]byte{byte(0x51 + hop)}, 32)
		private, err := ecdh.X25519().NewPrivateKey(privateKeys[hop])
		if err != nil {
			t.Fatal(err)
		}
		hashes[hop] = sha256.Sum256([]byte{byte(hop)})
		requests[hop] = ShortBuildRequest{
			ReceiveTunnelID: uint32(100 + hop),
			NextTunnelID:    uint32(101 + hop),
			NextRouter:      sha256.Sum256([]byte{byte(hop + 1)}),
			Endpoint:        hop == hops-1,
			RequestMinutes:  28_333_333,
			LifetimeSeconds: shortBuildLifetime,
			NextMessageID:   uint32(200 + hop),
		}
		var plaintext [ShortBuildRequestPlainSize]byte
		if err = marshalShortBuildRequest(plaintext[:], requests[hop], nil, bytes.NewReader(bytes.Repeat([]byte{byte(0x61 + hop)}, len(plaintext)))); err != nil {
			t.Fatal(err)
		}
		slot := int(positions[hop])
		record := records[slot*ShortBuildRecordSize : (slot+1)*ShortBuildRecordSize]
		keys[hop], err = encryptShortBuildRequest(record, hashes[hop], private.PublicKey().Bytes(), plaintext[:], bytes.NewReader(bytes.Repeat([]byte{byte(0x71 + hop)}, 32)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := PreprocessShortBuildRecords(records, keys, positions); err != nil {
		t.Fatal(err)
	}
	for hop := range hops {
		var plaintext [ShortBuildRequestPlainSize]byte
		request, derived, slot, err := ProcessShortBuildRecords(records, plaintext[:], hashes[hop], privateKeys[hop], true, bytes.NewReader(bytes.Repeat([]byte{byte(0x81 + hop)}, ShortBuildReplyPlainSize)))
		if err != nil {
			t.Fatalf("hop %d: %v", hop, err)
		}
		if slot != positions[hop] || request.ReceiveTunnelID != requests[hop].ReceiveTunnelID || derived != keys[hop] {
			t.Fatalf("hop %d processed wrong request", hop)
		}
	}
	replies := make([]byte, hops*ShortBuildReplyPlainSize)
	if err := OpenShortBuildReplies(records, keys, positions, replies); err != nil {
		t.Fatal(err)
	}
	for hop := range hops {
		if code := replies[(hop+1)*ShortBuildReplyPlainSize-1]; code != 0 {
			t.Fatalf("hop %d reply code = %d", hop, code)
		}
	}
}

func TestTunnelKDFMatchesStandardHKDF(t *testing.T) {
	salt := sha256.Sum256([]byte("short-build-chain"))
	for _, info := range []string{"SMTunnelReplyKey", "SMTunnelLayerKey", "TunnelLayerIVKey", "RGarlicKeyAndTag"} {
		first, second := tunnelKDF(salt, info)
		want, err := hkdf.Key(sha256.New, nil, salt[:], info, 64)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first[:], want[:32]) || !bytes.Equal(second[:], want[32:]) {
			t.Fatalf("%s KDF mismatch", info)
		}
	}
}

func BenchmarkShortBuildRequestEncrypt(b *testing.B) {
	private, err := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)))
	if err != nil {
		b.Fatal(err)
	}
	local := sha256.Sum256([]byte("benchmark-hop"))
	plaintext := make([]byte, ShortBuildRequestPlainSize)
	binary.BigEndian.PutUint32(plaintext[48:52], 600)
	record := make([]byte, ShortBuildRecordSize)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err = EncryptShortBuildRequest(record, local, private.PublicKey().Bytes(), plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShortBuildRequestDecrypt(b *testing.B) {
	privateBytes := bytes.Repeat([]byte{0x42}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		b.Fatal(err)
	}
	local := sha256.Sum256([]byte("benchmark-hop"))
	plaintext := make([]byte, ShortBuildRequestPlainSize)
	binary.BigEndian.PutUint32(plaintext[48:52], 600)
	record := make([]byte, ShortBuildRecordSize)
	if _, err = encryptShortBuildRequest(record, local, private.PublicKey().Bytes(), plaintext, bytes.NewReader(bytes.Repeat([]byte{0x43}, 32))); err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, ShortBuildRequestPlainSize)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err = DecryptShortBuildRequest(dst, record, local, privateBytes); err != nil {
			b.Fatal(err)
		}
	}
}
