package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	ivnp "gosuda.org/ivnp"
	"gosuda.org/ivnp/crypto/cryptx"
)

func TestVariableBuildKnownRequestLayouts(t *testing.T) {
	local := sha256.Sum256([]byte("legacy-local"))
	next := sha256.Sum256([]byte("legacy-next"))
	request := variableBuildTestRequest(next, 9, 10, 11)
	request.RequestHours, request.RequestMinutes, request.LifetimeSeconds, request.Endpoint = 0x01020304, 0x11121314, legacyBuildLifetimeSeconds, true
	for index := range request.LayerKey {
		request.LayerKey[index], request.IVKey[index], request.ReplyKey[index] = byte(index), byte(index+32), byte(index+64)
	}
	for index := range request.ReplyIV {
		request.ReplyIV[index] = byte(index + 96)
	}

	legacy := make([]byte, LegacyBuildRequestPlainSize)
	if err := MarshalElGamalBuildRequest(legacy, request, local, bytes.NewReader(bytes.Repeat([]byte{0xa5}, 29))); err != nil {
		t.Fatal(err)
	}
	variableBuildKnownRequestLayoutsRejected := binary.BigEndian.Uint32(legacy[:4]) != 9 || !bytes.Equal(legacy[4:36], local[:]) || binary.BigEndian.Uint32(legacy[36:40]) != 10 || !bytes.Equal(legacy[40:72], next[:]) || !bytes.Equal(legacy[72:104], request.LayerKey[:]) || !bytes.Equal(legacy[104:136], request.IVKey[:]) || !bytes.Equal(legacy[136:168], request.ReplyKey[:]) || !bytes.Equal(legacy[168:184], request.ReplyIV[:]) || legacy[184] != legacyBuildEndpointFlag || binary.BigEndian.Uint32(legacy[185:189]) != request.RequestHours || binary.BigEndian.Uint32(legacy[189:193]) != 11
	if !variableBuildKnownRequestLayoutsRejected {
		variableBuildKnownRequestLayoutsRejected = !bytes.Equal(legacy[193:], bytes.Repeat([]byte{0xa5}, 29))
	}
	if variableBuildKnownRequestLayoutsRejected {
		t.Fatal("legacy request layout differs")
	}
	parsedElGamal, err := ParseElGamalBuildRequest(legacy)
	elGamalRoundTripMismatch := err != nil
	if !elGamalRoundTripMismatch {
		elGamalRoundTripMismatch = parsedElGamal.ReceiveTunnelID != request.ReceiveTunnelID ||
			parsedElGamal.NextTunnelID != request.NextTunnelID ||
			parsedElGamal.NextRouter != request.NextRouter ||
			parsedElGamal.NextMessageID != request.NextMessageID ||
			!parsedElGamal.Endpoint
	}
	if elGamalRoundTripMismatch {
		t.Fatalf("ParseElGamalBuildRequest() = %#v, %v", parsedElGamal, err)
	}

	long := make([]byte, LongBuildRequestPlainSize)
	if err := MarshalLongECIESBuildRequest(long, request); err != nil {
		t.Fatal(err)
	}
	variableBuildKnownRequestLayoutsRejected = binary.BigEndian.Uint32(long[:4]) != 9 || binary.BigEndian.Uint32(long[4:8]) != 10 || !bytes.Equal(long[8:40], next[:]) || !bytes.Equal(long[40:72], request.LayerKey[:]) || !bytes.Equal(long[72:104], request.IVKey[:]) || !bytes.Equal(long[104:136], request.ReplyKey[:]) || !bytes.Equal(long[136:152], request.ReplyIV[:]) || long[152] != legacyBuildEndpointFlag || long[153] != 0 || long[154] != 0 || long[155] != 0 || binary.BigEndian.Uint32(long[156:160]) != request.RequestMinutes || binary.BigEndian.Uint32(long[160:164]) != legacyBuildLifetimeSeconds || binary.BigEndian.Uint32(long[164:168]) != 11
	if !variableBuildKnownRequestLayoutsRejected {
		variableBuildKnownRequestLayoutsRejected = !allZero(long[168:])
	}
	if variableBuildKnownRequestLayoutsRejected {
		t.Fatal("long request layout differs")
	}
	parsedLong, err := ParseLongECIESBuildRequest(long)
	longRoundTripMismatch := err != nil
	if !longRoundTripMismatch {
		longRoundTripMismatch = parsedLong.ReceiveTunnelID != request.ReceiveTunnelID ||
			parsedLong.NextTunnelID != request.NextTunnelID ||
			parsedLong.NextRouter != request.NextRouter ||
			parsedLong.NextMessageID != request.NextMessageID ||
			!parsedLong.Endpoint
	}
	if longRoundTripMismatch {
		t.Fatalf("ParseLongECIESBuildRequest() = %#v, %v", parsedLong, err)
	}
}

func TestVariableBuildRecordTampering(t *testing.T) {
	local := sha256.Sum256([]byte("long-local"))
	privateBytes := bytes.Repeat([]byte{0x42}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, LongBuildRequestPlainSize)
	if err = MarshalLongECIESBuildRequest(plain, variableBuildTestRequest(sha256.Sum256([]byte("next")), 1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, VariableBuildRecordSize)
	if _, err = encryptLongECIESBuildRequest(record, local, private.PublicKey().Bytes(), plain, bytes.NewReader(bytes.Repeat([]byte{0x51}, 32))); err != nil {
		t.Fatal(err)
	}
	record[VariableBuildRecordSize-1] ^= 1
	if _, _, err = DecryptLongECIESBuildRequest(make([]byte, LongBuildRequestPlainSize), record, local, privateBytes); err != ErrLegacyBuildRecord {
		t.Fatalf("long tamper error = %v", err)
	}

	public, secret, err := cryptx.GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	legacyPlain := make([]byte, LegacyBuildRequestPlainSize)
	if err = MarshalElGamalBuildRequest(legacyPlain, variableBuildTestRequest(sha256.Sum256([]byte("next-legacy")), 1, 2, 3), local, bytes.NewReader(bytes.Repeat([]byte{0x33}, 29))); err != nil {
		t.Fatal(err)
	}
	if err = EncryptElGamalBuildRequest(record, local, public, legacyPlain); err != nil {
		t.Fatal(err)
	}
	record[200] ^= 1
	if _, err = DecryptElGamalBuildRequest(make([]byte, LegacyBuildRequestPlainSize), record, local, secret); err != ErrLegacyBuildRecord {
		t.Fatalf("legacy tamper error = %v", err)
	}
}

func TestVariableBuildOneHopLegacyAndLong(t *testing.T) {
	for _, kind := range []VariableBuildKind{VariableBuildElGamal, VariableBuildLongECIES} {
		t.Run(map[VariableBuildKind]string{VariableBuildElGamal: "legacy", VariableBuildLongECIES: "long"}[kind], func(t *testing.T) {
			local := sha256.Sum256([]byte{byte(kind), 1})
			next := sha256.Sum256([]byte{byte(kind), 2})
			records := make([]byte, VariableBuildRecordSize)
			request := variableBuildTestRequest(next, 5, 6, 7)
			var static []byte
			var legacy cryptx.ElGamalPrivateKey
			var keys VariableBuildKeys
			var err error
			if kind == VariableBuildElGamal {
				public, private, generateErr := cryptx.GenerateElGamalKeyPair()
				if generateErr != nil {
					t.Fatal(generateErr)
				}
				legacy = private
				plain := make([]byte, LegacyBuildRequestPlainSize)
				if err = MarshalElGamalBuildRequest(plain, request, local, bytes.NewReader(bytes.Repeat([]byte{0x44}, 29))); err == nil {
					err = EncryptElGamalBuildRequest(records, local, public, plain)
				}
				keys = VariableBuildKeys{Kind: kind, LayerKey: request.LayerKey, IVKey: request.IVKey, ReplyKey: request.ReplyKey, ReplyIV: request.ReplyIV}
			} else {
				private := bytes.Repeat([]byte{0x55}, 32)
				privateKey, keyErr := ecdh.X25519().NewPrivateKey(private)
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				static = private
				plain := make([]byte, LongBuildRequestPlainSize)
				if err = MarshalLongECIESBuildRequest(plain, request); err == nil {
					keys, err = encryptLongECIESBuildRequest(records, local, privateKey.PublicKey().Bytes(), plain, bytes.NewReader(bytes.Repeat([]byte{0x66}, 32)))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var plaintext [LongBuildRequestPlainSize]byte
			got, _, _, err := ProcessVariableBuildRecords(records, plaintext[:], local, kind, static, legacy, true, bytes.NewReader(bytes.Repeat([]byte{0x77}, LongBuildResponsePlainSize)))
			if err != nil || got.ReceiveTunnelID != request.ReceiveTunnelID {
				t.Fatalf("ProcessVariableBuildRecords() = %#v, %v", got, err)
			}
			replies := make([]byte, LongBuildResponsePlainSize)
			if err = OpenVariableBuildReplies(records, []VariableBuildKeys{keys}, []uint8{0}, replies); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVariableBuildMixedThreeHopFourRecords(t *testing.T) {
	const hops = 3
	positions := []uint8{2, 0, 3}
	records := bytes.Repeat([]byte{0x9a}, legacyBuildMinRecords*VariableBuildRecordSize)
	keys := make([]VariableBuildKeys, hops)
	hashes := make([]ivnp.Hash, hops)
	statics := make([][]byte, hops)
	legacy := make([]cryptx.ElGamalPrivateKey, hops)
	kinds := []VariableBuildKind{VariableBuildElGamal, VariableBuildLongECIES, VariableBuildElGamal}
	requests := make([]VariableBuildRequest, hops)
	for hop := range hops {
		hashes[hop] = sha256.Sum256([]byte{byte(0x80 + hop)})
		requests[hop] = variableBuildTestRequest(sha256.Sum256([]byte{byte(0x90 + hop)}), uint32(20+hop), uint32(30+hop), uint32(40+hop))
		requests[hop].Endpoint = hop == hops-1
		record := records[int(positions[hop])*VariableBuildRecordSize : (int(positions[hop])+1)*VariableBuildRecordSize]
		if kinds[hop] == VariableBuildElGamal {
			public, private, err := cryptx.GenerateElGamalKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			legacy[hop] = private
			var plain [LegacyBuildRequestPlainSize]byte
			if err = MarshalElGamalBuildRequest(plain[:], requests[hop], hashes[hop], bytes.NewReader(bytes.Repeat([]byte{byte(0xa0 + hop)}, 29))); err != nil {
				t.Fatal(err)
			}
			if err = EncryptElGamalBuildRequest(record, hashes[hop], public, plain[:]); err != nil {
				t.Fatal(err)
			}
			keys[hop] = VariableBuildKeys{Kind: kinds[hop], LayerKey: requests[hop].LayerKey, IVKey: requests[hop].IVKey, ReplyKey: requests[hop].ReplyKey, ReplyIV: requests[hop].ReplyIV}
		} else {
			statics[hop] = bytes.Repeat([]byte{byte(0x40 + hop)}, 32)
			private, err := ecdh.X25519().NewPrivateKey(statics[hop])
			if err != nil {
				t.Fatal(err)
			}
			var plain [LongBuildRequestPlainSize]byte
			if err = MarshalLongECIESBuildRequest(plain[:], requests[hop]); err != nil {
				t.Fatal(err)
			}
			if keys[hop], err = encryptLongECIESBuildRequest(record, hashes[hop], private.PublicKey().Bytes(), plain[:], bytes.NewReader(bytes.Repeat([]byte{byte(0xb0 + hop)}, 32))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := PreprocessVariableBuildRecords(records, keys, positions); err != nil {
		t.Fatal(err)
	}
	for hop := range hops {
		var plaintext [LongBuildRequestPlainSize]byte
		request, derived, slot, err := ProcessVariableBuildRecords(records, plaintext[:], hashes[hop], kinds[hop], statics[hop], legacy[hop], true, bytes.NewReader(bytes.Repeat([]byte{byte(0xc0 + hop)}, LongBuildResponsePlainSize)))
		if err != nil || slot != positions[hop] || request.ReceiveTunnelID != requests[hop].ReceiveTunnelID || derived != keys[hop] {
			t.Fatalf("hop %d = %#v / %#v / %d / %v", hop, request, derived, slot, err)
		}
	}
	if err := OpenVariableBuildReplies(records, keys, positions, make([]byte, hops*LongBuildResponsePlainSize)); err != nil {
		t.Fatal(err)
	}
}

func variableBuildTestRequest(next ivnp.Hash, receive, tunnel, message uint32) VariableBuildRequest {
	request := VariableBuildRequest{ReceiveTunnelID: receive, NextTunnelID: tunnel, NextRouter: next, RequestHours: 1, RequestMinutes: 1, LifetimeSeconds: legacyBuildLifetimeSeconds, NextMessageID: message}
	for index := range request.LayerKey {
		request.LayerKey[index], request.IVKey[index], request.ReplyKey[index] = byte(index+1), byte(index+33), byte(index+65)
	}
	for index := range request.ReplyIV {
		request.ReplyIV[index] = byte(index + 97)
	}
	return request
}
