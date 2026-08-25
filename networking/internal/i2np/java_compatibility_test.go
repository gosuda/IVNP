package i2np

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// These corpora were sampled every 30 seconds during a 10-minute run of Java
// I2P router commit fda1ced99c3b1e8513b88c543bca3aeb668330a8.
const javaI2NPFixtureDirectory = "testdata/java-fda1ced/"

func readJavaI2NPCorpus(t testing.TB, name string) [][]byte {
	t.Helper()
	corpus, err := os.ReadFile(javaI2NPFixtureDirectory + name)
	if err != nil {
		t.Fatalf("read Java I2P corpus %q: %v", name, err)
	}
	var records [][]byte
	for offset := 0; offset < len(corpus); {
		if len(corpus)-offset < 4 {
			t.Fatalf("Java I2P corpus %q has truncated record length at byte %d", name, offset)
		}
		length := int(binary.BigEndian.Uint32(corpus[offset : offset+4]))
		offset += 4
		if length > len(corpus)-offset {
			t.Fatalf("Java I2P corpus %q record %d declares %d bytes with %d remaining", name, len(records), length, len(corpus)-offset)
		}
		records = append(records, corpus[offset:offset+length])
		offset += length
	}
	if len(records) != 21 {
		t.Fatalf("Java I2P corpus %q has %d records, want 21 samples spanning both run endpoints", name, len(records))
	}
	return records
}

func TestJavaDatabaseLookupECIESPublicKeyCorpus(t *testing.T) {
	seenIDs := make(map[uint32]struct{})
	for index, frame := range readJavaI2NPCorpus(t, "database-lookup-ecies-public-key.corpus") {
		message, used, err := Parse(frame)
		if err != nil || used != len(frame) || message.Header.Type != DatabaseLookup {
			t.Fatalf("record %d: parse Java DatabaseLookup = type %d, %d/%d bytes, %v", index, message.Header.Type, used, len(frame), err)
		}
		lookup, err := ParseDatabaseLookup(message.Payload)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if lookup.Flags != lookupDelivery|lookupEncrypted|lookupECIES|0x08 || lookup.ReplyTunnelID != 0x01020304 {
			t.Fatalf("record %d: Java DatabaseLookup flags/tunnel = %#x/%#x", index, lookup.Flags, lookup.ReplyTunnelID)
		}
		if !lookup.ReplyUsesECIESPublicKey() || lookup.ExcludedCount() != 1 || len(lookup.ReplyPublicKey) != 32 {
			t.Fatalf("record %d: Java DatabaseLookup = public key %t, %d exclusions, %d key bytes", index, lookup.ReplyUsesECIESPublicKey(), lookup.ExcludedCount(), len(lookup.ReplyPublicKey))
		}
		if bytes.Equal(lookup.ReplyPublicKey, make([]byte, 32)) || len(lookup.ReplyKey) != 0 || len(lookup.ReplyTags) != 0 {
			t.Fatalf("record %d: Java ECIES public-key fields = public %x symmetric %x tags %x", index, lookup.ReplyPublicKey, lookup.ReplyKey, lookup.ReplyTags)
		}
		seenIDs[message.Header.ID] = struct{}{}
	}
	if len(seenIDs) != 21 {
		t.Fatalf("Java DatabaseLookup corpus has %d unique message IDs, want 21", len(seenIDs))
	}
}

func TestJavaTransportExpirationCorpus(t *testing.T) {
	encodedCounts := make(map[uint32]int)
	for index, frame := range readJavaI2NPCorpus(t, "transport-expiration.corpus") {
		header, err := ParseTransportHeader(frame)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		encoded := binary.BigEndian.Uint32(frame[5:9])
		if encoded != 1 && encoded != 2 {
			t.Fatalf("record %d: Java transport expiration seconds = %d", index, encoded)
		}
		wantExpiration := uint64(encoded)*1_000 + 500
		if header.Type != DeliveryStatus || header.Expiration != wantExpiration {
			t.Fatalf("record %d: Java transport header = type %d expiration %d, want type %d expiration %d", index, header.Type, header.Expiration, DeliveryStatus, wantExpiration)
		}
		if _, err = ParseDeliveryStatus(frame[TransportHeaderLen:]); err != nil {
			t.Fatalf("record %d: parse Java transport payload: %v", index, err)
		}
		encodedCounts[encoded]++
	}
	if encodedCounts[1] != 11 || encodedCounts[2] != 10 {
		t.Fatalf("Java transport boundary samples = %#v, want 11 rounded down and 10 rounded up", encodedCounts)
	}
}

func TestJavaDatabaseStoreAllZeroHashCorpus(t *testing.T) {
	for index, frame := range readJavaI2NPCorpus(t, "database-store-zero-hash.corpus") {
		message, used, err := Parse(frame)
		if err != nil || used != len(frame) || message.Header.Type != DatabaseStore {
			t.Fatalf("record %d: parse Java all-zero DatabaseStore frame = type %d, %d/%d bytes, %v", index, message.Header.Type, used, len(frame), err)
		}
		if _, err = ParseDatabaseStore(message.Payload); !errors.Is(err, ErrMalformed) {
			t.Fatalf("record %d: parse Java all-zero DatabaseStore payload = %v, want ErrMalformed", index, err)
		}
	}
}
