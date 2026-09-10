package garlic

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestJavaDeliveryInstructionsIgnoresDeprecatedEncryptedFlagCorpus(t *testing.T) {
	// Each record starts with DeliveryInstructions.writeBytes(byte[], int), then
	// adds the deprecated 0x80 bit and is accepted by readBytes(). The records
	// were sampled during a 10-minute run of Java I2P commit fda1ced99c3b1e8513b88c543bca3aeb668330a8.
	const path = "testdata/java-fda1ced/delivery-encrypted-destination.corpus"
	corpus, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Java DeliveryInstructions corpus: %v", err)
	}
	var records int
	for offset := 0; offset < len(corpus); records++ {
		if len(corpus)-offset < 4 {
			t.Fatalf("Java DeliveryInstructions corpus has truncated record length at byte %d", offset)
		}
		length := int(binary.BigEndian.Uint32(corpus[offset : offset+4]))
		offset += 4
		if length > len(corpus)-offset {
			t.Fatalf("Java DeliveryInstructions record %d declares %d bytes with %d remaining", records, length, len(corpus)-offset)
		}
		fixture := corpus[offset : offset+length]
		offset += length
		if len(fixture) == 0 || fixture[0]&0x80 == 0 {
			t.Fatalf("Java DeliveryInstructions record %d lacks deprecated encrypted flag", records)
		}
		// Java's corpus records contain a flag byte and a 32-byte destination,
		// with no delay field.
		if len(fixture) != 33 {
			t.Fatalf("record %d: Java destination fixture has %d bytes, want 33", records, len(fixture))
		}
		delivery, used, parseErr := ParseDelivery(fixture)
		if parseErr != nil || used != len(fixture) {
			t.Fatalf("record %d: parse Java DeliveryInstructions = %#v, %d/%d bytes, %v", records, delivery, used, len(fixture), parseErr)
		}
		if delivery.Type != DeliveryDestination {
			t.Fatalf("record %d: Java DeliveryInstructions type = %d, want destination", records, delivery.Type)
		}
		if !bytes.Equal(delivery.To[:], fixture[1:33]) {
			t.Errorf("record %d: destination = %x, want Java fixture destination %x", records, delivery.To, fixture[1:33])
		}
		if delivery.Delay != 0 {
			t.Errorf("record %d: delay = %d, want 0 for Java fixture without delay", records, delivery.Delay)
		}
	}
	if records != 21 {
		t.Fatalf("Java DeliveryInstructions corpus has %d records, want 21 samples spanning both run endpoints", records)
	}
}
