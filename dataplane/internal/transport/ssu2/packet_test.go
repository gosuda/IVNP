package ssu2

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"gosuda.org/ivnp/cryptography"
)

func TestHeaderRoundTrips(t *testing.T) {
	long := LongHeader{DestinationID: 1, PacketNumber: 2, Type: SessionRequest, Version: Version, NetworkID: NetworkID, SourceID: 3, Token: 4}
	var longWire [LongHeaderLen]byte
	if err := long.MarshalTo(longWire[:]); err != nil {
		t.Fatal(err)
	}
	parsedLong, err := ParseLongHeader(longWire[:], NetworkID)
	if err != nil || parsedLong != long {
		t.Fatalf("long header = %#v, %v", parsedLong, err)
	}
	short := ShortHeader{DestinationID: 1, Type: SessionConfirmed, Fragment: 1}
	var shortWire [ShortHeaderLen]byte
	if err := short.MarshalTo(shortWire[:]); err != nil {
		t.Fatal(err)
	}
	parsedShort, err := ParseShortHeader(shortWire[:])
	if err != nil || parsedShort != short {
		t.Fatalf("short header = %#v, %v", parsedShort, err)
	}
}

func TestHeaderProtectionIsReversible(t *testing.T) {
	packet := make([]byte, MinPacketLen)
	for i := range packet {
		packet[i] = byte(i)
	}
	original := append([]byte(nil), packet...)
	key1, key2 := make([]byte, 32), make([]byte, 32)
	for i := range key1 {
		key1[i], key2[i] = byte(i), byte(i+32)
	}
	if err := ProtectHeader(packet, key1, key2, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(packet, original) {
		t.Fatal("header protection did not change packet")
	}
	if err := ProtectHeader(packet, key1, key2, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("header protection did not reverse")
	}
}

func TestDataCipherRoundTrip(t *testing.T) {
	dataKey, headerKey1, headerKey2 := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for i := range dataKey {
		dataKey[i], headerKey1[i], headerKey2[i] = byte(i), byte(i+32), byte(i+64)
	}
	cipher, err := NewDataCipher(dataKey, headerKey1, headerKey2)
	if err != nil {
		t.Fatal(err)
	}
	header := ShortHeader{DestinationID: 42, PacketNumber: 7, Type: Data}
	plaintext := []byte{0, 0, 4, 0, 0, 0, 1, 254}
	packet := make([]byte, ShortHeaderLen+len(plaintext)+PacketTagLen)
	sealed, err := cipher.SealDataTo(packet, header, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plaintext))
	parsed, opened, err := cipher.OpenDataTo(out, sealed)
	if err != nil || parsed != header || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenDataTo() = %#v, %x, %v", parsed, opened, err)
	}
}

func TestDataCipherConcurrentPacketNumbers(t *testing.T) {
	cipher, err := NewDataCipher(make([]byte, 32), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte{0, 0, 4, 0, 0, 0, 1, 254}
	var workers sync.WaitGroup
	for packetNumber := uint32(1); packetNumber <= 64; packetNumber++ {
		workers.Add(1)
		go func(packetNumber uint32) {
			defer workers.Done()
			header := ShortHeader{DestinationID: 42, PacketNumber: packetNumber, Type: Data}
			packet := make([]byte, ShortHeaderLen+len(plaintext)+PacketTagLen)
			sealed, err := cipher.SealDataTo(packet, header, plaintext)
			if err != nil {
				t.Error(err)
				return
			}
			openedHeader, opened, err := cipher.OpenDataTo(make([]byte, len(plaintext)), sealed)
			if err != nil || openedHeader != header || !bytes.Equal(opened, plaintext) {
				t.Errorf("packet %d = %#v, %x, %v", packetNumber, openedHeader, opened, err)
			}
		}(packetNumber)
	}
	workers.Wait()
}

func TestDataCipherRejectsPacketBounds(t *testing.T) {
	cipher, err := NewDataCipher(make([]byte, 32), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.SealDataTo(make([]byte, 40), ShortHeader{Type: Data}, make([]byte, 7)); !errors.Is(err, ErrPacketLength) {
		t.Fatalf("short plaintext = %v", err)
	}
	if _, _, err := cipher.OpenDataTo(nil, make([]byte, MinPacketLen-1)); !errors.Is(err, ErrPacketLength) {
		t.Fatalf("short packet = %v", err)
	}
}

func TestDataCipherReleaseZeroizesAndRejectsUse(t *testing.T) {
	cipher, err := NewDataCipher(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead := cipher.aead
	cipher.ReleaseSensitive()
	cipher.ReleaseSensitive()
	if cipher.headerKey1 != [32]byte{} || cipher.headerKey2 != [32]byte{} || cipher.nonce != [12]byte{} || !cipher.released {
		t.Fatal("released data cipher retained key state")
	}
	if aead == nil {
		t.Fatal("released data cipher lost its child reference")
	}
	if _, err := aead.SealTo(make([]byte, cryptography.ChaChaTagSize), make([]byte, cryptography.ChaChaNonceSize), nil, nil); !errors.Is(err, cryptography.ErrSensitiveReleased) {
		t.Fatalf("released data cipher AEAD remained usable: %v", err)
	}
	if _, err := cipher.SealDataTo(make([]byte, MinPacketLen), ShortHeader{Type: Data}, make([]byte, 8)); !errors.Is(err, cryptography.ErrSensitiveReleased) {
		t.Fatalf("SealDataTo after release = %v", err)
	}
}

func BenchmarkSealDataTo(b *testing.B) {
	cipher, err := NewDataCipher(make([]byte, 32), make([]byte, 32), make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, 1024)
	packet := make([]byte, ShortHeaderLen+len(plaintext)+PacketTagLen)
	header := ShortHeader{DestinationID: 1, Type: Data}
	b.ReportAllocs()
	for b.Loop() {
		header.PacketNumber++
		if _, err := cipher.SealDataTo(packet, header, plaintext); err != nil {
			b.Fatal(err)
		}
	}
}
