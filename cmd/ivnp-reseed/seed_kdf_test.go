package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

const (
	legacyGoldenPhrase = "ivnp reseed legacy golden phrase"
	// legacyGoldenFingerprint is the SHA-256 of the PKIX public key that the
	// original HKDF-SHA512 derivation produced for legacyGoldenPhrase. Existing
	// operators' published certificates depend on it never changing.
	legacyGoldenFingerprint = "ff3144805cb722a96552a8d73da92c9f25e4f875ccac7bd529903ce8b13f733b"
	argon2idTestPhrase      = "Zq3v8Lr1-tW6nB0x-Yp5cK2m-Hs7dF4j-Ae9u"
)

func publicKeyFingerprint(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func TestLegacySeedKDFStaysDefaultAndStable(t *testing.T) {
	kdf, err := parseSeedKDF("")
	if err != nil || kdf != seedKDFHKDF {
		t.Fatalf("parseSeedKDF(\"\") = %q, %v; want the legacy %q default", kdf, err, seedKDFHKDF)
	}
	for _, signerID := range []string{"reseed@ivnp.network", "other@example.org"} {
		key, err := deriveSigningKey(legacyGoldenPhrase, seedKDFHKDF, signerID)
		if err != nil {
			t.Fatal(err)
		}
		if got := publicKeyFingerprint(t, key); got != legacyGoldenFingerprint {
			t.Fatalf("legacy derivation for signer %q changed: fingerprint %s, want %s", signerID, got, legacyGoldenFingerprint)
		}
	}
}

func TestArgon2idSeedKDFBindsSignerID(t *testing.T) {
	a, err := deriveSigningKey(argon2idTestPhrase, seedKDFArgon2id, "reseed@a.example")
	if err != nil {
		t.Fatal(err)
	}
	again, err := deriveSigningKey(argon2idTestPhrase, seedKDFArgon2id, "reseed@a.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveSigningKey(argon2idTestPhrase, seedKDFArgon2id, "reseed@b.example")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := deriveSigningKey(argon2idTestPhrase, seedKDFHKDF, "reseed@a.example")
	if err != nil {
		t.Fatal(err)
	}
	if a.N.Cmp(again.N) != 0 {
		t.Fatal("argon2id derivation is not deterministic")
	}
	if a.N.Cmp(b.N) == 0 {
		t.Fatal("argon2id derivation ignores the signer ID salt")
	}
	if a.N.Cmp(legacy.N) == 0 {
		t.Fatal("argon2id derivation matches the legacy derivation")
	}
}

func TestArgon2idSeedKDFRejectsShortPhrase(t *testing.T) {
	short := strings.Repeat("x", minArgon2idSeedPhraseLen-1)
	if _, err := deriveSigningKey(short, seedKDFArgon2id, "reseed@a.example"); !errors.Is(err, errSeedPhraseTooShort) {
		t.Fatalf("deriveSigningKey(short) error = %v, want %v", err, errSeedPhraseTooShort)
	}
}

func TestParseSeedKDFRejectsUnknown(t *testing.T) {
	if _, err := parseSeedKDF("pbkdf2"); err == nil {
		t.Fatal("parseSeedKDF accepted an unknown KDF")
	}
	for _, name := range []string{"hkdf-sha512", "argon2id-v2"} {
		if _, err := parseSeedKDF(name); err != nil {
			t.Fatalf("parseSeedKDF(%q): %v", name, err)
		}
	}
}

func TestRunRejectsUnknownSeedKDF(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-seed-kdf", "pbkdf2", "-once", "-no-router", "-data-dir", t.TempDir()}, &stdout, &stderr); code != 2 {
		t.Fatalf("run exit = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown seed KDF") {
		t.Fatalf("stderr does not report the unknown KDF: %s", stderr.String())
	}
}

func TestLegacySeedKDFWarnsAboutMigration(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := initSigningKey("short legacy phrase", seedKDFHKDF, "reseed@a.example", logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), string(seedKDFArgon2id)) {
		t.Fatalf("legacy KDF use logged no migration hint: %s", logs.String())
	}
	if strings.Contains(logs.String(), "short legacy phrase") {
		t.Fatal("log output contains the seed phrase")
	}
	if _, err := initSigningKey("", seedKDFArgon2id, "reseed@a.example", slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("ephemeral key with argon2id selected: %v", err)
	}
}
