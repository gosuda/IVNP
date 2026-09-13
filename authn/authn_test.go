package authn_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"gosuda.org/ivnp/authn"
	"gosuda.org/ivnp/overlay"
)

func TestCredentialRealmBuilders(t *testing.T) {
	realm := authn.NewCredentialRealmProfile("enterprise", "fast-fabric")
	if realm.Admission != authn.AdmissionCredential {
		t.Fatalf("expected AdmissionCredential, got %v", realm.Admission)
	}
	if realm.IncludeNative {
		t.Fatal("expected IncludeNative false")
	}
	if len(realm.Fabrics) != 1 || realm.Fabrics[0] != "fast-fabric" {
		t.Fatalf("unexpected fabrics: %v", realm.Fabrics)
	}

	alias := authn.NewCredentialRealm("enterprise", "fast-fabric")
	if alias.ID != realm.ID || alias.Admission != realm.Admission {
		t.Fatalf("alias mismatch: got %+v, want %+v", alias, realm)
	}
}

func TestStaticTrustProvider(t *testing.T) {
	state := authn.TrustState{
		Generation:     42,
		Issuers:        []string{"RootCA"},
		MaxActiveSlots: 10,
		NotAfter:       time.Now().Add(time.Hour).Unix(),
	}
	provider := authn.StaticTrust(state)

	ctx := context.Background()
	realmID := overlay.RealmIDFor("enterprise")
	got, err := provider.Trust(ctx, realmID)
	if err != nil {
		t.Fatalf("Trust failed: %v", err)
	}
	if got.Generation != 42 || len(got.Issuers) != 1 || got.Issuers[0] != "RootCA" {
		t.Fatalf("unexpected trust state: %+v", got)
	}

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := provider.Trust(canceledCtx, realmID); err == nil {
		t.Fatal("expected error on canceled context")
	}
}

func TestX509Verifier(t *testing.T) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "IVNP Test Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "node-1.enterprise",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	verifier := authn.NewX509Verifier(authn.X509VerifierConfig{
		Roots:          roots,
		ExpectedIssuer: "IVNP Test Root CA",
	})

	ctx := context.Background()
	realmID := overlay.RealmIDFor("enterprise")

	// 1. Verify DER bytes
	proof, err := verifier.VerifyCredential(ctx, realmID, leafBytes)
	if err != nil {
		t.Fatalf("VerifyCredential(DER) failed: %v", err)
	}
	if proof.Realm != realmID {
		t.Fatalf("expected realm %v, got %v", realmID, proof.Realm)
	}
	if proof.ChannelKey != [32]byte(leafPub) {
		t.Fatal("channel key does not match leaf public key")
	}
	if proof.Issuer != "IVNP Test Root CA" {
		t.Fatalf("unexpected issuer: %q", proof.Issuer)
	}

	// 2. Verify PEM encoded bytes
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafBytes,
	})
	pemProof, err := verifier.VerifyCredential(ctx, realmID, pemBytes)
	if err != nil {
		t.Fatalf("VerifyCredential(PEM) failed: %v", err)
	}
	if pemProof.ChannelKey != proof.ChannelKey {
		t.Fatal("PEM channel key mismatch")
	}

	// 3. Untrusted CA cert
	otherRoots := x509.NewCertPool()
	untrustedVerifier := authn.NewX509Verifier(authn.X509VerifierConfig{
		Roots: otherRoots,
	})
	if _, err := untrustedVerifier.VerifyCredential(ctx, realmID, leafBytes); err == nil {
		t.Fatal("expected error for untrusted CA")
	}

	// 4. Unexpected issuer
	badIssuerVerifier := authn.NewX509Verifier(authn.X509VerifierConfig{
		Roots:          roots,
		ExpectedIssuer: "Different Issuer",
	})
	if _, err := badIssuerVerifier.VerifyCredential(ctx, realmID, leafBytes); err == nil {
		t.Fatal("expected error for mismatched issuer")
	}

	// 5. Empty / corrupt bytes
	if _, err := verifier.VerifyCredential(ctx, realmID, nil); err == nil {
		t.Fatal("expected error for nil credential")
	}
	if _, err := verifier.VerifyCredential(ctx, realmID, []byte("garbage")); err == nil {
		t.Fatal("expected error for corrupt credential")
	}

	// 6. Canceled context
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := verifier.VerifyCredential(canceledCtx, realmID, leafBytes); err == nil {
		t.Fatal("expected error on canceled context")
	}
}

// Configured KeyUsages constrain the accepted extended key usages; the
// empty set accepts any usage (membership credentials are not TLS server
// certificates).
func TestX509VerifierKeyUsages(t *testing.T) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "IVNP Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "node-1.enterprise"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, leafPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	realmID := overlay.RealmIDFor("enterprise")

	anyVerifier := authn.NewX509Verifier(authn.X509VerifierConfig{Roots: roots})
	if _, err := anyVerifier.VerifyCredential(ctx, realmID, leafBytes); err != nil {
		t.Fatalf("empty KeyUsages rejected a client-auth credential: %v", err)
	}

	clientVerifier := authn.NewX509Verifier(authn.X509VerifierConfig{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if _, err := clientVerifier.VerifyCredential(ctx, realmID, leafBytes); err != nil {
		t.Fatalf("matching KeyUsages rejected the credential: %v", err)
	}

	serverVerifier := authn.NewX509Verifier(authn.X509VerifierConfig{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if _, err := serverVerifier.VerifyCredential(ctx, realmID, leafBytes); err == nil {
		t.Fatal("server-auth KeyUsages accepted a client-auth credential")
	}
}
