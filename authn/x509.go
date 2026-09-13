package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"gosuda.org/ivnp/overlay"
)

var (
	// ErrInvalidCertificate indicates that the credential bytes could not be parsed as an X.509 certificate.
	ErrInvalidCertificate = errors.New("authn: invalid x509 certificate")

	// ErrUnsupportedKey indicates that the certificate's public key is not an Ed25519 key.
	ErrUnsupportedKey = errors.New("authn: unsupported public key algorithm, expected ed25519")

	// ErrUnexpectedIssuer indicates that the certificate issuer did not match the expected issuer constraint.
	ErrUnexpectedIssuer = errors.New("authn: unexpected certificate issuer")
)

// X509VerifierConfig configures an X.509 certificate credential verifier.
type X509VerifierConfig struct {
	Roots          *x509.CertPool
	ExpectedIssuer string
	// KeyUsages lists the extended key usages the certificate chain must
	// satisfy; the certificate needs any one of them. Empty defaults to
	// ExtKeyUsageAny: membership credentials are not TLS server
	// certificates, so Go's implicit ServerAuth default would reject a
	// client-auth-only member certificate. Callers may tighten the set —
	// e.g. ExtKeyUsageClientAuth — or wrap the verifier to enforce custom
	// EKU OIDs the standard library cannot express.
	KeyUsages   []x509.ExtKeyUsage
	CurrentTime func() time.Time
}

// X509Verifier implements CredentialVerifier for X.509 certificates carrying Ed25519 public keys.
type X509Verifier struct {
	cfg X509VerifierConfig
}

var _ CredentialVerifier = (*X509Verifier)(nil)

// NewX509Verifier creates a new X.509 credential verifier.
func NewX509Verifier(cfg X509VerifierConfig) *X509Verifier {
	return &X509Verifier{cfg: cfg}
}

// VerifyCredential parses and validates an X.509 certificate (DER or PEM encoded),
// ensures it is signed by trusted roots, and extracts its Ed25519 public key as the ChannelKey.
func (v *X509Verifier) VerifyCredential(ctx context.Context, realm overlay.RealmID, credential []byte) (IdentityProof, error) {
	if err := ctx.Err(); err != nil {
		return IdentityProof{}, err
	}
	if len(credential) == 0 {
		return IdentityProof{}, ErrInvalidCertificate
	}

	der := credential
	if block, _ := pem.Decode(credential); block != nil && block.Type == "CERTIFICATE" {
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IdentityProof{}, errors.Join(ErrInvalidCertificate, err)
	}

	opts := x509.VerifyOptions{
		Roots:     v.cfg.Roots,
		KeyUsages: v.cfg.KeyUsages,
	}
	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if v.cfg.CurrentTime != nil {
		opts.CurrentTime = v.cfg.CurrentTime()
	}
	if _, err := cert.Verify(opts); err != nil {
		return IdentityProof{}, err
	}

	if v.cfg.ExpectedIssuer != "" && cert.Issuer.CommonName != v.cfg.ExpectedIssuer {
		return IdentityProof{}, ErrUnexpectedIssuer
	}

	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != 32 {
		return IdentityProof{}, ErrUnsupportedKey
	}

	var proof IdentityProof
	proof.Realm = realm
	copy(proof.ChannelKey[:], pub)
	proof.Issuer = cert.Issuer.CommonName
	proof.NotAfter = cert.NotAfter.Unix()
	proof.Credential = credential
	return proof, nil
}
