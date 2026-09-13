// Package authn provides authentication, identity, and credential verification
// extensions for IVNP overlay networks.
//
// By separating enterprise PKI and issuer-based credentials from the core overlay
// facade, IVNP keeps its primary API focused on lightweight cryptographic key
// identity and PSK admission while enabling advanced certificate and token
// verification workflows when required.
package authn

import (
	"context"

	"gosuda.org/ivnp/overlay"
)

type (
	// CredentialVerifier authenticates an issuer-signed membership document and
	// returns the claims it attests.
	CredentialVerifier = overlay.CredentialVerifier

	// IdentityProvider supplies the local workload/device credential and signing handle.
	IdentityProvider = overlay.IdentityProvider

	// TrustProvider supplies issuer constraints, revocation, and limits.
	TrustProvider = overlay.TrustProvider

	// TrustState is a versioned trust snapshot.
	TrustState = overlay.TrustState

	// IdentityProof is provider-supplied membership evidence.
	IdentityProof = overlay.IdentityProof

	// Signer is a non-exportable signing handle over a bound key.
	Signer = overlay.Signer

	// MemberID identifies a distinct member identity.
	MemberID = overlay.MemberID
)

const (
	// AdmissionCredential requires presented issuer-signed credentials for admission.
	AdmissionCredential = overlay.AdmissionCredential

	// AdmissionCredentialPSK requires both a PSK and presented credentials.
	AdmissionCredentialPSK = overlay.AdmissionCredentialPSK
)

// NewCredentialRealmProfile returns a realm profile configured for certificate / credential
// based admission with high-speed direct transport.
func NewCredentialRealmProfile(name string, fabrics ...string) *overlay.RealmProfile {
	return &overlay.RealmProfile{
		ID:            overlay.RealmIDFor(name),
		Admission:     AdmissionCredential,
		Discovery:     overlay.DiscoveryLocalOnly,
		Privacy:       overlay.PrivacyPrivateConfined,
		Routing:       overlay.RoutingOverlayDirect,
		Publication:   overlay.PublicationNone,
		Fabrics:       append([]string(nil), fabrics...),
		IncludeNative: false,
	}
}

// NewCredentialRealm is an alias for NewCredentialRealmProfile.
func NewCredentialRealm(name string, fabrics ...string) *overlay.RealmProfile {
	return NewCredentialRealmProfile(name, fabrics...)
}

// staticTrustProvider implements overlay.TrustProvider returning a constant trust state.
type staticTrustProvider struct {
	state TrustState
}

// StaticTrust returns a TrustProvider backed by the given fixed trust state.
func StaticTrust(state TrustState) TrustProvider {
	return &staticTrustProvider{state: state}
}

func (p *staticTrustProvider) Trust(ctx context.Context, realm overlay.RealmID) (TrustState, error) {
	if err := ctx.Err(); err != nil {
		return TrustState{}, err
	}
	return p.state, nil
}
