package overlay

import (
	"context"
	"crypto/sha256"
	"time"
)

// Credential admission. Registration of the identity/trust/secret/verifier
// providers is only the configuration gate; this file is the runtime path that
// actually verifies membership evidence before an admitted channel exists. For
// psk modes the carrier's setup proof over the leased epoch key is the
// admission; for credential modes the peer's presented document is verified by
// the CredentialVerifier and the resulting claims are validated against the
// trust snapshot. Fail-closed: stale trust, expired credentials, revocation,
// issuer constraints, missing evidence, and unverifiable documents all deny.

// admissionMaterial assembles the verified local admission material for one
// dial. The returned release function must run only after every setup attempt
// that received the material has finished; it is never nil.
func (r *Realm) admissionMaterial(ctx context.Context) (req *AdmissionRequest, trust *TrustState, release func(), err error) {
	mode := r.admissionMode()
	release = func() {}
	if mode == AdmissionOpen {
		return nil, nil, release, nil
	}
	req = &AdmissionRequest{Realm: r.realmID()}
	var lease SecretLease
	release = func() {
		if lease != nil {
			_ = lease.Release()
		}
	}
	if mode == AdmissionPSK || mode == AdmissionCredentialPSK {
		secrets := r.host.secretProvider()
		if secrets == nil {
			return nil, nil, release, CodeUnsupportedCapability.Wrap("psk admission requires a secret provider")
		}
		lease, err = secrets.Lease(ctx, req.Realm, KeyPurposeNetworkAdmission)
		if err != nil {
			release()
			return nil, nil, func() {}, err
		}
		req.NetworkKey = lease.Key()
		req.Epoch = lease.Epoch()
	}
	if mode == AdmissionCredential || mode == AdmissionCredentialPSK {
		identity := r.host.identityProvider()
		trustProvider := r.host.trustProvider()
		if identity == nil || trustProvider == nil {
			release()
			return nil, nil, func() {}, CodeUnsupportedCapability.Wrap("credential admission requires identity and trust providers")
		}
		proof, signer, err := identity.LocalIdentity(ctx, req.Realm)
		if err != nil {
			release()
			return nil, nil, func() {}, err
		}
		state, err := trustProvider.Trust(ctx, req.Realm)
		if err != nil {
			release()
			return nil, nil, func() {}, err
		}
		if err := r.validateMembership(proof, req.Realm, proof.ChannelKey, &state); err != nil {
			release()
			return nil, nil, func() {}, err
		}
		req.Credential = &proof
		req.Signer = signer
		trust = &state
	}
	return req, trust, release, nil
}

// verifyPeerMembership gates an authenticated channel before an AdmittedPeer
// exists. For credential modes the channel must carry MembershipChannel
// evidence: the presented document is verified by the registered
// CredentialVerifier and the resulting claims — never the fields the peer
// asserted — are validated against the realm and the trust snapshot. When the
// resolved candidate advertised a credential digest, the presented document
// must hash to it. A nil trust fetches a fresh snapshot (inbound path); a
// supplied snapshot is reused across the dial's bounded setup attempts.
func (r *Realm) verifyPeerMembership(ctx context.Context, channel Channel, scope ChannelScope, key [32]byte, trust *TrustState, credDigest *[32]byte) error {
	mode := r.admissionMode()
	switch mode {
	case AdmissionCredential, AdmissionCredentialPSK:
		mc, ok := channel.(MembershipChannel)
		if !ok {
			return CodeMembershipDenied.Wrap("carrier exchanged no credential evidence")
		}
		proof, ok := mc.PeerMembership()
		if !ok || len(proof.Credential) == 0 {
			return CodeMembershipDenied.Wrap("peer presented no credential evidence")
		}
		if credDigest != nil && sha256.Sum256(proof.Credential) != *credDigest {
			return CodeMembershipDenied.Wrap("credential does not match the advertised digest")
		}
		verifier := r.host.credentialVerifier()
		if verifier == nil {
			return CodeUnsupportedCapability.Wrap("credential admission requires a credential verifier")
		}
		verified, err := verifier.VerifyCredential(ctx, scope.Realm, proof.Credential)
		if err != nil {
			return CodeMembershipDenied.WrapCause("credential verification failed", err)
		}
		if trust == nil {
			provider := r.host.trustProvider()
			if provider == nil {
				return CodeTrustStale.Wrap("credential admission has no trust provider")
			}
			state, err := provider.Trust(ctx, scope.Realm)
			if err != nil {
				return err
			}
			trust = &state
		}
		if err := r.validateMembership(verified, scope.Realm, key, trust); err != nil {
			return err
		}
		if err := r.authorizePeer(ctx, PeerRef{Realm: scope.Realm, Member: verified.Member, HasMember: true}); err != nil {
			return err
		}
	default:
		// open and psk modes: the channel's own authenticated setup is the
		// admission evidence; the authorization point still applies when
		// configured, keyed by the self-certifying proven key.
		if err := r.authorizePeer(ctx, PeerRef{Realm: scope.Realm, Member: MemberID(key), HasMember: true}); err != nil {
			return err
		}
	}
	return nil
}

// validateMembership applies the membership gate to verified claims: realm
// match, channel-key binding, credential expiry, issuer allow-list,
// revocation, and slot bounds under a fresh-enough trust snapshot. An empty
// issuer list admits nothing.
func (r *Realm) validateMembership(proof IdentityProof, realm RealmID, channelKey [32]byte, trust *TrustState) error {
	now := time.Now().Unix()
	if proof.Realm != realm {
		return CodeRealmMismatch.Wrap("credential names a different realm")
	}
	if proof.ChannelKey != channelKey {
		return CodeMembershipDenied.Wrap("credential does not bind the proven channel key")
	}
	if proof.NotAfter != 0 && proof.NotAfter <= now {
		return CodeCredentialExpired.Wrap("credential expired")
	}
	if trust != nil {
		if trust.NotAfter != 0 && trust.NotAfter <= now {
			return CodeTrustStale.Wrap("trust snapshot is stale")
		}
		if len(trust.Issuers) == 0 || !containsString(trust.Issuers, proof.Issuer) {
			return CodeMembershipDenied.Wrap("issuer not in the trust bundle")
		}
		for _, revoked := range trust.Revoked {
			if revoked == proof.Member {
				return CodeMembershipDenied.Wrap("member is revoked")
			}
		}
		if trust.MaxActiveSlots > 0 && proof.Slot >= uint64(trust.MaxActiveSlots) {
			return CodeMembershipDenied.Wrap("credential slot exceeds the issuer bound")
		}
	}
	return nil
}

// authorizePeer invokes the optional policy decision point; it can only deny.
func (r *Realm) authorizePeer(ctx context.Context, peer PeerRef) error {
	provider := r.host.authorizeProvider()
	if provider == nil {
		return nil
	}
	allowed, err := provider.Authorize(ctx, peer, "connect")
	if err != nil {
		return err
	}
	if !allowed {
		return CodeMembershipDenied.Wrap("authorization denied the peer")
	}
	return nil
}

// trustSnapshot fetches the current membership snapshot for this realm.
func (r *Realm) trustSnapshot(ctx context.Context) (*TrustState, error) {
	provider := r.host.trustProvider()
	if provider == nil {
		return nil, CodeUnsupportedCapability.Wrap("no trust provider")
	}
	state, err := provider.Trust(ctx, r.realmID())
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
