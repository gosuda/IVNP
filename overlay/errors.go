package overlay

// Code is a stable management error identifier. Codes are part of the API
// contract; callers match them with errors.Is.
type Code string

func (c Code) Error() string { return "overlay: " + string(c) }

// Wrap annotates a code with operation context.
func (c Code) Wrap(msg string) error { return &Error{Code: c, Message: msg} }

// WrapCause annotates a code with context and an underlying cause.
func (c Code) WrapCause(msg string, cause error) error {
	return &Error{Code: c, Message: msg, Err: cause}
}

// Error carries a stable Code plus context. It never exposes secret material,
// decrypted private routes, or another tenant's identifiers.
type Error struct {
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code.Error() + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Code.Error() + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches a bare Code sentinel so errors.Is(err, overlay.CodeX) works.
func (e *Error) Is(target error) bool {
	code, ok := target.(Code)
	return ok && e.Code == code
}

const (
	CodeUnsupportedCapability      Code = "unsupported_capability"
	CodeInvalidConfig              Code = "invalid_config"
	CodeIdentityMismatch           Code = "identity_mismatch"
	CodeRealmMismatch              Code = "realm_mismatch"
	CodeMembershipDenied           Code = "membership_denied"
	CodeCredentialExpired          Code = "credential_expired"
	CodeTrustStale                 Code = "trust_stale"
	CodePublicUnavailable          Code = "public_unavailable"
	CodeLookupBudgetExceeded       Code = "lookup_budget_exceeded"
	CodeRecordTooLarge             Code = "record_too_large"
	CodeRecordStale                Code = "record_stale"
	CodeEquivocation               Code = "equivocation"
	CodeInsufficientDiversity      Code = "insufficient_diversity"
	CodePrivacyPolicyConflict      Code = "privacy_policy_conflict"
	CodePublicationNotFresh        Code = "publication_not_fresh"
	CodeRevisionConflict           Code = "revision_conflict"
	CodeRateLimited                Code = "rate_limited"
	CodeClosed                     Code = "closed"
	CodeFabricMismatch             Code = "fabric_mismatch"
	CodeNetworkIDConflict          Code = "network_id_conflict"
	CodeContextScopeMismatch       Code = "context_scope_mismatch"
	CodeLookupCapabilityRequired   Code = "lookup_capability_required"
	CodeEndpointBindingInvalid     Code = "endpoint_binding_invalid"
	CodeMinimumSecurityUnsatisfied Code = "minimum_security_unsatisfied"
	CodeFallbackNotReady           Code = "fallback_not_ready"
	CodeReconnectRequired          Code = "reconnect_required"
	CodeDeliveryUncertain          Code = "delivery_uncertain"
	CodeResumeNotSupported         Code = "resume_not_supported"
	CodeResumeStateMismatch        Code = "resume_state_mismatch"
	CodeUnreachable                Code = "unreachable"
	CodeUnknownDispatchProfile     Code = "unknown_dispatch_profile"
)
