package verifier

import "time"

const DefaultClockSkewTolerance time.Duration = 0

type Verifier struct {
	signatureVerifier  SignatureVerifier
	clockSkewTolerance time.Duration
}

type VerifierOption func(*Verifier)

func WithClockSkewTolerance(tolerance time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.clockSkewTolerance = tolerance
	}
}

func NewVerifier(signatureVerifier SignatureVerifier, options ...VerifierOption) *Verifier {
	v := &Verifier{
		signatureVerifier:  signatureVerifier,
		clockSkewTolerance: DefaultClockSkewTolerance,
	}
	for _, option := range options {
		option(v)
	}
	return v
}

func (v *Verifier) Verify(intent ActionIntent, pccb PCCB, context VerificationContext) (VerifiedProtectedRequest, error) {
	normalizedIntent, err := normalizeActionIntent(intent)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	normalizedPCCB, err := normalizePCCB(pccb)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	normalizedContext, err := normalizeVerificationContext(context)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}

	notBefore, err := parseTimestamp(normalizedPCCB.NotBefore, "pccb.not_before", ErrInvalidPCCB)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	expiresAt, err := parseTimestamp(normalizedPCCB.ExpiresAt, "pccb.expires_at", ErrInvalidPCCB)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	if v.clockSkewTolerance < 0 {
		return VerifiedProtectedRequest{}, newVerificationError(ErrInvalidContext, "clock skew tolerance must be non-negative.", nil)
	}

	// ── Signature verification (before any semantic check) ───────────
	// Security principle: verify cryptographic integrity BEFORE interpreting
	// semantic fields, including the validity window. Any mutation to the
	// signed PCCB payload must produce SIGNATURE_INVALID, never a semantic
	// refusal that tells a forger which check it would fail. The order of
	// every check below matches the Python reference verifier
	// (PCCBVerifier.verify steps 4-11).
	unsignedPayload, err := canonicalizeBytes(normalizedUnsignedPCCBPayload(normalizedPCCB))
	if err != nil {
		return VerifiedProtectedRequest{}, newVerificationError(
			ErrInvalidPCCB,
			"The proof cannot be canonicalized for signature verification.",
			nil,
		)
	}
	if v.signatureVerifier == nil || !v.signatureVerifier.Verify(unsignedPayload, normalizedPCCB.Signature) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrSignatureInvalid, "The proof signature could not be verified.", nil)
	}

	// ── Semantic checks (after signature is verified) ────────────────
	if normalizedContext.Now.Add(v.clockSkewTolerance).Before(notBefore) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrProofNotYetValid, "The proof is not yet valid.", nil)
	}
	if normalizedContext.Now.Add(-v.clockSkewTolerance).After(expiresAt) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrProofExpired, "The proof has expired.", nil)
	}
	if !normalizedEqual(normalizedPCCB.Audience, normalizedContext.Audience) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrAudienceMismatch, "The proof audience does not match this endpoint.", nil)
	}
	if !normalizedEqual(normalizedPCCB.Target, normalizedIntent.Target) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrTargetMismatch, "The proof target does not exactly match the action intent.", nil)
	}
	// Protocol v1 proofs are exact and single-use only (protocol/13 E4).
	if normalizedPCCB.Scope.Mode != "exact" || !normalizedPCCB.Scope.SingleUse {
		return VerifiedProtectedRequest{}, newVerificationError(ErrScopeModeInvalid, "The proof scope mode is not supported.", nil)
	}
	if !containsString(normalizedPCCB.Scope.Capabilities, normalizedIntent.Action.Capability) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrScopeCapabilityMismatch, "The proof scope does not allow this capability.", nil)
	}
	// E1: the capability must be one this endpoint declares it performs.
	if !containsString(normalizedContext.ScopeCapabilities, normalizedIntent.Action.Capability) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrScopeCapabilityMismatch, "The action capability is not one this endpoint performs.", nil)
	}
	if normalizedPCCB.IntentID != "" && normalizedPCCB.IntentID != normalizedIntent.IntentID {
		return VerifiedProtectedRequest{}, newVerificationError(ErrIntentMismatch, "The proof does not match the supplied action intent.", nil)
	}
	if !normalizedEqual(normalizedPCCB.Tenant, normalizedIntent.Tenant) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrTenantMismatch, "The proof tenant does not match the action intent.", nil)
	}
	if !normalizedEqual(normalizedPCCB.Subject, normalizedIntent.Requester) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrSubjectMismatch, "The proof subject does not match the action intent.", nil)
	}
	if !normalizedEqual(normalizedPCCB.Action, normalizedIntent.Action) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrActionMismatch, "The proof action does not exactly match the action intent.", nil)
	}
	if normalizedPCCB.ActionHash.Algorithm != "sha-256" || !IsAcceptedCanonicalization(normalizedPCCB.ActionHash.Canonicalization) {
		return VerifiedProtectedRequest{}, newVerificationError(ErrActionHashAlgorithmInvalid, "The proof action hash metadata is invalid.", nil)
	}

	expectedHash, err := sha256Hex(normalizedIntentActionHashInput(normalizedIntent))
	if err != nil {
		return VerifiedProtectedRequest{}, newVerificationError(
			ErrInvalidIntent,
			"The action intent cannot be canonicalized for verification.",
			nil,
		)
	}
	if normalizedPCCB.ActionHash.Value != expectedHash {
		return VerifiedProtectedRequest{}, newVerificationError(ErrActionHashMismatch, "The proof action hash does not match the action intent.", nil)
	}
	// E2: every constraint the endpoint relies on was signed into the proof.
	for key, value := range normalizedContext.ParameterConstraints {
		signed, ok := normalizedPCCB.Scope.ParameterConstraints[key]
		if !ok || !canonicalValueEqual(signed, value) {
			return VerifiedProtectedRequest{}, newVerificationError(ErrParameterMismatch, "The proof parameter constraints do not cover this endpoint's constraints.", nil)
		}
	}
	// E3: the signed target satisfies at least one declared resource selector.
	if len(normalizedContext.ResourceSelectors) > 0 {
		satisfied := false
		for _, selector := range normalizedContext.ResourceSelectors {
			if targetSatisfies(normalizedPCCB.Target, selector) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			return VerifiedProtectedRequest{}, newVerificationError(ErrTargetMismatch, "The proof target does not satisfy this endpoint's resource selectors.", nil)
		}
	}

	return VerifiedProtectedRequest{
		Intent:  normalizedIntent,
		PCCB:    normalizedPCCB,
		Context: normalizedContext,
	}, nil
}

func (v *Verifier) VerifyJSON(intentRaw []byte, pccbRaw []byte, context VerificationContext) (VerifiedProtectedRequest, error) {
	intent, err := ParseActionIntentJSON(intentRaw)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	pccb, err := ParsePCCBJSON(pccbRaw)
	if err != nil {
		return VerifiedProtectedRequest{}, err
	}
	return v.Verify(intent, pccb, context)
}

func canonicalValueEqual(left any, right any) bool {
	leftBytes, err := canonicalizeBytes(left)
	if err != nil {
		return false
	}
	rightBytes, err := canonicalizeBytes(right)
	if err != nil {
		return false
	}
	return string(leftBytes) == string(rightBytes)
}

// targetSatisfies implements protocol/13-edge-binding.md E3.
func targetSatisfies(target TargetRef, selector map[string]any) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		var actual any
		switch key {
		case "resource_id":
			actual = target.ResourceID
		case "resource_type":
			actual = target.ResourceType
		default:
			found, ok := target.Selectors[key]
			if !ok {
				return false
			}
			actual = found
		}
		if !canonicalValueEqual(actual, value) {
			return false
		}
	}
	return true
}
