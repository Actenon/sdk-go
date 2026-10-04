package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func provenanceFixtures(t *testing.T) (ActionIntent, PCCB) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test path")
	}
	dir := filepath.Join(filepath.Dir(filename), "..", "fixtures", "portable-local-proof")
	intentRaw, err := os.ReadFile(filepath.Join(dir, "action_intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	pccbRaw, err := os.ReadFile(filepath.Join(dir, "pccb.json"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ParseActionIntentJSON(intentRaw)
	if err != nil {
		t.Fatal(err)
	}
	pccb, err := ParsePCCBJSON(pccbRaw)
	if err != nil {
		t.Fatal(err)
	}
	return intent, pccb
}

func provenanceContext(capabilities []string) VerificationContext {
	return VerificationContext{
		RequestID:         "req_go_conformance_001",
		Audience:          AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
		Now:               time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		ScopeCapabilities: capabilities,
	}
}

func resignLocal(pccb PCCB) (PCCB, error) {
	normalized, err := normalizePCCB(pccb)
	if err != nil {
		return PCCB{}, err
	}
	payload, err := canonicalizeBytes(normalizedUnsignedPCCBPayload(normalized))
	if err != nil {
		return PCCB{}, err
	}
	mac := hmac.New(sha256.New, []byte(LocalProofSecret))
	mac.Write(payload)
	normalized.Signature.Algorithm = "HS256"
	normalized.Signature.KeyID = LocalProofKeyID
	normalized.Signature.Encoding = "base64url"
	normalized.Signature.Value = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return normalized, nil
}

func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion != "1.2.0" {
		t.Fatalf("PROTOCOL_VERSION %s", ProtocolVersion)
	}
}

func TestMintRefusesEmptyOrWildcardScope(t *testing.T) {
	_, err := ScopeCapabilitiesForMint(nil)
	if err == nil || !strings.Contains(err.Error(), "empty allow-list") {
		t.Fatalf("expected empty allow-list refusal, got %v", err)
	}
	_, err = ScopeCapabilitiesForMint([]string{})
	if err == nil || !strings.Contains(err.Error(), "empty allow-list") {
		t.Fatalf("expected empty allow-list refusal, got %v", err)
	}
	for _, capability := range []string{"payment.*", "*", "payment.refund?", "file[s].write"} {
		_, err = ScopeCapabilitiesForMint([]string{capability})
		if err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("expected wildcard refusal for %q, got %v", capability, err)
		}
	}
	got, err := ScopeCapabilitiesForMint([]string{"payment.refund"})
	if err != nil || len(got) != 1 || got[0] != "payment.refund" {
		t.Fatalf("concrete capability: %v %v", got, err)
	}
	got, err = ScopeCapabilitiesForMint([]string{"filesystem.write", "airlock.http.post"})
	if err != nil || len(got) != 2 || got[0] != "filesystem.write" || got[1] != "airlock.http.post" {
		t.Fatalf("concrete set: %v %v", got, err)
	}
}

func TestVerificationEmptyAllowListDoesNotBecomeTheAttemptedAction(t *testing.T) {
	got, err := ScopeCapabilitiesForVerification(nil, "payment.refund")
	if err != nil || len(got) != 1 || got[0] != "payment.refund" {
		t.Fatalf("omitted allow-list: %v %v", got, err)
	}
	got, err = ScopeCapabilitiesForVerification([]string{}, "payment.refund")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty allow-list: %v %v", got, err)
	}
	if CapabilityInScope("payment.refund", nil) || CapabilityInScope("payment.refund", []string{}) {
		t.Fatal("empty declaration authorised a capability")
	}
	if CapabilityInScope("payment.refund", []string{"filesystem.write"}) {
		t.Fatal("unrelated capability matched")
	}
	if !CapabilityInScope("filesystem.write", []string{"filesystem.write"}) {
		t.Fatal("exact capability did not match")
	}
	if CapabilityInScope("payment.*", []string{"payment.*"}) {
		t.Fatal("a glob matched itself")
	}
	if CapabilityInScope("payment.refund", []string{"payment.refund", "payment.*"}) {
		t.Fatal("a glob in the set was expanded or ignored")
	}
	_, err = ScopeCapabilitiesForVerification([]string{"*"}, "payment.refund")
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard refusal, got %v", err)
	}
	_, err = ScopeCapabilitiesForVerification(nil, "payment.*")
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected intent wildcard refusal, got %v", err)
	}
}

func TestTokenLengthIsNotAcceptance(t *testing.T) {
	token := strings.Repeat("A", 32)
	if len(token) < 16 {
		t.Fatal("token fixture is too short")
	}
	if _, err := ParsePCCBJSON([]byte(token)); err == nil {
		t.Fatal("a long string was accepted as a PCCB")
	}
	prefixed := "v1." + token
	if _, err := ParsePCCBJSON([]byte(prefixed)); err == nil {
		t.Fatal("a v1. prefixed string was accepted as a PCCB")
	}
	code, refused := UnauthenticatedRefusal(false, false)
	if !refused || code != ErrIssuerUntrusted {
		t.Fatalf("no trust root: %s %v", code, refused)
	}
	code, refused = UnauthenticatedRefusal(true, false)
	if !refused || code != ErrSignatureInvalid {
		t.Fatalf("forged signature: %s %v", code, refused)
	}
	if _, refused = UnauthenticatedRefusal(true, true); refused {
		t.Fatal("verified signature was refused")
	}
}

func TestAuthorityExtensionRoundTrip(t *testing.T) {
	extensions, err := AuthorityExtensionObject("service:actenon-permit", "grant_9f3c1a175e9b4d80a1b2c3d4e5f60718", true)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthorityExtension(extensions)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Issuer != "service:actenon-permit" || parsed.GrantID != "grant_9f3c1a175e9b4d80a1b2c3d4e5f60718" || !parsed.Revocable {
		t.Fatalf("parsed %+v", parsed)
	}
	if _, err := ParseAuthorityExtension(map[string]any{}); err == nil || !strings.Contains(err.Error(), "no authority") {
		t.Fatalf("expected missing authority, got %v", err)
	}
	if _, err := AuthorityExtensionObject("", "grant", true); err == nil {
		t.Fatal("empty issuer was accepted")
	}
	if _, err := ParseAuthorityExtension(map[string]any{"authority": map[string]any{"issuer": "svc", "grant_id": "g", "revocable": "yes"}}); err == nil {
		t.Fatal("non-boolean revocable was accepted")
	}
}

func TestScopeCodesStayCanonical(t *testing.T) {
	for _, code := range []string{"SCOPE_CAPABILITY_MISMATCH", "SCOPE_MODE_INVALID"} {
		resolved, err := ResolveAlias(code)
		if err != nil || resolved != code {
			t.Fatalf("alias %s -> %s (%v)", code, resolved, err)
		}
		if resolved == "PARAMETER_MISMATCH" {
			t.Fatalf("%s collapsed to PARAMETER_MISMATCH", code)
		}
		if DisclosedCode(code) != "PROOF_INVALID" {
			t.Fatalf("public disclosure of %s is %s", code, DisclosedCode(code))
		}
		if _, ok := InternalCode(code, DisclosurePublic); ok {
			t.Fatalf("public internal code leaked %s", code)
		}
		internal, ok := InternalCode(code, DisclosureTrusted)
		if !ok || internal != code {
			t.Fatalf("trusted internal %s -> %s %v", code, internal, ok)
		}
		if RefusalRetryable(code) {
			t.Fatalf("%s is retryable", code)
		}
	}
	resolved, err := ResolveAlias("INTENT_MISMATCH")
	if err != nil || resolved != "PARAMETER_MISMATCH" {
		t.Fatalf("INTENT_MISMATCH alias: %s %v", resolved, err)
	}
	if DisclosedCode("ISSUER_UNTRUSTED") != "PROOF_INVALID" || DisclosedCode("SIGNATURE_INVALID") != "PROOF_INVALID" {
		t.Fatal("forged-proof codes were disclosed in detail")
	}
	if DisclosedCode("PROOF_EXPIRED") != "PROOF_EXPIRED" {
		t.Fatal("PROOF_EXPIRED was collapsed")
	}
}

func TestVerifierRefusesCapabilityOutsideTheEdgeAllowList(t *testing.T) {
	intent, pccb := provenanceFixtures(t)
	sdk := NewVerifier(BuildLocalProofVerifier())
	_, err := sdk.Verify(intent, pccb, provenanceContext([]string{"filesystem.write"}))
	if !IsVerificationErrorCode(err, ErrScopeCapabilityMismatch) {
		t.Fatalf("expected capability mismatch, got %v", err)
	}
}

func TestVerifierDoesNotWidenAnEmptyOrWildcardAllowList(t *testing.T) {
	intent, pccb := provenanceFixtures(t)
	sdk := NewVerifier(BuildLocalProofVerifier())
	for _, capabilities := range [][]string{nil, {}, []string{"*"}, {"protected_resource.*"}, {"protected_resource.read", "*"}} {
		_, err := sdk.Verify(intent, pccb, provenanceContext(capabilities))
		if !IsVerificationErrorCode(err, ErrScopeCapabilityMismatch) {
			t.Fatalf("capabilities %q: got %v", capabilities, err)
		}
	}
}

func TestVerifierRefusesUnsignedSingleUseAndForgedProofs(t *testing.T) {
	intent, pccb := provenanceFixtures(t)
	pccb.Scope.SingleUse = false
	signed, err := resignLocal(pccb)
	if err != nil {
		t.Fatal(err)
	}
	sdk := NewVerifier(BuildLocalProofVerifier())
	_, err = sdk.Verify(intent, signed, provenanceContext([]string{"protected_resource.read"}))
	if !IsVerificationErrorCode(err, ErrScopeModeInvalid) {
		t.Fatalf("expected scope mode invalid, got %v", err)
	}

	_, pccb = provenanceFixtures(t)
	untrusted := NewVerifier(nil)
	_, err = untrusted.Verify(intent, pccb, provenanceContext([]string{"protected_resource.read"}))
	if !IsVerificationErrorCode(err, ErrIssuerUntrusted) {
		t.Fatalf("expected issuer untrusted, got %v", err)
	}

	pccb.Signature.Value = strings.Repeat("A", 43)
	forged := NewVerifier(BuildLocalProofVerifier())
	_, err = forged.Verify(intent, pccb, provenanceContext([]string{"protected_resource.read"}))
	if !IsVerificationErrorCode(err, ErrSignatureInvalid) {
		t.Fatalf("expected signature invalid, got %v", err)
	}
}

func TestVerifierCarriesSignedAuthorityExtension(t *testing.T) {
	intent, pccb := provenanceFixtures(t)
	extensions, err := AuthorityExtensionObject("service:actenon-permit", "grant_9f3c1a175e9b4d80a1b2c3d4e5f60718", true)
	if err != nil {
		t.Fatal(err)
	}
	pccb.Extensions = extensions
	signed, err := resignLocal(pccb)
	if err != nil {
		t.Fatal(err)
	}
	sdk := NewVerifier(BuildLocalProofVerifier())
	verified, err := sdk.Verify(intent, signed, provenanceContext([]string{"protected_resource.read"}))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Authority == nil || verified.Authority.GrantID != "grant_9f3c1a175e9b4d80a1b2c3d4e5f60718" || !verified.Authority.Revocable {
		t.Fatalf("authority %+v", verified.Authority)
	}

	signed.Extensions = map[string]any{"authority": "not-an-object"}
	signed, err = resignLocal(signed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sdk.Verify(intent, signed, provenanceContext([]string{"protected_resource.read"}))
	if !IsVerificationErrorCode(err, ErrInvalidPCCB) {
		t.Fatalf("expected invalid authority, got %v", err)
	}
	_, parseErr := ParseAuthorityExtension(map[string]any{})
	var capErr *CapabilityError
	if !errors.As(parseErr, &capErr) {
		t.Fatal("missing authority was not a CapabilityError")
	}
}
