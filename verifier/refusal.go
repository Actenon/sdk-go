package verifier

import "errors"

// DisclosurePolicy selects which refusal detail a caller may see.
// Wire 1.2.0 keeps SCOPE_CAPABILITY_MISMATCH and SCOPE_MODE_INVALID as
// canonical codes. They are not aliases of PARAMETER_MISMATCH. Public
// disclosure still collapses them to PROOF_INVALID.
type DisclosurePolicy string

const (
	DisclosurePublic     DisclosurePolicy = "public"
	DisclosureTrusted    DisclosurePolicy = "trusted"
	DisclosureLocalDebug DisclosurePolicy = "local_debug"
)

// canonicalRefusalCodes is the wire 1.2.0 catalogue (22 codes).
var canonicalRefusalCodes = map[string]struct{}{
	"MALFORMED_REQUEST":            {},
	"UNSUPPORTED_PROTOCOL_VERSION": {},
	"CANONICALISATION_FAILURE":     {},
	"PROOF_MISSING":                {},
	"PROOF_INVALID":                {},
	"ISSUER_UNTRUSTED":             {},
	"SIGNATURE_INVALID":            {},
	"PROOF_EXPIRED":                {},
	"PROOF_NOT_YET_VALID":          {},
	"AUDIENCE_MISMATCH":            {},
	"TARGET_MISMATCH":              {},
	"ACTION_MISMATCH":              {},
	"PARAMETER_MISMATCH":           {},
	"SCOPE_CAPABILITY_MISMATCH":    {},
	"SCOPE_MODE_INVALID":           {},
	"REPLAY_DETECTED":              {},
	"AUTHORITY_REVOKED":            {},
	"POLICY_REFUSAL":               {},
	"CREDENTIAL_UNAVAILABLE":       {},
	"PROVIDER_REFUSAL":             {},
	"PROVIDER_FAILURE":             {},
	"OUTCOME_UNKNOWN":              {},
}

// compatibilityAliases resolves legacy kernel and permit codes. The two
// edge-binding codes are canonical and intentionally absent.
var compatibilityAliases = map[string]string{
	"PCCB_REQUIRED":                 "PROOF_MISSING",
	"PCCB_EXPIRED":                  "PROOF_EXPIRED",
	"DUPLICATE_REPLAY":              "REPLAY_DETECTED",
	"SIGNATURE_INVALID":             "SIGNATURE_INVALID",
	"ACTION_MISMATCH":               "ACTION_MISMATCH",
	"AUDIENCE_MISMATCH":             "AUDIENCE_MISMATCH",
	"PROOF_INVALID":                 "PROOF_INVALID",
	"INTENT_MISMATCH":               "PARAMETER_MISMATCH",
	"TARGET_MISMATCH":               "TARGET_MISMATCH",
	"ACTION_HASH_MISMATCH":          "PARAMETER_MISMATCH",
	"ACTION_HASH_ALGORITHM_INVALID": "PARAMETER_MISMATCH",
	"ACTION_HASH_INVALID":           "PARAMETER_MISMATCH",
	"TENANT_MISMATCH":               "TARGET_MISMATCH",
	"SUBJECT_MISMATCH":              "TARGET_MISMATCH",
	"PROOF_PAYLOAD_INVALID":         "MALFORMED_REQUEST",
	"PROOF_NOT_YET_VALID":           "PROOF_NOT_YET_VALID",
	"NOT_ACTIVE":                    "POLICY_REFUSAL",
	"REVOKED":                       "AUTHORITY_REVOKED",
	"EXPIRED":                       "PROOF_EXPIRED",
	"SCOPE_DENIED":                  "POLICY_REFUSAL",
	"OUT_OF_SCOPE":                  "POLICY_REFUSAL",
	"BUDGET_EXCEEDED":               "POLICY_REFUSAL",
	"RATE_LIMITED":                  "POLICY_REFUSAL",
	"ENGINE_ERROR":                  "OUTCOME_UNKNOWN",
	"SCHEMA_INVALID":                "MALFORMED_REQUEST",
	"ESCROW_REFERENCE_MISSING":      "MALFORMED_REQUEST",
	"EXECUTION_FAILED":              "OUTCOME_UNKNOWN",
	"POLICY_REFUSED":                "POLICY_REFUSAL",
}

// disclosedByCanonical is the public umbrella for each canonical code.
var disclosedByCanonical = map[string]string{
	"MALFORMED_REQUEST":            "MALFORMED_REQUEST",
	"UNSUPPORTED_PROTOCOL_VERSION": "UNSUPPORTED_PROTOCOL_VERSION",
	"CANONICALISATION_FAILURE":     "CANONICALISATION_FAILURE",
	"PROOF_MISSING":                "PROOF_MISSING",
	"PROOF_INVALID":                "PROOF_INVALID",
	"ISSUER_UNTRUSTED":             "PROOF_INVALID",
	"SIGNATURE_INVALID":            "PROOF_INVALID",
	"PROOF_EXPIRED":                "PROOF_EXPIRED",
	"PROOF_NOT_YET_VALID":          "PROOF_NOT_YET_VALID",
	"AUDIENCE_MISMATCH":            "PROOF_INVALID",
	"TARGET_MISMATCH":              "PROOF_INVALID",
	"ACTION_MISMATCH":              "PROOF_INVALID",
	"PARAMETER_MISMATCH":           "PROOF_INVALID",
	"SCOPE_CAPABILITY_MISMATCH":    "PROOF_INVALID",
	"SCOPE_MODE_INVALID":           "PROOF_INVALID",
	"REPLAY_DETECTED":              "REPLAY_DETECTED",
	"AUTHORITY_REVOKED":            "AUTHORITY_REVOKED",
	"POLICY_REFUSAL":               "POLICY_REFUSAL",
	"CREDENTIAL_UNAVAILABLE":       "CREDENTIAL_UNAVAILABLE",
	"PROVIDER_REFUSAL":             "PROVIDER_REFUSAL",
	"PROVIDER_FAILURE":             "PROVIDER_FAILURE",
	"OUTCOME_UNKNOWN":              "OUTCOME_UNKNOWN",
}

var retryableByCanonical = map[string]bool{
	"MALFORMED_REQUEST":            false,
	"UNSUPPORTED_PROTOCOL_VERSION": false,
	"CANONICALISATION_FAILURE":     false,
	"PROOF_MISSING":                false,
	"PROOF_INVALID":                false,
	"ISSUER_UNTRUSTED":             false,
	"SIGNATURE_INVALID":            false,
	"PROOF_EXPIRED":                false,
	"PROOF_NOT_YET_VALID":          true,
	"AUDIENCE_MISMATCH":            false,
	"TARGET_MISMATCH":              false,
	"ACTION_MISMATCH":              false,
	"PARAMETER_MISMATCH":           false,
	"SCOPE_CAPABILITY_MISMATCH":    false,
	"SCOPE_MODE_INVALID":           false,
	"REPLAY_DETECTED":              false,
	"AUTHORITY_REVOKED":            false,
	"POLICY_REFUSAL":               false,
	"CREDENTIAL_UNAVAILABLE":       true,
	"PROVIDER_REFUSAL":             false,
	"PROVIDER_FAILURE":             true,
	"OUTCOME_UNKNOWN":              true,
}

// ResolveAlias returns the canonical refusal code. Canonical codes,
// including SCOPE_CAPABILITY_MISMATCH and SCOPE_MODE_INVALID, return
// themselves. Unknown codes return an error.
func ResolveAlias(code string) (string, error) {
	if _, ok := canonicalRefusalCodes[code]; ok {
		return code, nil
	}
	if canonical, ok := compatibilityAliases[code]; ok {
		return canonical, nil
	}
	return "", errors.New("refusal code " + code + " is neither canonical nor a registered alias")
}

// DisclosedCode is the public-safe code for a verifier refusal.
// Unknown codes disclose as OUTCOME_UNKNOWN. An empty code discloses as
// PROOF_MISSING.
func DisclosedCode(code string) string {
	if code == "" {
		return "PROOF_MISSING"
	}
	canonical, err := ResolveAlias(code)
	if err != nil {
		return "OUTCOME_UNKNOWN"
	}
	return disclosedByCanonical[canonical]
}

// InternalCode is the trusted detail for a refusal. Public disclosure
// suppresses it. Trusted and local-debug disclosure return the canonical
// code. Unknown codes are returned unchanged.
func InternalCode(code string, policy DisclosurePolicy) (string, bool) {
	if policy == DisclosurePublic || code == "" {
		return "", false
	}
	canonical, err := ResolveAlias(code)
	if err != nil {
		return code, true
	}
	return canonical, true
}

// RefusalRetryable reports the catalogue retryable flag. Unknown codes are
// retryable, matching the protocol's forward-compatible default.
func RefusalRetryable(code string) bool {
	if code == "" {
		return retryableByCanonical["PROOF_MISSING"]
	}
	canonical, err := ResolveAlias(code)
	if err != nil {
		return true
	}
	return retryableByCanonical[canonical]
}
