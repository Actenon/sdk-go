package verifier_test

import (
	"testing"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

// Targeted regressions against proofs minted by the Python reference. The
// full kernel_interop_v1 matrix runs in TestKernelInteropVectors.

func TestVerifierAcceptsCurrentCanonicalizationProfile(t *testing.T) {
	// The Kernel mints action hashes labelled ACTENON-JCS-STRICT-1 and still
	// accepts the legacy RFC8785-JCS label; anything else is refused.
	runInteropCases(t,
		"hs256/valid",
		"ed25519/valid",
		"hs256/issuer_signed_legacy_label",
		"ed25519/issuer_signed_legacy_label",
		"hs256/issuer_signed_unknown_label",
		"hs256/issuer_signed_hash_alg_sha512",
	)
}

func TestVerifierAcceptsSubSecondTimestamps(t *testing.T) {
	// The reference normalizes timestamps to UTC with microsecond precision
	// (isoformat), so proofs minted from a real clock carry fractional
	// seconds in the signed payload and in the action-hash input.
	runInteropCases(t,
		"hs256/subsecond_micro_123456",
		"hs256/subsecond_micro_123456_before_nbf",
		"hs256/subsecond_micro_500000",
		"hs256/subsecond_micro_500000_before_nbf",
		"hs256/subsecond_micro_000001",
		"hs256/subsecond_micro_000001_before_nbf",
		"ed25519/subsecond_micro_500000",
		"hs256/frac7_pccb_nbf",
		"hs256/frac9_intent_issued",
		"hs256/issuer_signed_pccb_frac_nbf",
		"hs256/issuer_signed_pccb_frac_nbf_presented_short",
		"hs256/pccb_nbf_frac_zero",
		"hs256/pccb_nbf_offset_equiv",
		"hs256/time_nbf_minus_skew_minus1us_skew0",
		"hs256/time_exp_plus_skew_plus1us_skew2000",
	)
}

func TestVerifierChecksInReferenceOrder(t *testing.T) {
	// Signature first, then time, audience, target, scope, intent, tenant,
	// subject, action and action hash, so a forged or tampered proof never
	// learns which semantic check it would fail.
	runInteropCases(t,
		"hs256/expired_and_bad_sig",
		"hs256/not_yet_valid_and_bad_sig",
		"ed25519/expired_and_bad_sig",
		"hs256/pccb_nbf_frac_half",
		"hs256/multi_audience_and_expired",
		"hs256/multi_target_and_tenant",
		"hs256/multi_target_and_capability",
		"hs256/pccb_scope_mode",
		"hs256/issuer_signed_scope_mode_prefix",
	)
}

func TestVerifierDoesNotReorderSignedCapabilities(t *testing.T) {
	// scope.capabilities is signed in the order presented. Sorting it before
	// verification let a reordered (or re-duplicated) proof verify.
	runInteropCases(t,
		"hs256/issuer_unsorted_caps",
		"hs256/issuer_sorted_caps",
		"hs256/reordered_caps_presented",
		"hs256/dup_caps_presented",
		"ed25519/reordered_caps_presented",
		"ed25519/issuer_unsorted_caps",
	)
}

func TestVerifierCanonicalizesLikeReference(t *testing.T) {
	// Strings are canonicalized without HTML/U+2028 escaping, "-0" is the
	// integer zero, bindings are compared on canonical bytes, and the
	// profile's depth limit applies.
	runInteropCases(t,
		"hs256/minted_html",
		"hs256/minted_u2028",
		"ed25519/minted_html",
		"hs256/minted_control",
		"hs256/minted_emoji",
		"hs256/minted_keys_order",
		"hs256/minted_escape_chars",
		"hs256/minted_big_ints",
		"hs256/minted_bigger_ints",
		"hs256/minted_empty_string_key",
		"hs256/neg_zero_intent",
		"hs256/neg_zero_both",
		"hs256/nfd_intent_vs_nfc_proof",
		"hs256/depth_params_124",
	)
}

func TestVerifierParsesJSONLikeTheReferenceIngress(t *testing.T) {
	// The reference's JSON ingress refuses duplicate members and oversized
	// or over-deep documents, treats member names case-sensitively, and
	// refuses null for objects, arrays and booleans. encoding/json keeps the
	// last duplicate, binds "Audience", "AUDIENCE" or a long-s "scope" to
	// struct fields, and decodes null as an empty value, so without these checks
	// the Go verifier could act on a different document than the one the
	// reference (or the issuer) saw.
	runInteropCases(t,
		"hs256/dup_param_key_same",
		"hs256/dup_param_key_diff_last_signed",
		"hs256/dup_param_key_diff_first_signed",
		"hs256/dup_top_audience_pccb",
		"hs256/dup_top_audience_pccb_signed_last",
		"hs256/case_Audience_extra",
		"hs256/case_AUDIENCE_only",
		"hs256/case_Target_intent_extra",
		"hs256/case_target_resource_ID_extra",
		"hs256/case_longs_scope",
		"hs256/case_kelvin_key_id",
		"hs256/intent_tenant_attr_null",
		"hs256/intent_constraints_null",
		"hs256/intent_target_selectors_null",
		"hs256/pccb_extensions_null",
		"hs256/pccb_tenant_attr_null",
		"hs256/pccb_scope_selectors_null",
		"hs256/pccb_scope_pc_null",
		"hs256/pccb_scope_single_use_str",
		"hs256/pccb_escrow_null",
		"hs256/intent_requester_dn_null",
		"hs256/pccb_intent_id_null",
		"hs256/lone_surrogate_param",
		"hs256/amount_escaped_key",
		"hs256/currency_escaped_value",
		"hs256/trailing_garbage_intent",
		"hs256/two_objects_pccb",
		"hs256/bom_intent",
		"hs256/depth_params_125",
		"hs256/depth_params_128",
		"hs256/depth_params_200",
		"hs256/intent_target_uri_empty",
		"hs256/intent_dn_empty_proof_absent",
		"hs256/intent_target_uri_empty_proof_absent",
		"hs256/pccb_intent_id_empty",
		"hs256/pccb_display_name_empty",
		"hs256/pccb_escrow_empty",
	)
}

func TestSignatureValuesMustBeCanonicalBase64URL(t *testing.T) {
	// base64.RawURLEncoding ignores CR/LF anywhere in its input, so a
	// signature with inserted line breaks verified (a malleable proof) while
	// the reference refuses it.
	runInteropCases(t,
		"hs256/sig_newline",
		"hs256/sig_crlf",
		"hs256/sig_space",
		"hs256/sig_padded",
		"hs256/sig_padded2",
		"hs256/sig_std_alphabet",
		"hs256/sig_truncated",
		"hs256/sig_nontrailing_bits",
	)
}

func TestVerifierEnforcesActionIntentSemantics(t *testing.T) {
	// The reference's Action Intent intake refuses an expiry that is not
	// after issuance and an action without parameters, even when a proof
	// was issued for it.
	runInteropCases(t,
		"hs256/issuer_signed_window_equal",
		"hs256/issuer_signed_window_inverted",
		"hs256/issuer_signed_empty_params",
		"ed25519/issuer_signed_window_inverted",
		"ed25519/issuer_signed_empty_params",
	)
}

func TestVerifierBindsEscrowReferenceLikeReference(t *testing.T) {
	// The signed payload carries escrow_reference whenever escrow_id is
	// present (even " "), with single_use taken from scope.single_use.
	runInteropCases(t,
		"hs256/minted_escrow",
		"hs256/minted_escrow_single_use_tamper",
		"hs256/minted_escrow_removed",
		"hs256/escrow_added_to_plain",
		"hs256/pccb_escrow_space",
		"ed25519/pccb_escrow_space",
	)
}

func TestVerifiedEscrowReferenceCarriesOnlySignedValues(t *testing.T) {
	document := loadInteropDocument(t)
	for _, vector := range document.Cases {
		if vector.ID != "hs256/minted_escrow_single_use_tamper" {
			continue
		}
		now, _ := time.Parse(time.RFC3339, vector.Context.Now)
		verified, err := verifier.NewVerifier(verifier.BuildLocalProofVerifier()).VerifyJSON(
			[]byte(vector.Intent), []byte(vector.PCCB), verifier.VerificationContext{
				RequestID:         vector.Context.RequestID,
				Audience:          verifier.AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
				Now:               now,
				ScopeCapabilities: vector.Context.ScopeCapabilities,
			})
		if err != nil {
			t.Fatal(err)
		}
		// escrow_reference.single_use is not signed (the signed payload uses
		// scope.single_use); the presented false must not be surfaced.
		if verified.PCCB.EscrowReference == nil || !verified.PCCB.Scope.SingleUse ||
			verified.PCCB.EscrowReference.SingleUse != verified.PCCB.Scope.SingleUse {
			t.Fatalf("verified escrow reference carries an unsigned value: %+v", verified.PCCB.EscrowReference)
		}
		return
	}
	t.Fatal("interop case not found")
}
