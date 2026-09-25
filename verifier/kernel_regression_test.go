package verifier_test

import "testing"

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
