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
