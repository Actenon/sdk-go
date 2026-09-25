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
