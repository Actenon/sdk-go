package verifier_test

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

// This is the README quickstart, run against a proof minted through
// actenon-permit (fixtures/permit_interop_v1/main-ed25519).
func ExampleVerifier_VerifyJSON() {
	dir := "../fixtures/permit_interop_v1/main-ed25519/"
	intentJSON, _ := os.ReadFile(dir + "action_intent.json")
	pccbJSON, _ := os.ReadFile(dir + "pccb.json")
	issuerJWK, _ := os.ReadFile(dir + "public_key.jwk.json")

	// Pin the issuer's Ed25519 public key(s) by key ID.
	signatures, err := verifier.NewEd25519VerifierFromJWKs(issuerJWK)
	if err != nil {
		panic(err)
	}
	// Clock-skew tolerance defaults to zero; see WithClockSkewTolerance.
	v := verifier.NewVerifier(signatures)

	context := verifier.VerificationContext{
		RequestID:         "req-123",
		Audience:          verifier.AudienceRef{Type: "service", ID: "actenon-permit-gateway"},
		Now:               time.Date(2026, 9, 25, 17, 35, 0, 0, time.UTC), // time.Now() in production
		ScopeCapabilities: []string{"payment.refund"},
	}
	verified, err := v.VerifyJSON(intentJSON, pccbJSON, context)
	var refusal *verifier.VerificationError
	if errors.As(err, &refusal) {
		fmt.Println("refused:", refusal.Code)
		return
	}
	if err != nil {
		panic(err)
	}
	fmt.Println("verified:", verified.Intent.Action.Name, "on", verified.Intent.Target.ResourceID)

	// A proof never covers a different action than the one it was minted for.
	widenedJSON, _ := os.ReadFile(dir + "action_intent_widened.json")
	_, err = v.VerifyJSON(widenedJSON, pccbJSON, context)
	if errors.As(err, &refusal) {
		fmt.Println("refused:", refusal.Code)
	}
	// Output:
	// verified: payment.refund on stripe
	// refused: ACTION_MISMATCH
}
