package verifier_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

// permit_interop_v1 holds real proofs minted through actenon-permit by the
// current Kernel (Ed25519 and the local HS256 key, from the main branch and
// the published packages), with fractional-second timestamps. The expected
// decisions come from the Python reference (generate_manifest.py).

func permitFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(append([]string{filepath.Dir(filename), "..", "fixtures", "permit_interop_v1"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func permitVerifier(t *testing.T, directory string, pccb verifier.PCCB) verifier.SignatureVerifier {
	t.Helper()
	if pccb.Signature.Algorithm != "EdDSA" {
		return verifier.BuildLocalProofVerifier()
	}
	ed, err := verifier.NewEd25519VerifierFromJWKs(permitFixture(t, directory, "public_key.jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	return ed
}

func permitVerify(t *testing.T, sv verifier.SignatureVerifier, intentRaw, pccbRaw []byte) error {
	t.Helper()
	pccb, err := verifier.ParsePCCBJSON(pccbRaw)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, pccb.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.NewVerifier(sv).VerifyJSON(intentRaw, pccbRaw, verifier.VerificationContext{
		RequestID:         "req_permit_interop",
		Audience:          pccb.Audience,
		Now:               now,
		ScopeCapabilities: pccb.Scope.Capabilities,
	})
	return err
}

func TestPermitMintedProofs(t *testing.T) {
	var manifest struct {
		Cases []struct {
			ID        string             `json:"id"`
			Directory string             `json:"directory"`
			Intent    string             `json:"intent"`
			Expected  interopExpectation `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(permitFixture(t, "manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("no Permit interop cases")
	}
	for _, vector := range manifest.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			pccbRaw := permitFixture(t, vector.Directory, "pccb.json")
			pccb, err := verifier.ParsePCCBJSON(pccbRaw)
			if err != nil {
				t.Fatal(err)
			}
			err = permitVerify(t, permitVerifier(t, vector.Directory, pccb), permitFixture(t, vector.Directory, vector.Intent), pccbRaw)
			if vector.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("reference verifies this proof; SDK refused: %v", err)
				}
				return
			}
			if !verifier.IsVerificationErrorCode(err, verifier.VerificationErrorCode(vector.Expected.ReasonCode)) {
				t.Fatalf("expected %s, got %v", vector.Expected.ReasonCode, err)
			}
		})
	}
}

func TestEd25519VerifierRefusesWrongKeyKidAndAlgorithm(t *testing.T) {
	intentRaw := permitFixture(t, "main-ed25519", "action_intent.json")
	pccbRaw := permitFixture(t, "main-ed25519", "pccb.json")
	pccb, err := verifier.ParsePCCBJSON(pccbRaw)
	if err != nil {
		t.Fatal(err)
	}
	mainKeyID, mainKey, err := verifier.ParseEd25519PublicJWK(permitFixture(t, "main-ed25519", "public_key.jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := verifier.ParseEd25519PublicJWK(permitFixture(t, "published-ed25519", "public_key.jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	correct, err := verifier.NewEd25519Verifier(map[string]ed25519.PublicKey{mainKeyID: mainKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := permitVerify(t, correct, intentRaw, pccbRaw); err != nil {
		t.Fatalf("pinned key must verify: %v", err)
	}
	wrongKey, _ := verifier.NewEd25519Verifier(map[string]ed25519.PublicKey{mainKeyID: otherKey})
	wrongKid, _ := verifier.NewEd25519Verifier(map[string]ed25519.PublicKey{"another-kid": mainKey})
	for name, sv := range map[string]verifier.SignatureVerifier{
		"wrong key":    wrongKey,
		"unknown kid":  wrongKid,
		"local HS256":  verifier.BuildLocalProofVerifier(),
		"nil verifier": (*verifier.Ed25519Verifier)(nil),
	} {
		if err := permitVerify(t, sv, intentRaw, pccbRaw); !verifier.IsVerificationErrorCode(err, verifier.ErrSignatureInvalid) {
			t.Fatalf("%s: expected SIGNATURE_INVALID, got %v", name, err)
		}
	}
	for _, algorithm := range []string{"HS256", "none", "Ed25519", "eddsa"} {
		spec := pccb.Signature
		spec.Algorithm = algorithm
		if correct.Verify([]byte("payload"), spec) {
			t.Fatalf("algorithm %q must not verify", algorithm)
		}
	}
	for _, jwk := range []string{
		`{"kty":"OKP","crv":"X25519","kid":"k","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN18"}`,
		`{"kty":"OKP","crv":"Ed25519","kid":"k","alg":"ES256","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN18"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN18"}`,
		`{"kty":"OKP","crv":"Ed25519","kid":"k","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN1"}`,
		`{"kty":"OKP","crv":"Ed25519","kid":"k","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN18","d":"x"}`,
	} {
		if _, _, err := verifier.ParseEd25519PublicJWK([]byte(jwk)); err == nil {
			t.Fatalf("JWK must be refused: %s", jwk)
		}
	}
	if _, err := verifier.NewEd25519Verifier(map[string]ed25519.PublicKey{"k": mainKey[:31]}); err == nil {
		t.Fatal("short keys must be refused")
	}
	var refusal *verifier.VerificationError
	if err := permitVerify(t, wrongKey, intentRaw, pccbRaw); !errors.As(err, &refusal) {
		t.Fatal("expected a VerificationError")
	}
}
