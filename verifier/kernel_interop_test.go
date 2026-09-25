package verifier_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

// kernel_interop_v1 vectors are minted and decided by the Python reference
// (actenon-kernel). See fixtures/kernel_interop_v1/generate.py.

type interopExpectation struct {
	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

type interopCase struct {
	ID                   string `json:"id"`
	Signer               string `json:"signer"`
	ClockSkewToleranceMS int64  `json:"clock_skew_tolerance_ms"`
	Context              struct {
		RequestID            string           `json:"request_id"`
		Audience             map[string]any   `json:"audience"`
		Now                  string           `json:"now"`
		ScopeCapabilities    []string         `json:"scope_capabilities"`
		ParameterConstraints map[string]any   `json:"parameter_constraints"`
		ResourceSelectors    []map[string]any `json:"resource_selectors"`
	} `json:"context"`
	Intent       string                        `json:"intent"`
	PCCB         string                        `json:"pccb"`
	Expected     interopExpectation            `json:"expected"`
	SDKOverrides map[string]interopExpectation `json:"sdk_overrides"`
}

type interopDocument struct {
	Signers struct {
		HS256 struct {
			KeyID  string `json:"key_id"`
			Secret string `json:"secret"`
		} `json:"hs256"`
		Ed25519 struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"ed25519"`
	} `json:"signers"`
	InvalidInputCodes []string      `json:"invalid_input_codes"`
	Cases             []interopCase `json:"cases"`
}

var interopBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ed25519TestVerifier is an Ed25519 SignatureVerifier equivalent to the
// reference's well-known EdDSA verifier, plugged in through the exported
// SignatureVerifier interface.
type ed25519TestVerifier struct {
	keyID     string
	publicKey ed25519.PublicKey
}

func (v ed25519TestVerifier) Verify(payload []byte, signature verifier.SignatureSpec) bool {
	if signature.Algorithm != "EdDSA" || signature.KeyID != v.keyID || signature.Encoding != "base64url" {
		return false
	}
	if !interopBase64URL.MatchString(signature.Value) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(signature.Value)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(v.publicKey, payload, raw)
}

func loadInteropDocument(t *testing.T) interopDocument {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "fixtures", "kernel_interop_v1", "cases.json"))
	if err != nil {
		t.Fatalf("failed to read kernel interop vectors: %v", err)
	}
	var document interopDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("failed to decode kernel interop vectors: %v", err)
	}
	if len(document.Cases) == 0 {
		t.Fatal("kernel interop vectors contain no cases")
	}
	return document
}

func runInteropCase(t *testing.T, document interopDocument, vector interopCase) {
	t.Helper()
	var signatureVerifier verifier.SignatureVerifier
	switch vector.Signer {
	case "hs256":
		if document.Signers.HS256.Secret != verifier.LocalProofSecret || document.Signers.HS256.KeyID != verifier.LocalProofKeyID {
			t.Fatal("interop vectors use an unexpected local proof key")
		}
		signatureVerifier = verifier.BuildLocalProofVerifier()
	case "ed25519":
		publicKey, err := base64.RawURLEncoding.DecodeString(document.Signers.Ed25519.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			t.Fatalf("invalid interop Ed25519 public key: %v", err)
		}
		signatureVerifier = ed25519TestVerifier{keyID: document.Signers.Ed25519.KeyID, publicKey: publicKey}
	default:
		t.Fatalf("unknown signer %q", vector.Signer)
	}

	now, err := time.Parse(time.RFC3339Nano, vector.Context.Now)
	if err != nil {
		t.Fatalf("invalid context.now: %v", err)
	}
	audience := verifier.AudienceRef{
		Type: vector.Context.Audience["type"].(string),
		ID:   vector.Context.Audience["id"].(string),
	}
	if uri, ok := vector.Context.Audience["uri"].(string); ok {
		audience.URI = uri
	}
	sdk := verifier.NewVerifier(
		signatureVerifier,
		verifier.WithClockSkewTolerance(time.Duration(vector.ClockSkewToleranceMS)*time.Millisecond),
	)
	_, err = sdk.VerifyJSON([]byte(vector.Intent), []byte(vector.PCCB), verifier.VerificationContext{
		RequestID:            vector.Context.RequestID,
		Audience:             audience,
		Now:                  now,
		ScopeCapabilities:    vector.Context.ScopeCapabilities,
		ParameterConstraints: vector.Context.ParameterConstraints,
		ResourceSelectors:    vector.Context.ResourceSelectors,
	})

	expected := vector.Expected
	if override, ok := vector.SDKOverrides["go"]; ok {
		if expected.Outcome == "refused" && override.Outcome == "verified" {
			t.Fatal("an SDK override may never accept what the reference refuses")
		}
		expected = override
	}
	if expected.Outcome == "verified" {
		if err != nil {
			t.Fatalf("reference verifies this proof; SDK refused: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("reference refuses this proof with %s; SDK verified it", expected.ReasonCode)
	}
	var verificationErr *verifier.VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("expected a VerificationError, got %v", err)
	}
	code := string(verificationErr.Code)
	for _, invalid := range document.InvalidInputCodes {
		if code == invalid {
			code = "INVALID_INPUT"
		}
	}
	if code != expected.ReasonCode {
		t.Fatalf("expected refusal %s, got %s (%s)", expected.ReasonCode, verificationErr.Code, verificationErr.Message)
	}
}

func runInteropCases(t *testing.T, ids ...string) {
	t.Helper()
	document := loadInteropDocument(t)
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	ran := 0
	for _, vector := range document.Cases {
		if len(ids) > 0 && !selected[vector.ID] {
			continue
		}
		ran++
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			runInteropCase(t, document, vector)
		})
	}
	if ran != len(ids) && len(ids) > 0 {
		t.Fatalf("selected %d interop cases, found %d", len(ids), ran)
	}
}

// TestKernelInteropVectors runs every kernel_interop_v1 case: the SDK must
// reach the reference's decision (or its documented stricter override) and
// must never verify a proof the reference refuses.
func TestKernelInteropVectors(t *testing.T) {
	runInteropCases(t)
}
