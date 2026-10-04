package verifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// protocol/13-edge-binding.md E2 with a numeric constraint. The shared
// vectors only declare string constraints, so this re-signs the shared PCCB
// with a numeric signed constraint (max_bytes: 64) and checks what the edge
// may declare: Go integers and json.Number are exact and match; float64 is
// refused (PARAMETER_MISMATCH), because the SDK cannot recover the source text
// (2500, 2500.0, 2.5e3, or a rounded 2^53+1 all decode to the same float64).
// Decode a JSON-configured declaration with json.Decoder.UseNumber.
func TestEdgeBindingNumericParameterConstraints(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "fixtures", "verifier_sdk_v1")
	intentRaw, err := os.ReadFile(filepath.Join(root, "action_intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	pccbRaw, err := os.ReadFile(filepath.Join(root, "pccb.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(pccbRaw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	scope := document["scope"].(map[string]any)
	scope["parameter_constraints"].(map[string]any)["max_bytes"] = json.Number("64")
	unsignedRaw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePCCBJSON(unsignedRaw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalizeBytes(normalizedUnsignedPCCBPayload(parsed))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(LocalProofSecret))
	mac.Write(payload)
	document["signature"].(map[string]any)["value"] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	signedRaw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	verify := func(declared any) error {
		context := VerificationContext{
			RequestID:            "req_numeric_constraints",
			Audience:             AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
			Now:                  time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			ScopeCapabilities:    []string{"protected_resource.read"},
			ParameterConstraints: map[string]any{"exact_message": "portable hello world", "max_bytes": declared},
			ResourceSelectors:    []map[string]any{{"resource_id": "hello_resource_demo_001"}},
		}
		_, err := NewVerifier(BuildLocalProofVerifier()).VerifyJSON(intentRaw, signedRaw, context)
		return err
	}
	for name, declared := range map[string]any{"int": 64, "int64": int64(64), "json.Number": json.Number("64")} {
		if err := verify(declared); err != nil {
			t.Fatalf("%s declaration of the signed constraint: expected verified, got %v", name, err)
		}
	}
	for name, declared := range map[string]any{"float64": float64(64), "different int": 65, "string": "64"} {
		var verificationErr *VerificationError
		if err := verify(declared); !errors.As(err, &verificationErr) || verificationErr.Code != ErrParameterMismatch {
			t.Fatalf("%s declaration: expected %s, got %v", name, ErrParameterMismatch, err)
		}
	}
}
