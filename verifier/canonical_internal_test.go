package verifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type strictCanonicalizationCase struct {
	ID             string          `json:"id"`
	Input          json.RawMessage `json:"input"`
	ExpectedOutput string          `json:"expected_output"`
	ExpectedPass   bool            `json:"expected_pass"`
	Generator      string          `json:"generator"`
}

func decodeWithNumbers(t *testing.T, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("failed to decode canonicalization input: %v", err)
	}
	return value
}

func nestedObject(levels int) any {
	var value any = "leaf"
	for i := 0; i < levels; i++ {
		value = map[string]any{"k": value}
	}
	return value
}

// TestCanonicalizationStrictV1Vectors runs the Kernel's
// canonicalization_strict_v1 vectors (ACTENON-JCS-STRICT-1) against the
// canonicaliser used for signatures and action hashes.
func TestCanonicalizationStrictV1Vectors(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "fixtures", "canonicalization_strict_v1", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []strictCanonicalizationCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	generated := map[string]any{
		// validate_json_depth counts the root as level 1.
		"max_depth":             nestedObject(127),
		"excessive_depth":       nestedObject(129),
		"max_output_size":       map[string]any{"s": strings.Repeat("A", 1_048_576-8)},
		"excessive_output_size": map[string]any{"s": strings.Repeat("A", 1_048_576+100)},
		"nan":                   map[string]any{"value": json.Number("NaN")},
		"positive_inf":          map[string]any{"value": json.Number("Infinity")},
		"negative_inf":          map[string]any{"value": json.Number("-Infinity")},
		"non_string_key":        map[int]any{1: "x"},
	}
	ran := 0
	for _, vector := range manifest.Cases {
		var input any
		switch {
		case vector.Generator == "":
			input = decodeWithNumbers(t, vector.Input)
		case generated[vector.Generator] != nil:
			input = generated[vector.Generator]
		default:
			// legacy_proof / new_profile_proof / unsupported_profile are
			// proof-level cases covered by the kernel_interop_v1 vectors.
			continue
		}
		ran++
		t.Run(vector.ID, func(t *testing.T) {
			output, err := canonicalizeJSON(input)
			if !vector.ExpectedPass {
				if err == nil {
					t.Fatalf("expected rejection, got %q", truncate(output))
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if vector.Generator == "" && output != vector.ExpectedOutput {
				t.Fatalf("expected %q, got %q", vector.ExpectedOutput, output)
			}
		})
	}
	if ran != 15 {
		t.Fatalf("expected to run 15 canonicalization vectors, ran %d", ran)
	}
}

func truncate(value string) string {
	if len(value) > 80 {
		return value[:80] + "..."
	}
	return value
}

func TestCanonicalStringEncodingMatchesReference(t *testing.T) {
	// Expected values produced by the reference canonicaliser
	// (json.dumps(ensure_ascii=False, separators=(",", ":"))).
	cases := map[string]string{
		"<b>Tom & Jerry</b> > 1":  `"<b>Tom & Jerry</b> > 1"`,
		"line\u2028sep\u2029para": "\"line\u2028sep\u2029para\"",
		"a\u0001b\u001fc\u007fd":  "\"a\\u0001b\\u001fc\u007fd\"",
		"\b\f\n\r\t\"\\/":         `"\b\f\n\r\t\"\\/"`,
		"caf\u00e9 \U0001F600":    "\"caf\u00e9 \U0001F600\"",
	}
	for input, expected := range cases {
		output, err := canonicalizeJSON(input)
		if err != nil || output != expected {
			t.Fatalf("canonicalizeJSON(%q) = %q, %v; want %q", input, output, err, expected)
		}
	}
	if _, err := canonicalizeJSON("bad \xff utf-8"); err == nil {
		t.Fatal("invalid UTF-8 must not be canonicalized")
	}
}

func TestCanonicalNumbersMatchReference(t *testing.T) {
	output, err := canonicalizeJSON(map[string]any{"z": json.Number("-0"), "big": json.Number("-9223372036854775809")})
	if err != nil || output != `{"big":-9223372036854775809,"z":0}` {
		t.Fatalf("unexpected canonical numbers: %q, %v", output, err)
	}
	for _, raw := range []string{"25.0", "2.5e1", "1E2", "NaN", "+1", "01", ""} {
		if _, err := canonicalizeJSON(json.Number(raw)); err == nil {
			t.Fatalf("json.Number(%q) must be refused", raw)
		}
	}
}
