package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtocolCanonicalDepthCounterexample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "protocol_canonicalisation", "deeply_nested_exceeds_limit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		InputJSON string `json:"input_json"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(vector.InputJSON))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if output, err := canonicalizeBytes(value); err == nil {
		t.Fatalf("SDK accepted Protocol's frozen invalid depth vector: %s", output)
	}
}

func TestProtocolCanonicalDepthBoundary(t *testing.T) {
	if _, err := canonicalizeBytes(nestedObject(32)); err != nil {
		t.Fatalf("Protocol depth32 must pass: %v", err)
	}
	for _, depth := range []int{33, 127} {
		if _, err := canonicalizeBytes(nestedObject(depth)); err == nil {
			t.Fatalf("Protocol depth%d must fail", depth)
		}
	}
}
