package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Adversarial extension of the frozen raw corpus. Expectations were computed
// by the Protocol Python reference at a2e0e08 and verified identical across
// Protocol Python, Kernel Python, Kernel TypeScript SDK, sdk-go and sdk-rust
// (255/255 verdicts; see the kernel fixture of the same name for provenance).
func TestProtocolAdversarialCanonicalCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "protocol_canonicalisation", "raw-corpus-adversarial.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ID        string   `json:"id"`
			Raw       string   `json:"raw_base64"`
			RawHash   string   `json:"raw_sha256"`
			Decision  string   `json:"expected_decision"`
			Canonical string   `json:"canonical_utf8"`
			Hash      string   `json:"canonical_sha256"`
			Profiles  []string `json:"safe_rejection_profiles"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			wire, err := base64.StdEncoding.DecodeString(c.Raw)
			if err != nil {
				t.Fatal(err)
			}
			rawSum := sha256.Sum256(wire)
			if hex.EncodeToString(rawSum[:]) != c.RawHash {
				t.Fatal("frozen raw hash mismatch")
			}
			var value any
			err = decodeStrictJSON(wire, &value, strictJSONOptions{})
			var canonical []byte
			if err == nil {
				canonical, err = canonicalizeBytes(value)
			}
			row := map[string]any{"id": c.ID, "decision": "REFUSE"}
			if err == nil {
				sum := sha256.Sum256(canonical)
				row["decision"] = "ACCEPT"
				row["canonical_utf8"] = string(canonical)
				row["canonical_sha256"] = hex.EncodeToString(sum[:])
			} else {
				row["error"] = err.Error()
			}
			rows = append(rows, row)
			// The Go verifier has no safe-rejection domain: json.Number
			// preserves integer digits of any length, so every case must
			// match the reference decision and canonical bytes exactly.
			if row["decision"] != c.Decision {
				t.Fatalf("expected %s got %v", c.Decision, row)
			}
			if err == nil && (string(canonical) != c.Canonical || row["canonical_sha256"] != c.Hash) {
				t.Fatalf("canonical mismatch: %v", row)
			}
		})
	}
	if output := os.Getenv("ACTENON_PARITY_RESULTS"); output != "" {
		data, _ := json.MarshalIndent(rows, "", "  ")
		if err = os.WriteFile(output, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
