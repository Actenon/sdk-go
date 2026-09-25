package verifier_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Actenon/sdk-go/verifier"
)

type interopArtifactExpectation struct {
	Outcome    string `json:"outcome"`
	ReasonCode string `json:"reason_code"`
}

type interopArtifactsDocument struct {
	CountersignatureTrustedKeys json.RawMessage `json:"countersignature_trusted_keys"`
	ApprovalTrustedKeys         json.RawMessage `json:"approval_trusted_keys"`
	Countersignatures           []struct {
		ID               string                     `json:"id"`
		ReceiptOrDigest  json.RawMessage            `json:"receipt_or_digest"`
		Countersignature json.RawMessage            `json:"countersignature"`
		Expected         interopArtifactExpectation `json:"expected"`
	} `json:"countersignatures"`
	Approvals []struct {
		ID                 string                     `json:"id"`
		Approval           json.RawMessage            `json:"approval"`
		ExpectedActionHash *verifier.ActionHashSpec   `json:"expected_action_hash"`
		Expected           interopArtifactExpectation `json:"expected"`
	} `json:"approvals"`
	Inclusions []struct {
		ID             string                     `json:"id"`
		Digest         verifier.ReceiptDigest     `json:"digest"`
		InclusionProof json.RawMessage            `json:"inclusion_proof"`
		Checkpoint     json.RawMessage            `json:"checkpoint"`
		Expected       interopArtifactExpectation `json:"expected"`
	} `json:"inclusions"`
}

// interopArtifactCases lists the artifact vectors the SDK is checked against.
var interopArtifactCases = map[string]bool{
	"countersignature/receipt_current_profile":                true,
	"countersignature/digest_current_profile":                 true,
	"countersignature/digest_legacy_label_vs_current_profile": true,
	"countersignature/legacy_profile_countersignature":        true,
	"countersignature/unknown_profile_label":                  true,
	"countersignature/anchor_reference_null":                  true,
	"countersignature/anchor_reference_object":                true,
	"approval/current_profile":                                true,
	"approval/current_profile_expected_legacy_label":          true,
	"approval/legacy_profile_expected_current_label":          true,
	"approval/different_action":                               true,
	"approval/unknown_profile_label":                          true,
	"approval/expected_hash_unknown_label":                    true,
	"inclusion/legacy_profile":                                true,
	"inclusion/current_profile":                               true,
	"inclusion/unknown_profile_label":                         true,
}

func loadInteropArtifacts(t *testing.T) interopArtifactsDocument {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "fixtures", "kernel_interop_v1", "artifacts.json"))
	if err != nil {
		t.Fatalf("failed to read kernel interop artifacts: %v", err)
	}
	var document interopArtifactsDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("failed to decode kernel interop artifacts: %v", err)
	}
	return document
}

func artifactErrorCode(t *testing.T, err error) string {
	t.Helper()
	var countersignatureErr *verifier.CountersignatureVerificationError
	var trustErr *verifier.TrustArtifactVerificationError
	var transparencyErr *verifier.TransparencyVerificationError
	switch {
	case errors.As(err, &countersignatureErr):
		return countersignatureErr.Code
	case errors.As(err, &trustErr):
		return trustErr.Code
	case errors.As(err, &transparencyErr):
		return transparencyErr.Code
	}
	t.Fatalf("unexpected error type: %v", err)
	return ""
}

func requireArtifactOutcome(t *testing.T, err error, expected interopArtifactExpectation) {
	t.Helper()
	if expected.Outcome == "verified" {
		if err != nil {
			t.Fatalf("reference verifies this artifact; SDK refused: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("reference refuses this artifact with %s; SDK verified it", expected.ReasonCode)
	}
	if code := artifactErrorCode(t, err); code != expected.ReasonCode {
		t.Fatalf("expected %s, got %s (%v)", expected.ReasonCode, code, err)
	}
}

func TestKernelInteropCountersignatures(t *testing.T) {
	document := loadInteropArtifacts(t)
	keys, err := verifier.ParseTrustedCounterSignatureKeysJSON(document.CountersignatureTrustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range document.Countersignatures {
		if !interopArtifactCases["countersignature/"+vector.ID] {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			var receiptOrDigest map[string]any
			decoder := json.NewDecoder(bytes.NewReader(vector.ReceiptOrDigest))
			decoder.UseNumber()
			if err := decoder.Decode(&receiptOrDigest); err != nil {
				t.Fatal(err)
			}
			countersignature, err := verifier.ParseReceiptCountersignatureJSON(vector.Countersignature)
			if err == nil {
				_, err = verifier.VerifyCountersignature(receiptOrDigest, countersignature, keys)
			}
			requireArtifactOutcome(t, err, vector.Expected)
		})
	}
}

func TestKernelInteropApprovals(t *testing.T) {
	document := loadInteropArtifacts(t)
	keys, err := verifier.ParseTrustedCounterSignatureKeysJSON(document.ApprovalTrustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range document.Approvals {
		if !interopArtifactCases["approval/"+vector.ID] {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			approval, err := verifier.ParseApprovalArtifactJSON(vector.Approval)
			if err == nil {
				if vector.ExpectedActionHash != nil {
					_, err = verifier.VerifyApprovalArtifactForAction(approval, keys, *vector.ExpectedActionHash)
				} else {
					_, err = verifier.VerifyApprovalArtifact(approval, keys)
				}
			}
			requireArtifactOutcome(t, err, vector.Expected)
		})
	}
}

func TestKernelInteropInclusions(t *testing.T) {
	document := loadInteropArtifacts(t)
	for _, vector := range document.Inclusions {
		if !interopArtifactCases["inclusion/"+vector.ID] {
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			proof, err := verifier.ParseTransparencyInclusionProofJSON(vector.InclusionProof)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := verifier.ParseTransparencyCheckpointJSON(vector.Checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.VerifyInclusion(vector.Digest, proof, checkpoint)
			requireArtifactOutcome(t, err, vector.Expected)
		})
	}
}
