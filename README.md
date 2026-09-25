# Actenon Go Verifier SDK

Minimal protected-endpoint verifier SDK for Go, aligned to the Actenon Kernel's public `action_intent` and `pccb` contracts.

This package is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

## Install

```bash
go get github.com/Actenon/sdk-go@v1.0.0
```

## Scope

- `action_intent` v1 and `pccb` v1 Go data structures
- protected-endpoint proof verification, with the checks in the reference
  verifier's order: signature first, then not-before/expiry, audience,
  target, scope, intent, tenant, subject, action, and action hash
- optional verifier-side clock skew tolerance, defaulting to zero
- the `ACTENON-JCS-STRICT-1` canonicalisation profile (and the legacy
  `RFC8785-JCS` label), byte-identical to the Kernel's canonicaliser
- strict JSON decoding: duplicate or case-variant members, `null` objects and
  over-deep or oversized documents are refused
- built-in `Ed25519Verifier` (EdDSA, keys pinned by `kid`, raw keys or JWKs)
  and the deterministic local `HS256` verifier; custom verifiers via the
  exported `SignatureVerifier` interface
- offline Receipt counter-signature verification by historical or active `kid`
- offline, fail-closed issuer-status verification
- signed exact-action approval verification
- transparency-log checkpoint, inclusion and consistency verification
- stdlib HTTP protected-endpoint example

The verifier is stateless. It does not enforce single use: record the
proof's `pccb_id` / `nonce` in your replay store, and refuse a second use,
before performing the side effect.

## Quickstart

```go
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Actenon/sdk-go/verifier"
)

func main() {
	intentJSON, _ := os.ReadFile("action_intent.json")
	pccbJSON, _ := os.ReadFile("pccb.json")
	issuerJWK, _ := os.ReadFile("public_key.jwk.json") // the issuer's Ed25519 public key

	signatures, err := verifier.NewEd25519VerifierFromJWKs(issuerJWK)
	if err != nil {
		panic(err)
	}
	v := verifier.NewVerifier(signatures) // clock skew tolerance defaults to zero

	verified, err := v.VerifyJSON(intentJSON, pccbJSON, verifier.VerificationContext{
		RequestID:         "req-123",
		Audience:          verifier.AudienceRef{Type: "service", ID: "actenon-permit-gateway"},
		Now:               time.Now(),
		ScopeCapabilities: []string{"payment.refund"},
	})
	var refusal *verifier.VerificationError
	if errors.As(err, &refusal) {
		fmt.Println("refused:", refusal.Code, refusal.Message) // e.g. ACTION_MISMATCH
		return
	}
	if err != nil {
		panic(err)
	}
	fmt.Println("verified:", verified.Intent.Action.Name, "on", verified.Intent.Target.ResourceID)
}
```

This quickstart is compiled and run by `go test` as
[`ExampleVerifier_VerifyJSON`](verifier/example_test.go), against a proof
minted through actenon-permit. For local proofs signed with the public
development key use `verifier.BuildLocalProofVerifier()` instead.

See [`examples/http-protected-endpoint/`](examples/http-protected-endpoint/) for a complete stdlib HTTP server example.


## The Actenon ecosystem

<!-- ECOSYSTEM-TABLE:START -->
| Repository | Role | Depends on | Packages |
|---|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | — | `actenon-protocol` (PyPI) · `@actenon/protocol-types` (npm) |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` | `actenon-kernel` (PyPI) |
| **`actenon-permit`** | The developer on-ramp and authority broker | `actenon-kernel`, `actenon-protocol` | `actenon-permit` (PyPI) · `@actenon/sdk` (npm) |
| **`actenon-scan`** | The independent static-analysis scanner | — | `actenon-scan` (PyPI) |
| **`sdk-go`** ← you are here | Go verifier SDK | `actenon-protocol` | `github.com/Actenon/sdk-go` (v1.0.0) |
| **`sdk-rust`** | Rust verifier SDK | `actenon-protocol` | `cargo add --git` (crates.io pending) |

**Optional:** [`actenon-cloud`](https://github.com/Actenon/actenon-cloud) — a managed control plane (source-available; see its LICENSE). Not required by any component above; every capability in this ecosystem works without it.
<!-- ECOSYSTEM-TABLE:END -->

## Conformance

`go test ./...` runs, from [`fixtures/`](fixtures/):

- the Kernel's `verifier_sdk_v1` (16 cases), `canonicalization_strict_v1`,
  `receipt_countersignature_v1`, `transparency_log_v1` and
  `trust_artifacts_v1` vectors, copied byte-for-byte (they match the
  Kernel's `conformance/vector-lock.json`);
- `kernel_interop_v1`: 347 proof and 21 trust-artifact differential cases
  minted and decided by the Python reference verifier (see its README);
- `permit_interop_v1`: real proofs minted through actenon-permit.

See [CONFORMANCE.md](https://github.com/Actenon/actenon-protocol/blob/main/CONFORMANCE.md) for the ecosystem-wide map.

## License

Apache-2.0 — see [LICENSE](LICENSE).
