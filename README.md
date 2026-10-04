# Actenon Go Verifier SDK

Minimal protected-endpoint verifier SDK for Go, aligned to the Actenon Kernel's public `action_intent` and `pccb` contracts and to protocol wire `1.2.0` (actenon-protocol 1.5.0).

This package is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

## Install

```bash
go get github.com/Actenon/sdk-go@v1.0.0
```

`v1.0.0` is the published module. Capability provenance for wire `1.2.0` is in this repository and is not a release. Pin the protocol contract at `d03236403ea160b3b63f0e6019468f380b2dfc6c` ([actenon-protocol#21](https://github.com/Actenon/actenon-protocol/pull/21)). See [docs/CAPABILITY_PROVENANCE.md](docs/CAPABILITY_PROVENANCE.md).

## Scope

- `action_intent` v1 and `pccb` v1 Go data structures
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- exact edge allow-list (`VerificationContext.ScopeCapabilities`). An empty list authorises nothing. Globs (`*`, `?`, `[`, `]`) are not capabilities and are not expanded to the attempted action
- `SCOPE_CAPABILITY_MISMATCH` and `SCOPE_MODE_INVALID` as canonical refusal codes. Public disclosure is `PROOF_INVALID`. They are not aliases of `PARAMETER_MISMATCH`
- single-use proofs: `scope.single_use` other than `true` is `SCOPE_MODE_INVALID`
- no configured trust root is `ISSUER_UNTRUSTED`; a forged signature is `SIGNATURE_INVALID`. Token length, a `v1.` prefix, and well-formed JSON are not acceptance
- optional signed `extensions.authority` grant reference (`issuer`, `grant_id`, `revocable`)
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` verifier
- custom signature verification via the exported `SignatureVerifier` interface
- offline Receipt counter-signature verification by historical or active `kid`
- offline, fail-closed issuer-status verification
- signed exact-action approval verification
- stdlib HTTP protected-endpoint example

## Quickstart

```go
package main

import (
    "fmt"
    "time"

    "github.com/Actenon/sdk-go/verifier"
)

func main() {
    sdk := verifier.NewVerifier(verifier.BuildLocalProofVerifier())
    result, err := sdk.Verify(intent, pccb, verifier.VerificationContext{
        RequestID:         "req_001",
        Audience:          verifier.AudienceRef{Type: "service", ID: "portable-hello-world-endpoint"},
        Now:               time.Now().UTC(), // must fall inside the proof window
        ScopeCapabilities: []string{"protected_resource.read"},
    })
    if err != nil {
        // Trusted detail. Public callers should use verifier.DisclosedCode.
        fmt.Println("refused:", err)
        return
    }
    fmt.Println("verified:", result.Intent.Action.Capability, result.PCCB.PCCBID)
}
```

See [`examples/http-protected-endpoint/`](examples/http-protected-endpoint/) for a complete stdlib HTTP server example.


## The Actenon ecosystem

<!-- ECOSYSTEM-TABLE:START -->
| Repository | Role | Depends on | Packages |
|---|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | — | `actenon-protocol` (PyPI) · `@actenon/protocol-types` (npm) |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` | `actenon-kernel` (PyPI) |
| **`actenon-permit`** | The developer on-ramp and authority broker | `actenon-kernel`, `actenon-protocol` | `actenon-permit` (PyPI) · `@actenon/sdk` (npm) |
| **`actenon-scan`** | The independent static-analysis scanner | — | `actenon-scan` (PyPI) |
| **`sdk-go`** ← you are here | Go verifier SDK — protected-endpoint proof verification in Go | `actenon-protocol` | [repo](https://github.com/Actenon/sdk-go) |
| **`sdk-rust`** | Rust verifier SDK — protected-endpoint proof verification in Rust | `actenon-protocol` | [repo](https://github.com/Actenon/sdk-rust) |

**Optional:** `actenon-cloud` — a managed control plane (private repository, not publicly available). Not required by any component above; every capability in this ecosystem works without it.
<!-- ECOSYSTEM-TABLE:END -->

## Conformance

Every Actenon SDK runs against the same 51 conformance vectors in the Kernel. See [CONFORMANCE.md](https://github.com/Actenon/actenon-protocol/blob/main/CONFORMANCE.md) for the canonical map.

## License

Apache-2.0 — see [LICENSE](LICENSE).
