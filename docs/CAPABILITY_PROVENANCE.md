# Capability provenance

Scan names a power. Permit signs it into a grant and one concrete proof capability. The Kernel checks that proof before the side effect. Airlock writes the receipt. This module is the Go verifier's view of that path: exact capabilities, `extensions.authority`, and the refusal codes the edge emits.

Wire `PROTOCOL_VERSION` is `1.2.0` (`verifier.ProtocolVersion`). The shared Protocol 1.5.0 implementation is merged at `eba78d3dbd41a0b6c86166ece0f34cc8d7b7a002` ([#21](https://github.com/Actenon/actenon-protocol/pull/21)). This module is a source candidate, not a published release. See [consolidation evidence](ECOSYSTEM_CONSOLIDATION.md) for the unified Kernel fixture pin and preserved parents.

## What this verifier does

- `ResolveAlias("SCOPE_CAPABILITY_MISMATCH")` and `ResolveAlias("SCOPE_MODE_INVALID")` return those codes. They do not return `PARAMETER_MISMATCH`.
- Public `DisclosedCode` for both, and for `ISSUER_UNTRUSTED` and `SIGNATURE_INVALID`, is `PROOF_INVALID`. `InternalCode` under `DisclosureTrusted` keeps the specific code.
- `ScopeCapabilitiesForMint` refuses an empty slice and any capability containing `*`, `?`, `[`, or `]`. The attempted action and `*` are not substitutes.
- `ScopeCapabilitiesForVerification(nil, capability)` is exactly that one capability. An empty slice stays empty and authorises nothing. `Verify` does not apply the nil substitution: `VerificationContext.ScopeCapabilities` is the edge declaration, and nil or empty refuses with `SCOPE_CAPABILITY_MISMATCH`.
- `CapabilityInScope` is exact membership. A glob does not match, including a glob equal to itself.
- `UnauthenticatedRefusal` is `ISSUER_UNTRUSTED` with no trust root and `SIGNATURE_INVALID` when the signature does not verify. Token length is not an input. `NewVerifier(nil)` refuses every proof with `ISSUER_UNTRUSTED`.
- `AuthorityExtensionObject` / `ParseAuthorityExtension` is the signed `extensions.authority` object `{issuer, grant_id, revocable}`. A present but unusable object is `AUTHORITY_REVOKED`. `WithRevocationChecker` consults the configured revocation source before returning a verified request. A revocable proof without a source, or one whose source errors, panics or refuses, fails closed with `AUTHORITY_REVOKED`. Parsing metadata alone is never enough.

`action.name` and `action.capability` stay distinct fields on the Kernel PCCB. The portable local proof uses both, and they are not the same string. A glob is still not a capability.

## Canonical candidate

The unified candidate combines PR #2's production verifier, signature-first validation,
strict raw JSON, timestamps, edge parameter/resource binding and revocation with PR #3's
wire-1.2 capability helpers, authority metadata and disclosure helpers. Both parents remain
in history. `fixtures/KERNEL_PIN` is the sole vector-source pin; the Kernel pins this SDK in
`sdk/standalone-sdk-pins.json` after its own fixtures and this suite pass.
