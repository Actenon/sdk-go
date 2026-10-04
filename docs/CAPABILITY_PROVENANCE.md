# Capability provenance

Scan names a power. Permit signs it into a grant and one concrete proof capability. The Kernel checks that proof before the side effect. Airlock writes the receipt. This module is the Go verifier's view of that path: exact capabilities, `extensions.authority`, and the refusal codes the edge emits.

Wire `PROTOCOL_VERSION` is `1.2.0` (`verifier.ProtocolVersion`). Package guidance is actenon-protocol **1.5.0**, pin:

```text
d03236403ea160b3b63f0e6019468f380b2dfc6c
```

That is the head of [actenon-protocol#21](https://github.com/Actenon/actenon-protocol/pull/21). The implementation commit is `9cc6ded0e0fc35ee98a8fc419b47d80a251581e3`; the later commit records this pin. Either commit is the same contract. Do not stay on PyPI `actenon-protocol` 1.4.0 for it: 1.4.0 aliases `SCOPE_CAPABILITY_MISMATCH` and `SCOPE_MODE_INVALID` to `PARAMETER_MISMATCH`, and `ExecutionProof` there has no `extensions` object. This module is not published.

## What this verifier does

- `ResolveAlias("SCOPE_CAPABILITY_MISMATCH")` and `ResolveAlias("SCOPE_MODE_INVALID")` return those codes. They do not return `PARAMETER_MISMATCH`.
- Public `DisclosedCode` for both, and for `ISSUER_UNTRUSTED` and `SIGNATURE_INVALID`, is `PROOF_INVALID`. `InternalCode` under `DisclosureTrusted` keeps the specific code.
- `ScopeCapabilitiesForMint` refuses an empty slice and any capability containing `*`, `?`, `[`, or `]`. The attempted action and `*` are not substitutes.
- `ScopeCapabilitiesForVerification(nil, capability)` is exactly that one capability. An empty slice stays empty and authorises nothing. `Verify` does not apply the nil substitution: `VerificationContext.ScopeCapabilities` is the edge declaration, and nil or empty refuses with `SCOPE_CAPABILITY_MISMATCH`.
- `CapabilityInScope` is exact membership. A glob does not match, including a glob equal to itself.
- `UnauthenticatedRefusal` is `ISSUER_UNTRUSTED` with no trust root and `SIGNATURE_INVALID` when the signature does not verify. Token length is not an input. `NewVerifier(nil)` refuses every proof with `ISSUER_UNTRUSTED`.
- `AuthorityExtensionObject` / `ParseAuthorityExtension` is the signed `extensions.authority` object `{issuer, grant_id, revocable}`. A present but unusable object is `INVALID_PCCB`. This verifier does not consult a revocation source. When `Revocable` is true, the caller must do that before the side effect; a source that cannot be read fails closed (`AUTHORITY_REVOKED`).

`action.name` and `action.capability` stay distinct fields on the Kernel PCCB. The portable local proof uses both, and they are not the same string. A glob is still not a capability.

## Dependent pins

| Repo | Pin with protocol `d032364` | Note |
|---|---|---|
| actenon-permit | `e368dca24af6f316590ce5fd1a0e83a9aebee924` ([#23](https://github.com/Actenon/actenon-permit/pull/23)) | Signs authority only; one concrete capability. |
| actenon-kernel | `fb3a38936f7dade4d25beb91402081eb16c31bfc` ([#43](https://github.com/Actenon/actenon-kernel/pull/43)) | Forged tokens refuse. `ActenonGate(..., capabilities=, revocation_checker=)`. |
| actenon-scan | `b7c5951e81acb5c5a84aa11947b76065f47bb452` ([#101](https://github.com/Actenon/actenon-scan/pull/101)) | Names capabilities. This module does not parse Scan. |
| actenon-airlock | `d9b1ef11fed698d05fd53a27e674125941b69be6` ([#3](https://github.com/Actenon/actenon-airlock/pull/3)) | Replaces its protocol pin with `d03236403ea160b3b63f0e6019468f380b2dfc6c`. |
