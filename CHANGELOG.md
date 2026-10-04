# Changelog

## Unreleased

Not published. The module tag remains `v1.0.0`.

### Security

- **Edge allow-list.** `Verify` refuses when the intent capability is not an exact member of `VerificationContext.ScopeCapabilities` (`SCOPE_CAPABILITY_MISMATCH`). An empty list and any glob (`*`, `?`, `[`, `]`) authorise nothing. They are not replaced by the attempted action or by `*`.
- **No trust root is not a signature failure.** `NewVerifier(nil)` refuses with `ISSUER_UNTRUSTED`. A forged signature is `SIGNATURE_INVALID`. A long string, a `v1.` prefix, or well-formed JSON is not a proof.
- **Single-use.** A proof whose signed `scope.single_use` is not `true` is `SCOPE_MODE_INVALID`.

### Added

- Wire `PROTOCOL_VERSION` `1.2.0`, aligned to actenon-protocol 1.5.0 pin `d03236403ea160b3b63f0e6019468f380b2dfc6c`.
- `SCOPE_CAPABILITY_MISMATCH` and `SCOPE_MODE_INVALID` stay canonical under `ResolveAlias`. Public disclosure is `PROOF_INVALID`.
- `extensions.authority` parse and build helpers. A present but unusable authority object is `INVALID_PCCB`.

### Fixed

- Conformance fixtures are vendored under `fixtures/`. Tests no longer look for a Kernel checkout outside this repository.
- The ecosystem table matches `ecosystem.yaml`: Go and Rust role text, repository links, and `actenon-cloud` named without a public URL.
