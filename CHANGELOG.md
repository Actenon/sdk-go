# Changelog

## [v1.1.0]

### Security (actenon-protocol `protocol/13-edge-binding.md`)

- **E1–E4.** The verifier enforces the protected edge's own declarations:
  - the intent's capability must be in `ScopeCapabilities` (exact match; an
    empty declaration refuses);
  - every edge `ParameterConstraints` member must be signed into the proof;
  - the signed target must satisfy a `ResourceSelectors` entry;
  - only `single_use: true` proofs verify.
  v1.0.0 accepted these context fields and ignored them.
- **E5.** `WithRevocationChecker` consults the revocation source for a proof
  whose signed `extensions.authority` is revocable. Revoked, unknown or
  unreachable authority, or no source at all, refuses with
  `AUTHORITY_REVOKED`. Proofs minted by actenon-permit 2.0 are revocable.
- New errors: `ErrParameterMismatch`, `ErrAuthorityRevoked`.
- `ParameterConstraints` values must be JSON-exact. A `float64` declaration
  is refused because its source text cannot be checked; decode JSON
  configuration with `json.Decoder.UseNumber`.

### Fixed

- Timestamps with a `,` before the fractional seconds (for example
  `2026-01-01T12:00:00,5Z`) are refused with `INVALID_TIMESTAMP`. Go's
  `time.Parse(time.RFC3339, ...)` accepts them; RFC 3339 and the Actenon
  reference do not (actenon-kernel north-star `corpus-addendum-timestamp-grammar`).
  Applies to every timestamp the SDK reads.
- CI: the test-vector path that failed on `main` and on the v1.0.0 tag.

### Conformance

- The kernel's shared vectors are vendored byte-identically and pinned to
  kernel `b1b175d` (`fixtures/KERNEL_PIN`), Conformance 1.1.0.

## [v1.0.0]

Initial release.
