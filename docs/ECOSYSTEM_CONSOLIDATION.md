# Go verifier consolidation evidence

This candidate preserves both frozen histories as merge parents:

- Production/release candidate: `0198ef597e67a31de778c38628d10d99a5c60d8e`.
- Capability-provenance candidate: `2646b80be52c5d305f493b789702cc976947119b`.

The production parser, canonicalisation profiles, signature-first verification, exact E1–E5 edge checks and revocation source requirement remain. Wire-1.2 capability helpers and authority metadata are added. A revocable proof without an authoritative checker remains a refusal; parsing `revocable=true` does not authorise execution.

The candidate vendors Kernel core `c6564b90be8bdb7a871c176df5673d5b3a4ab5fc`, the first unified #41+#43 commit. All previous vector records are retained. Six additional counterexamples reject mixed wildcard scopes and incomplete signed authority references. `fixtures/kernel_vector_lock.json` is identical to the pinned Kernel lock; unlocked fixtures are compared separately in CI.

Local race tests, vet, build and format checks pass. CI must also pass against the minimum supported compiler and current stable. No package or tag is published by this consolidation. Existing release evidence remains historical evidence for its original commits; a new coordinated release requires its own exact commit and artifact freeze.
