# Go canonical compatibility repair — source candidate

Base Go: `12d27356935c7081c36c0b918fda7f5029c14529`.
Normative Protocol: `8e5bc9e342f694767508bae9a392749c6a8df2cc`.
Corresponding repaired Kernel candidate: `4bae9252666a71361be4374316dd151b924815a8` (PR #48, unmerged).

`before-depth.log` freezes the actual base SDK accepting Protocol's invalid
depth-33 vector. Canonical signing depth is now 32 (root zero), distinct from
the transport envelope limit. Both accepted canonicalization labels use this
same restriction.

All original fixtures remain byte-identical. `full-before-legacy-expectation-correction.log`
preserves the failures caused by older Kernel fixtures claiming 128-level
acceptance. The additive `legacy-expectation-correction.json` records the exact
two old signed cases that now must refuse. The old generated max-depth case
also must refuse; new regressions prove the real 32/33 boundary. This is an
explicit correction to a contradictory contract, not a widening or a skipped test.

The frozen 26-case raw corpus carries exact input bytes/hashes and Protocol
expected decisions/canonical bytes/hashes. Go's strict decoder and canonicalizer
produce 14 ACCEPT and 12 REFUSE with zero mismatches. Results are in
`raw-corpus-final.json`. These are canonical-wire checks, not every whole-proof
negative gate or a claim of effect-protected execution.

Validation on this candidate:

- `go test -race -count=1 ./...`: passed; full output `full-final.log`.
- `go vet ./...` and `go build ./...`: exit zero.
- `gofmt` on changed files: clean.
- To regenerate per-case results: `ACTENON_PARITY_RESULTS="$PWD/results.json" go test -count=1 -run TestProtocolRawCanonicalCorpus ./verifier`.

No merge, tag or publication is performed. Vendored old Kernel locks/pins remain
historical fixture provenance, not an assertion that that older Kernel has the
new depth correction. Original failures and earlier successful logs are retained.
