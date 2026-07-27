# Ratification and activation protocol

A Git commit, passing test, merged pull request, or version string is not a
constitutional activation.

## Candidate release

1. Open an issue describing the motivation, threat model, authority delta,
   migration, rollback, alternatives, and whether the change tightens,
   preserves, or expands authority.
2. Create a pull request against the previously active constitution.
3. Render `CONSTITUTION.md`, run every conformance test, and verify the candidate
   from a fresh checkout at the exact head SHA.
4. Build a release manifest conforming to
   `schemas/release-manifest-v1.schema.json`. It must bind the public source
   repository, exact source commit, file modes, and SHA-256 digest of every
   released file. The constitution document digest covers canonical JSON
   without the file's trailing newline; the file entry separately covers the
   exact installed bytes.
5. Hash the manifest with the declared
   `sorted-keys-utf8-no-whitespace-v1` encoding. This is a deliberately narrow
   byte format, not a claim of RFC 8785 compatibility. The manifest cannot
   contain its own digest.

## Human ratification

1. A security custodian who did not produce the candidate reviews its exact
   manifest digest.
2. Permission expansion requires two distinct human custodians, independent
   security review, and a 72-hour cooling period.
3. Each custodian creates a detached signature conforming to
   `schemas/signature-envelope-v1.schema.json`.
4. A verifier validates each signature against the externally installed active
   predecessor trust root, never a candidate `trust/root.json`. JSON fields
   claiming that a signature was verified are never sufficient.
5. Stale review, changed files, a changed manifest, an unknown key, an
   unavailable verifier, or an unmet threshold denies ratification.

The bootstrap trust root is intentionally `unratified` with no principals.
Until independent custodians and their public verification keys are added
through an out-of-band genesis ceremony, no release can activate. That ceremony
must bind the exact repository, post-merge source commit and tree, release
manifest, custodian keys, threshold, and target in a separately controlled
registry or verifier.

Each signature covers the UTF-8 bytes
`develop.cenetex/governance/v1\n` followed by the declared canonical encoding
of every envelope field except `signatures`. Cross-implementation positive and
negative test vectors are required before activation.

## Installation

1. A human platform administrator—not `agentd` and not a worker—verifies the
   manifest and signature threshold from a clean trusted environment.
2. The installer confirms the target workspace identity, current active digest,
   monotonic sequence, predecessor digest, ownership, filesystem ACLs, and
   rollback location.
3. Files are staged under the target filesystem, verified, made
   controller-owned and worker-read-only, then atomically activated.
4. An append-only activation event binds the previous digest, candidate digest,
   installer identity, target, timestamp, and verification evidence.
5. `agentd` remains suspended if deployed content, ownership, signatures, or
   activation history drift.

Squash merging creates a different commit from the reviewed pull-request head.
The merged `main` commit and tree must therefore be independently reverified
and used to build the release manifest; pull-request evidence alone cannot
authorize a release.

## Emergency changes

Emergency restrictions may take effect immediately because they only remove
authority. They expire after 72 hours unless ratified.

Break-glass cannot activate a permission expansion, delegate authority to a
worker, waive an unwaivable clause, or disable audit history.

## Non-activation checklist

Merging this proposal does not satisfy any item below. Activation remains
blocked until all are externally evidenced:

- independent custodians, public keys, cryptographic verification, and a
  controller-owned evidence registry;
- an exact complete release profile, post-merge manifest, and signed-byte test
  vectors;
- enforcement of activation effective time and predecessor sequence;
- current independent control attestations for every promoted scope;
- a no-follow installer that rejects special files, verifies staged bytes
  after placement, closes replacement races, activates atomically, and proves
  rollback;
- append-only activation history, drift detection, and automatic suspension on
  verification failure.
