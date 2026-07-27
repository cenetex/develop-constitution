# Develop Constitution

This repository is the candidate constitutional source for governed development
originating from `~/develop`. It is not yet a trust root.

The initial proposal deliberately grants no autonomous external authority. Its
declared posture is **L0 — quarantine** because worker isolation, independent
signed evidence, and repository-wide enforcement have not yet been proven.

## Source hierarchy

1. `constitution/v1/constitution.json` is the normative machine-readable source.
2. `CONSTITUTION.md` is an informative rendering generated from that source.
3. `constitution/v1/risk-rules.json` classifies paths and semantic changes.
4. `deployments/develop/posture.json` keeps the workspace baseline at L0 and may
   add only exact, externally ratified `{control plane, repository, risk,
   capability}` scopes.
5. `trust/root.json` identifies ratification keys and thresholds. It is
   intentionally unratified and contains no invented principals.

`agentd` may consume a signed constitutional release. It cannot author,
approve, or activate one.

Closed artifact schemas are included by
[issue #3](https://github.com/cenetex/develop-constitution/issues/3). Candidate
validation and CI are included by
[issue #2](https://github.com/cenetex/develop-constitution/issues/2). Passing
them is model checking, not ratification evidence. The base-revision validator
is defense in depth; only a separately controlled verifier may bind the active
predecessor.

## Local verification

```console
python3 tools/constitutionctl.py lint --root .
python3 tools/constitutionctl.py render --root . --check
python3 -m unittest discover -s tests -v
python3 -m compileall -q tools tests
git diff --check
```

## Status

Version 1.0.0 is a proposal under
[issue #1](https://github.com/cenetex/develop-constitution/issues/1). It is not
ratified, signed, activated, or deployed. Repository review settings are an
additional gate, not constitutional evidence; authoritative settings
attestation must come from outside the candidate branch.

See [activation protocol](docs/ACTIVATION.md) before treating any release as
authoritative.
