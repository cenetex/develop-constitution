# Develop Constitution 1.0.0

> Status: **PROPOSED**. This document grants no authority until independently ratified and activated.

## Governing invariant

A malicious, compromised, or incompetent worker may produce bad code, but cannot escape its task boundary, obtain ambient authority, falsify acceptance evidence, alter governance, or publish a change.

Autonomy is earned per capability, repository, and risk class. No system may promote itself.

## Authority model

Lifecycle: `queued → admitted → leased → running → verifying → review → merge-ready → merged`. Terminal states: `merged`, `failed`, `cancelled`, `expired`.

| Role | Principal kinds | Eligible capabilities | Absolute denials |
|---|---|---|---|
| `control_plane` | service, process | repository.read, task.admit, lease.manage, capability.grant, audit.append | candidate.execute, governance.approve, governance.activate, worker.self_promote |
| `human_owner` | human | governance.propose, governance.approve, break_glass.invoke | worker.self_promote |
| `merge_controller` | service, process | github.merge, audit.append | candidate.execute, github.pull_request.review, governance.approve, governance.activate |
| `platform_administrator` | human | github.repository.settings, deployment.execute, governance.activate | worker.self_promote |
| `publication_broker` | service, process | github.push, github.pull_request.create, audit.append | candidate.execute, github.pull_request.review, github.merge, governance.approve, governance.activate |
| `reviewer` | human | repository.read, github.pull_request.review | worker.self_promote |
| `security_custodian` | human | governance.approve, github.pull_request.review | worker.self_promote |
| `verifier` | service, process | repository.read, candidate.execute, evidence.attest, audit.append | github.push, github.merge, governance.approve, governance.activate |
| `worker` | process | repository.read, task_clone.write, candidate.execute, git.commit, governance.propose | credential.consume, github.push, github.pull_request.create, github.pull_request.review, github.merge, github.repository.settings, deployment.execute, governance.approve, governance.activate, worker.self_promote, break_glass.invoke |

Role-separation constraints are normative in the machine source and apply at their declared scope.

## Normative clauses

| Clause | Requirement | Owner | Controls / tests |
|---|---|---|---|
| `C-001` Supremacy and fail-closed operation | **MUST** — When policy, enforcement, evidence, or identity is missing, ambiguous, stale, or invalid, the more restrictive decision applies. | `security_custodian` | policy-validation; ADV-UNKNOWN-DENY |
| `C-002` Worker credential boundary | **MUST_NOT** — A worker must never receive credentials, the control-plane environment, signing material, or an ambient external capability. | `security_custodian` | worker-identity-boundary, default-deny-runtime; ADV-NO-WORKER-CREDENTIALS |
| `C-003` Workspace isolation | **MUST_NOT** — A worker must not write canonical repositories, shared Git metadata, governance, main, repository settings, another task, or control-plane state. | `platform_administrator` | worker-identity-boundary, private-task-clone; ADV-NO-CANONICAL-WRITE |
| `C-004` Terminal task lifecycle | **MUST** — Expired, failed, cancelled, and merged tasks are terminal; retries require a new task identity, clone, lease, and capability set. | `human_owner` | lease-revocation; ADV-TERMINAL-LEASE |
| `C-005` Independent evidence | **MUST** — Publication, merge, and deployment require independently generated evidence bound to the exact base SHA, head SHA, environment digest, and constitution digest. | `security_custodian` | independent-verification, sha-bound-publication; ADV-STALE-SHA-DENY |
| `C-006` Separation of duties | **MUST_NOT** — A producing worker must not verify, review, approve, publish, merge, deploy, or activate its own work. | `security_custodian` | independent-verification, repository-rules; ADV-NO-SELF-REVIEW |
| `C-007` Capability scope | **MUST** — Every non-human capability is explicit, narrowly bound, time-limited, revocable, audited, and denied when any required binding is absent. | `security_custodian` | capability-broker, append-only-audit; ADV-INCOMPLETE-GRANT-DENY |
| `C-008` Publication boundary | **MUST_NOT** — Workers must never push, open pull requests, merge, deploy, change repository settings, or hold credentials that permit those actions. | `platform_administrator` | capability-broker, sha-bound-publication, serialized-merge; ADV-WORKER-PUBLICATION-DENY |
| `C-009` No self-promotion | **MUST_NOT** — No agent, service, control plane, or worker may approve or activate an increase in its own authority. | `human_owner` | maturity-ratification; ADV-NO-SELF-PROMOTION |
| `C-010` Constitutional amendment | **MUST** — An amendment is evaluated under the previously active constitution and binds its base manifest digest, candidate digest, independent review, human approvals, and activation delay. | `security_custodian` | constitutional-release, maturity-ratification; ADV-PREDECESSOR-GOVERNS |
| `C-011` Audit integrity | **MUST** — Every privileged action and lifecycle transition is linked to a task, change, or incident and appended to tamper-evident audit history; audit failure denies the action. | `security_custodian` | append-only-audit; ADV-AUDIT-GAP-DENY |
| `C-012` Human-only break glass | **MUST_NOT** — Break-glass authority must not be delegated to a worker and cannot waive another unwaivable clause. | `security_custodian` | break-glass-control; ADV-BREAK-GLASS-HUMAN-ONLY |

Every v1 clause is unwaivable. A violation denies the action and demotes the affected scope to L0.

## Risk classes

| Risk | Meaning | Automated publication floor |
|---|---|---|
| **R0 — non-executable** | Inert prose and assets, excluding governance and generated artifacts. | `L3` |
| **R1 — ordinary-code** | Bounded application code without security, deployment, persistence, dependency, or data-boundary impact. | `L3` |
| **R2 — sensitive** | Dependencies, network surfaces, persistence, migrations, privacy, cryptography, or infrastructure. | `L4` |
| **R3 — constitutional** | Control plane, identity, credentials, CI, sandboxing, governance, evidence, repository settings, merge, or deployment authority. | `never` |

Candidate mutation and automated publication are separate ceilings. The stricter applicable rule wins.

## Capability maturity

| Level | Authority | Mutation ceiling | Non-human capability ceiling | Promotion floor |
|---|---|---|---|---|
| **L0 — quarantine** | Read-only analysis and disposable experiments; a human mediates every publication. | `none` | repository.read | 0 tasks / 0 days / 2 human approvals |
| **L1 — contained-worker** | A worker may edit, execute tests, and produce a candidate commit only in a private task clone without network or credentials. | `R1` | repository.read, task_clone.write, candidate.execute, git.commit, task.admit, lease.manage, capability.grant, evidence.attest, audit.append | 0 tasks / 0 days / 2 human approvals |
| **L2 — supervised-delivery** | The publication broker may push and open draft pull requests for R0 and R1; humans approve every merge. | `R1` | repository.read, task_clone.write, candidate.execute, git.commit, task.admit, lease.manage, capability.grant, evidence.attest, audit.append, github.push, github.pull_request.create | 30 tasks / 30 days / 2 human approvals |
| **L3 — bounded-autonomy** | R0 and R1 may auto-merge after independent verification and review; R2 and R3 remain human-approved. | `R1` | repository.read, task_clone.write, candidate.execute, git.commit, task.admit, lease.manage, capability.grant, evidence.attest, audit.append, github.push, github.pull_request.create, github.merge | 100 tasks / 60 days / 2 human approvals |
| **L4 — production-autonomy** | Approved R2 operations and non-critical deployments may be automated; R3 remains human-only. | `R2` | repository.read, task_clone.write, candidate.execute, git.commit, task.admit, lease.manage, capability.grant, evidence.attest, audit.append, network.egress, credential.consume, github.push, github.pull_request.create, github.merge, deployment.execute | 250 tasks / 180 days / 2 human approvals |

Higher maturity retains every lower-level control. Promotions are scoped to an exact control-plane digest, repository, risk class, and capability.

## Controls and adversarial evidence

| Control | Owner | Enforcement point | Failure |
|---|---|---|---|
| `append-only-audit` | `security_custodian` | every-privileged-action | `deny` |
| `break-glass-control` | `security_custodian` | emergency-access | `deny` |
| `capability-broker` | `control_plane` | privileged-operation | `deny` |
| `constitutional-release` | `platform_administrator` | policy-activation | `deny` |
| `default-deny-runtime` | `control_plane` | sandbox | `deny` |
| `deployment-rollback` | `platform_administrator` | deployment | `deny` |
| `independent-verification` | `security_custodian` | verification | `deny` |
| `lease-revocation` | `control_plane` | supervisor | `terminate` |
| `maturity-ratification` | `security_custodian` | authority-activation | `deny` |
| `policy-validation` | `security_custodian` | admission | `deny` |
| `private-task-clone` | `control_plane` | task-launch | `deny` |
| `repository-rules` | `platform_administrator` | github | `deny` |
| `serialized-merge` | `merge_controller` | merge | `deny` |
| `sha-bound-publication` | `publication_broker` | publication | `deny` |
| `signed-provenance` | `security_custodian` | release | `deny` |
| `worker-identity-boundary` | `platform_administrator` | kernel | `deny` |

| Test | Tier | Runner |
|---|---|---|
| `ADV-AUDIT-GAP-DENY` | `platform` | `external:agentd-boundary-suite` — An unavailable or unlinked audit sink blocks privileged action. |
| `ADV-BREAK-GLASS-HUMAN-ONLY` | `integration` | `external:agentd-integration-suite` — Break-glass requests by non-human principals are rejected. |
| `ADV-INCOMPLETE-GRANT-DENY` | `model` | `tests/test_constitution.py` — A capability with any missing exact binding is rejected. |
| `ADV-NO-CANONICAL-WRITE` | `platform` | `external:agentd-boundary-suite` — A worker cannot mutate canonical or shared Git state. |
| `ADV-NO-SELF-PROMOTION` | `integration` | `external:agentd-integration-suite` — A component cannot approve or activate its own authority increase. |
| `ADV-NO-SELF-REVIEW` | `integration` | `external:agentd-integration-suite` — The producing principal cannot verify or review its own task. |
| `ADV-NO-WORKER-CREDENTIALS` | `platform` | `external:agentd-boundary-suite` — A worker cannot observe broker or daemon credentials. |
| `ADV-PREDECESSOR-GOVERNS` | `model` | `tests/test_constitution.py` — Candidate amendment policy cannot govern its own ratification. |
| `ADV-STALE-SHA-DENY` | `integration` | `external:agentd-integration-suite` — Evidence and approval for another SHA are rejected. |
| `ADV-TERMINAL-LEASE` | `model` | `tests/test_constitution.py` — Terminal task states reject every subsequent transition. |
| `ADV-UNKNOWN-DENY` | `model` | `tests/test_constitution.py` — Unknown actions, risks, references, and fields are denied. |
| `ADV-WORKER-PUBLICATION-DENY` | `platform` | `external:agentd-boundary-suite` — A worker cannot receive an external publication capability. |

## Ratification

The machine-readable source is `constitution/v1/constitution.json`; this rendering is informative. The previous active constitution governs amendments, and a candidate cannot approve or activate itself.

Permission expansion requires at least 2 human approvals, independent security review, and a cooling period of 259200 seconds. Exceptions expire within 14400 seconds and cannot waive an unwaivable clause.

Candidate-controlled checks provide structural evidence only. Detached signatures, external verification, scoped control attestations, and a human installation ceremony are required for activation.
