# develop-constitution

This repository is the trust root for development under `~/develop`.

The workspace is a solo project operated by a human with AI developers. AI
developers are delegated tools, not independent approving authorities. Their
identity is recorded for attribution; scoped credentials and the effect of an
action define the safety boundary.

## Normal development

```text
request -> branch/worktree -> pull request -> checks -> merge -> deploy -> verify
```

- A clear user request authorizes the requested engineering work.
- Normal code changes use a branch and pull request.
- Parallel developers use separate worktrees.
- A developer may push, open or update a pull request, review it, merge it, and
  deploy it when the relevant checks pass.
- No issue, approval, label, hold period, evidence record, attestation, or
  special merge service is required.
- GitHub commits, pull requests, checks, and deployments are the audit trail.
- The human may pause, close, revert, or override any task.

## Human boundary

Ask once, immediately before an action that is irreversible or has a material
effect outside the repository. Examples include:

- deleting production data or applying a destructive migration;
- changing credentials, access, signing keys, or broad permissions;
- spending money or transferring assets;
- making a legal or public commitment;
- disabling recovery or security controls; or
- deploying a change that has no tested rollback path.

Editing a file is not high risk by itself. Risk follows the action and its
effect. Infrastructure and workflow changes may follow the normal path when
their deployment is reversible.

## Production

- Deploy previews and development environments automatically.
- Deploy production automatically when health checks and rollback are proven.
- Use one explicit human approval only when production impact is irreversible
  or rollback is not safe.
- On failure, roll back first and report the result. Do not create paperwork as
  a substitute for recovery.

## Retired systems

The following are not governance requirements:

- `agentd` leases, verifier images, evidence schemas, or publication brokers;
- bot or human approval ceremonies;
- protected-path approval commands;
- review and merge label state machines;
- merge hold periods or polling merge queues;
- mandatory issue intake, issue-quality forms, or backlog WIP gates.

The `cenetex/agent` runtime may still create branches and pull requests, run
checks, and report status. It must use native GitHub merge and deployment state
instead of maintaining a second governance control plane.

See `AGENTS.md` for the short workspace policy and
`DEVELOP_REPO_HYGIENE_CONTRACT.md` for repository hygiene.
