# Develop repository hygiene

This is the baseline for repositories under `~/develop`.

## Working state

- Preserve existing changes. They belong to their current owner.
- Use a separate worktree for parallel work.
- Keep commits and pull requests focused enough to understand and revert.
- Push completed work and open a pull request. Do not abandon finished changes
  in a local checkout.
- Remove temporary worktrees after their pull requests merge or close.

## Verification

- Run the smallest useful check first.
- Run broader checks when the change or release risk justifies them.
- Report checks that could not run and the exact missing dependency or access.
- A known failing broad suite is not evidence that a change failed; compare the
  changed behavior with the current base.

## Runtime data

- Do not commit credentials, local databases, caches, logs, sessions, build
  output, or other runtime state unless it is intentional product data.
- Ignore generated and local-only artifacts.
- Use scoped, short-lived credentials and secret stores.

## Pull requests

A pull request needs only:

- the outcome;
- the relevant checks; and
- a rollback note when production recovery is not obvious.

Issues, labels, approval reviews, evidence bundles, and hand-written checklists
are optional. GitHub already records authorship, commits, checks, merge state,
and deployments.
