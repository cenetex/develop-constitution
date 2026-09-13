# Shared interoperability contracts

Status: adopted 2026-09-13.
Decision record: [cenetex/develop-constitution#8](https://github.com/cenetex/develop-constitution/issues/8).

Use simple English.

## Why

Several repositories under `~/develop` independently built the same core
shape: an append-only, totally ordered event log, a deterministic kernel, an
epoch marker, and replay as a first-class guarantee. That is a good sign, but
it means every pair of systems needs a bespoke adapter.

`anima-research/eidoverse-worlds` adds exactly two layers the workspace lacks:
a free (CC0) wire contract for shared worlds, and an agent-native identity and
protocol stack (`aid1` + MCPL).

This document adopts the contracts, not the reference implementation. The
contracts are small, testable, and already proven across two independent
codebases.

## The three layers

### 1. Log contract

A shared world is an append-only, totally ordered log of intent entries.
There is no scene file; folding the log yields the world.

- Entry shape: `{seq, ts, actor, verb, args}`, serialized as JSON Lines.
  `seq` is dense, starts at 0, and is never renumbered.
- **Fold is total.** No entry may error a fold. Malformed or unknown entries
  shape nothing, and the log keeps them.
- **Unknown verbs and component types are preserved, not dropped.** This is
  the whole forward-compatibility story.
- **The door is closed; the log is open.** Ingestion refuses verbs outside a
  declared vocabulary, while the log tolerates unknown entries forever.
- Extension lanes, in order of preference:
  - state-shaped: a blind `comp {id, type, data}` bag;
  - event-shaped: `use {id, action}` with free-form action strings;
  - semantic: uploaded scripts bound as behaviors.
- Components carry parameters, never code, and nothing writes a component
  per-frame. Components change only through logged entries.
- Continuous state (avatar pose, voice, gaze, typing) lives on a separate
  ephemeral **presence plane** and is never persisted.
- Scheduled behavior is stored as a **function of time** (`f(params, t)`),
  not as per-tick entries. Every reader derives the same value at its own
  `now`.
- **Epochs.** A log names its dialect and version in `genesis`; an `epoch`
  entry transitions it. Old epochs remain carried and replay under the law
  they were authored under. Changing a fold rule is an explicit, logged
  transition, not a silent upgrade.
- **Replay never re-executes behaviors or scripts.** It folds the entries
  they emitted, so scripts may use randomness and wall-clock freely.

Free spec (CC0 1.0): `spec/PROTOCOL.md`, `spec/PROTOCOL_v2.md`,
`spec/EIDO-URIS.md` in `anima-research/eidoverse-worlds`.

### 2. Identity — `aid1`

One keypair per participant, minted once at the home node and verified
**offline** by every audience. Names are durable and unique at the home node.
Capabilities are granted per audience.

- A credential never goes into agent context when the host can hold the key
  and mint a fresh token per audience.
- Platform handles and display names are presentation. The keypair is the
  identity.
- An agent is not a username on a platform. It is a keypair that happens to
  manifest on many platforms at once.

### 3. Protocol — MCPL

Agents participate through MCPL:

- intent verbs in, tiered perception out (summary first, drill down on
  demand, never force a full dump);
- push wakes and channels for hosts that support them;
- a polling fallback (`look` / `catch_up`) for plain-MCP hosts;
- grants that name standing credentials, so a raw token is never passed by
  hand.

## Rules

- **Adopt the contracts, not the code.** The eidoverse spec is CC0; its
  reference implementation is AGPL. Implement the spec. Do not vendor AGPL
  code into other projects.
- **Do not unify runtimes, renderers, or UIs.** Only the contracts move.
  CosyWorld keeps its C kernel and card surface; Signal keeps its C11
  renderer; Swarm keeps its platform adapters.
- **Disagree in public.** Where a repository cannot follow a rule, record the
  reason in that repository and link it here. A silent divergence is a bug in
  this document.
- **Migrate by epoch.** Introduce the contracts with an explicit version
  marker so existing logs, journals, and saves keep replaying unchanged.

## Adoption

| Repository | Work |
|---|---|
| `cenetex/cosyworld` | [#1007](https://github.com/cenetex/cosyworld/issues/1007) fold-totality, [#1008](https://github.com/cenetex/cosyworld/issues/1008) presence plane, [#1009](https://github.com/cenetex/cosyworld/issues/1009) component bag, [#1010](https://github.com/cenetex/cosyworld/issues/1010) epochs, [#1011](https://github.com/cenetex/cosyworld/issues/1011) MCPL door, [#1012](https://github.com/cenetex/cosyworld/issues/1012) `aid1` identity, [#1013](https://github.com/cenetex/cosyworld/issues/1013) consent/audibility |
| `cenetex/signal` | [#752](https://github.com/cenetex/signal/issues/752) carried-law epochs, [#753](https://github.com/cenetex/signal/issues/753) `aid1` actor identity |
| `cenetex/swarm` | [#1928](https://github.com/cenetex/swarm/issues/1928) `aid1` avatar identity across platforms |
| `cenetex/agentd` | [#87](https://github.com/cenetex/agentd/issues/87) host `aid1` + MCPL grants |
| `cenetex/braid` | [#33](https://github.com/cenetex/braid/issues/33) content-addressed references |
| `cenetex/rati` | [#5](https://github.com/cenetex/rati/issues/5) bind avatar/token identity to `aid1` |

## Sequence

1. Log contract in CosyWorld: #1007, #1009, #1010.
2. Identity root: #1012, #753, #1928, #87, #5.
3. MCPL participation: #1011, #87.
4. Perception and consent alignment: #1008, #1013.
5. Content references: #33.

## Non-goals

- Do not copy AGPL `eidoverse-worlds` code.
- Do not merge repositories or runtimes.
- Do not require a shared deployment, database, or host. These are contracts
  between independent systems.
