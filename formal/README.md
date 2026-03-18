# CertiClaw Formal Model (Lean 4)

This directory contains a Lean 4 mechanization of the CertiClaw
trusted core.  All six security theorems from
[`docs/formal-core.md`](../docs/formal-core.md) are stated and proved.

## What is Modeled

| Lean file | OCaml counterpart | What it defines |
|-----------|-------------------|-----------------|
| `CertiClaw/Types.lean` | `lib/types.ml` | Effect, Action, Policy, Certificate, CheckError, CheckResult |
| `CertiClaw/Infer.lean` | `lib/infer.ml` | `infer : Action → List Effect`, `isDestructive` |
| `CertiClaw/Policy.lean` | `lib/policy.ml` | `authorizeEffect`, `authorizeAll`, `pathContains`, `emptyPolicy` |
| `CertiClaw/Check.lean` | `lib/check.ml` | `check : Policy → Certificate → Action → CheckResult` |
| `CertiClaw/Theorems.lean` | `docs/formal-core.md` §6 | Six security theorems, all proved |

## What is Abstracted

The Lean model intentionally differs from the OCaml implementation
in two ways to make proofs tractable:

### 1. Paths are `List String`, not raw `String`

In OCaml, paths are raw strings that pass through `Path_check.normalize`
(which resolves `.`, `..`, and backslashes) before segment-based
containment is checked.

In Lean, paths are `List String` — they represent *already-normalized*
segment lists.  For example, `/home/user/src` is `["home", "user", "src"]`.

**Why:** Path normalization involves string splitting, character
replacement, and `..` resolution — messy to formalize.  By modeling
paths as pre-normalized segments, the proofs focus on the checker
logic without needing string lemmas.

**Consequence:** The OCaml `PathTraversalBlocked` error does not appear
in the Lean model.  In the formal model, traversal is impossible by
construction (there is no `..` segment to inject).  The OCaml
`Path_check.has_traversal` check corresponds to the boundary between
raw strings and the normalized `List String` representation.

Theorem 5 (path traversal safety) is therefore trivially true in Lean.

### 2. Effect list comparison uses decidable equality, not set equality

In OCaml, `Check.effects_match` compares two effect lists as unordered
sets (mutual subset check).

In Lean, `check` uses `≠` with `DecidableEq` on `List Effect`, which
is *list equality* (order-sensitive).

**Why:** List equality is strictly stronger than set equality and
simpler to reason about.  Since `infer` is deterministic and returns a
fixed-order list, an honest agent that calls `infer` to populate its
certificate will always produce the same order.  The gap only matters
for dishonest certificates that reorder effects — set equality would
accept them, list equality rejects.  Both are safe.

## Proved Theorems

| # | Name | Statement |
|---|------|-----------|
| 1 | `effect_soundness` | If `check` accepts, `cert.claimedEffects = infer a` |
| 2 | `policy_soundness` | If `check` accepts, every inferred effect is authorized |
| 3 | `approval_soundness` | If `check` accepts and `isDestructive a`, approval is `ApprovedDestructive` |
| 4 | `mcp_authorization_soundness` | If `check` accepts a `mcpCall`, `(server, tool) ∈ policy.allowedMcp` |
| 5 | `path_traversal_safety` | Trivially true — paths are pre-normalized segments |
| 6 | `default_deny` / `default_deny_all_actions` | Empty policy rejects every action |

## How This Connects to the OCaml TCB

The Lean model covers the same logic as the OCaml trusted core:

```
Lean                    OCaml
────                    ─────
Types.lean          ←→  types.ml (core section)
Infer.lean          ←→  infer.ml
Policy.lean         ←→  policy.ml + path_check.ml (containment only)
Check.lean          ←→  check.ml
```

The Lean model does NOT cover:
- Path normalization from raw strings (`path_check.ml`'s `normalize`)
- Bash rendering (`render.ml`)
- Execution (`exec.ml`)
- Audit logging (`audit.ml`)
- Policy file loading (`policy_load.ml`)
- CLI (`bin/demo.ml`)

## Building

Requires Lean 4.28.0 (specified in `lean-toolchain`).

```bash
cd formal
lake build
```

## Correspondence Status (Iteration 6)

| Aspect | Status | Notes |
|--------|--------|-------|
| Effect comparison | **Closed** | OCaml changed from set equality to canonical list equality (`<>`) — now matches Lean's `≠` exactly |
| Effect ordering | **Closed** | Both OCaml and Lean return effects in identical deterministic order per action variant |
| Policy membership | **Closed** | OCaml `List.mem` ↔ Lean `∈` (decidable) |
| Path containment logic | **Closed** | OCaml `segments_within` ↔ Lean `List.isPrefixOf` — same segment-prefix semantics |
| Path normalization | **Open** | OCaml `normalize` bridges raw strings to `List String`; not modeled in Lean |
| Verified extraction | **Open** | Lean model is standalone; equivalence maintained by correspondence test corpus |

### What is now tested but not proved

The OCaml test suite includes:
- **Normalization contract tests** verifying that `normalize` produces
  clean segment lists (no `.`, no `..`, idempotent, containment = prefix)
- **Correspondence corpus** (8 test cases) exercising the same
  action/policy/certificate/result scenarios that the Lean model covers
- These could be exported to a Lean-side test harness for cross-validation

### Remaining gap

**Path normalization** is the only significant open gap.  The OCaml
`Path_check.normalize` function converts raw strings to segment lists.
The Lean model assumes paths are already `List String`.  To close this:
1. Define `normalize : String → Option (List String)` in Lean
2. Prove it satisfies the four contract properties
3. Prove that `pathContains` on normalized paths equals `path_within`

This is the hardest remaining proof obligation.
