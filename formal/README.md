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
| `CertiClaw/Normalize.lean` | `lib/path_check.ml` (`resolve_dots`) | `resolveDots`, `IsNormalized`, predicates |
| `CertiClaw/NormalizeTheorems.lean` | — | Six normalization theorems, all proved |
| `CertiClaw/PathFrontend.lean` | `lib/path_check.ml` (full pipeline) | `unifySepChars`, `splitOnSlashChars`, `filterEmpty`, `normalizePath` |

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

## Correspondence Status (Iteration 7)

| Aspect | Status | Notes |
|--------|--------|-------|
| Effect comparison | **Closed** | Canonical list equality in both |
| Effect ordering | **Closed** | Identical deterministic order |
| Policy membership | **Closed** | `List.mem` ↔ `∈` |
| Path containment logic | **Closed** | Prefix-on-segments in both |
| Segment normalization | **Proved** | `resolveDots` proved to produce clean output (no `.`, `..`, `""`) |
| Normalization idempotence | **Proved** | `resolveDots (resolveDots x) = resolveDots x` |
| Traversal consumption | **Proved** | `".." ∉ resolveDots segs` |
| Raw string → segments | **Proved** | `unifySepChars`, `splitOnSlashChars`, `filterEmpty` modeled and proved |
| Full pipeline | **Proved** | `normalizePath` = compose all steps; output is `IsNormalized` |
| Verified extraction | **Open** | Lean model is standalone |

### Normalization specification (Iteration 7)

The Lean model now includes a normalization spec in two files:

| File | What it defines |
|------|-----------------|
| `Normalize.lean` | `resolveDotsGo`, `resolveDots`, `isClean`, `AllClean`, `NoDot`, `NoDotDot`, `NoEmpty`, `IsNormalized` |
| `NormalizeTheorems.lean` | 6 proved theorems (see below) |

`resolveDots` matches OCaml `Path_check.resolve_dots` exactly:
- `"."` → dropped
- `".."` → pops previous segment; dropped at root
- `""` → dropped (matching OCaml `split_segments` filter)
- Everything else → kept

**Proved normalization theorems:**

| # | Theorem | Statement |
|---|---------|-----------|
| N1 | `resolveDots_noDot` | `"." ∉ resolveDots segs` |
| N2 | `resolveDots_noDotDot` | `".." ∉ resolveDots segs` |
| N3 | `resolveDots_noEmpty` | `"" ∉ resolveDots segs` |
| N4 | `resolveDots_idempotent` | `resolveDots (resolveDots segs) = resolveDots segs` |
| N5 | `containment_idempotent` | Re-normalizing doesn't change containment |
| N6 | `traversal_consumed` | `".." ∉ resolveDots segs` (alias of N2) |

### What is still not modeled

### Path frontend (Iteration 8)

`PathFrontend.lean` models the full OCaml raw-string-to-segments pipeline:

| Lean definition | OCaml counterpart | What it does |
|-----------------|-------------------|-------------|
| `unifySepChars` | `unify_separators` | Replace `\` with `/` in char list |
| `splitOnSlashChars` | `String.split_on_char '/'` | Split on `/` into char groups |
| `filterEmpty` | `List.filter (fun s -> s <> "")` | Remove empty segments |
| `normalizePath` | `split_segments p \|> resolve_dots` | Full pipeline composition |

**Proved properties:**

| Theorem | Statement |
|---------|-----------|
| `splitOnSlashChars_nonempty` | Split always produces ≥ 1 group |
| `splitOnSlashChars_no_slash` | No segment contains `/` |
| `filterEmpty_noEmpty` | No empty string in filtered output |
| `filterEmpty_preserves` | Non-empty strings preserved |
| `normalizePath_isNormalized` | Full pipeline output is `IsNormalized` |
| `normalizePath_resolveDots_idempotent` | `resolveDots` on normalized output is identity |

### Remaining gap

The lexical path frontend is **fully formalized**.  The only aspect not
modeled is the `String` ↔ `List Char` boundary (Lean's internal string
representation), which is a Lean standard library concern, not a
CertiClaw concern.  Verified extraction from Lean to OCaml remains open.
