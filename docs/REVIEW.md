# CertiClaw Self-Review: Adversarial Audit

This document records all issues found by adversarial review of the
codebase and paper. Issues are ordered by severity.

## CRITICAL ISSUES

### C1. Lean model covers only 4 of 7 OCaml action variants

**Location**: `formal/CertiClaw/Types.lean` lines 63-68 vs `lib/types.ml` lines 86-117

The OCaml `action` type has 7 constructors: `GrepRecursive`, `RemoveByGlob`,
`CurlToFile`, `McpCall`, `ReadFile`, `WriteFile`, `ListDir`. The Lean `Action`
type has only 4 (missing `ReadFile`, `WriteFile`, `ListDir`).

**Impact**: All 6 security theorems are proved only for 4 of 7 action
variants. The paper's claim that "the Lean model corresponds to the OCaml
implementation" is false for three action types. An agent performing
`ReadFile`, `WriteFile`, or `ListDir` has zero formal coverage.

**Paper claim broken**: "18 machine-checked theorems covering the checker
logic" — only covers 57% of the action language.

**Fix required**: Either (a) add ReadFile/WriteFile/ListDir to the Lean
model and reprove all theorems, or (b) clearly state in the paper that
the formal model covers the original 4 variants and the 3 new ones are
tested but not proved.

### C2. Theorem 5 (path traversal safety) is vacuously true

**Location**: `formal/CertiClaw/Theorems.lean` lines 150-152

```lean
theorem path_traversal_safety :
    ∀ (_p : Path), True :=
  fun _ => trivial
```

This literally proves `∀ p, True`. It has zero security content. It does
not mention `check`, `infer`, effects, or `".."`. The paper claims this
theorem guarantees "no accepted action contains '..' in its path effects."
The Lean proof proves no such thing.

Moreover, `[".."]` is a valid `List String` value in Lean — the type system
does NOT prevent it. The claim that "traversal is impossible by construction"
is false.

**Paper claim broken**: formal-core.md §6 Theorem 5 states a substantive
property. The Lean proof is vacuous.

**Fix required**: Either (a) state a real theorem connecting `check` acceptance
to `".."` absence in inferred effect paths, or (b) downgrade this from
"proved" to "justified by the type abstraction" in the paper, and honestly
state that `[".."]` is representable.

### C3. Lean `authorizeEffect` omits the `has_traversal` check

**Location**: `formal/CertiClaw/Policy.lean` lines 25-41 vs `lib/policy.ml` lines 18-38

The OCaml `authorize_effect` checks `Path_check.has_traversal p` before
containment, returning `PathTraversalBlocked` if `..` is present. The
Lean model has no such check. `PathTraversalBlocked` is not even in the
Lean `CheckError` type.

This means the Lean proofs do not cover the actual authorization logic
used in production for path effects.

## MAJOR ISSUES

### M1. No end-to-end equivalence theorem

There is no theorem (or even informal argument) that the Lean `check`
function, given inputs corresponding to OCaml inputs after normalization,
produces the same result. The normalization pipeline (PathFrontend.lean)
and the check pipeline (Check.lean) are completely disconnected. No
theorem ties `normalizePath` output to `check` input.

### M2. Lean model assumes pre-normalized paths; OCaml normalizes at check time

In OCaml, `authorize_effect` calls `Path_check.path_within` which
normalizes both the policy path and the effect path. In Lean,
`authorizeEffect` uses `pathContains` = `List.isPrefixOf` with no
normalization. The Lean model silently pushes normalization out of
the verified boundary.

### M3. Paper claims "340 LOC TCB" but LOC may have changed

After adding ReadFile/WriteFile/ListDir variants, the TCB modules
(types.ml, infer.ml, path_check.ml, policy.ml, check.ml) may now
total more than 340 lines. This number should be re-measured.

## MINOR ISSUES

### m1. `resolveDotsGo` in Lean filters empty strings; OCaml `resolve_dots` does not

Lean's `resolveDotsGo` has `| "" :: rest => resolveDotsGo acc rest`.
OCaml's `resolve_dots` has no such clause — empty filtering is done by
`split_segments`. The functions are not individually equivalent.

### m2. Certificate `explanation` field missing from Lean model

OCaml has `explanation : string option`; Lean omits it. Not security-
relevant but breaks correspondence claim.

### m3. Certificate `destructive` field missing from Lean model

OCaml has `destructive : bool`; Lean Certificate only has `claimedEffects`,
`destructive`, and `approval`. Need to verify Lean Certificate matches.

## PAPER NOTATION ISSUES (pending full audit)

[Will be filled when paper audit agent completes]

## OCaml CODE ISSUES (pending full audit)

[Will be filled when OCaml audit agent completes]
