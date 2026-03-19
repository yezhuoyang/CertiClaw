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

## OCaml CODE ISSUES

### C4. Symlink following in exec.ml defeats path containment

**Location**: `lib/exec.ml` lines 17-47 (`execute_direct_op`)

`open_in`, `open_out`, and `Sys.readdir` all follow symlinks. An
attacker who can create a symlink at a path within the allowed
directory can redirect reads/writes outside the policy sandbox:

- Policy allows writes to `/tmp/workspace/`
- Attacker: `ln -s /etc/passwd /tmp/workspace/output`
- `WriteFile{path="/tmp/workspace/output", content="pwned"}` passes
  path containment but writes to `/etc/passwd`

The paper claims "path safety" but the execution layer defeats
the lexical containment guarantees. path_check.ml normalization
is purely lexical and cannot detect symlinks.

**Severity: HIGH.**

### C5. Null byte injection in shell_quote

**Location**: `lib/render.ml` lines 9-10 (`shell_quote`)

`shell_quote` wraps in single quotes but does not reject or strip
null bytes. A malicious input like `"safe\x00; rm -rf /"` would:
1. Pass OCaml string equality (full string compared)
2. Be truncated at null by C `system()` call

This is a classic null-byte injection. Mitigation: reject or strip
`\x00` before rendering.

**Severity: MEDIUM-HIGH.**

### m4. `action_effect_equal` is dead code

**Location**: `lib/types.ml` lines 30-37

`action_effect_equal` is defined but never called anywhere. The
checker uses generic `<>`. Dead code is a maintenance hazard —
if someone adds an effect variant but forgets to update this
function, no compiler warning fires.

**Severity: LOW.**

### m5. Wildcard match in execute_direct_op suppresses warnings

**Location**: `lib/exec.ml` line 47

`| _ -> ExecError "Not a direct operation"` suppresses
exhaustiveness warnings. If a new direct-op variant is added,
the compiler won't warn.

**Severity: LOW.**
