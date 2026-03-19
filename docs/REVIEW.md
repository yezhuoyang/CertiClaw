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

## PAPER SCIENTIFIC ISSUES

### C6. "18 theorems" count is inflated

N6 (`traversal_consumed`) is literally `resolveDots_noDotDot segs` —
an alias of N2. T5 is `∀ p, True`. Counting both as theorems inflates
the count. Substantive distinct results are closer to 14-15.

### C7. "blocks all 7 attack classes by construction" (abstract)

The formal proofs cover only 4 of 7 variants. ReadFile, WriteFile,
ListDir are NOT covered. The "by construction" claim requires proof
coverage of the entire system, which we don't have.

### M4. "Empirical" overstates methodology

We extract isolated functions into standalone scripts and test them.
This is unit-testing extracted functions, not running real systems
against real attacks end-to-end. "Empirical" implies integration
testing. Should say "we test the extracted security-critical functions."

### M5. 11 "missing wrappers" are arguable as vulnerabilities

`awk '{print $1}' file.txt` does not execute subcommands in practice.
`nmap` is a scanner, not a command dispatcher. `strace`/`ltrace` are
debugging tools. Fairer count of exploitable issues: 6-8, not 18.
Should distinguish "coverage gaps" from "exploitable vulnerabilities."

### M6. Performance uses Sys.time (~1ms resolution on Windows)

Claiming ~4μs with Sys.time on Windows is below measurement
resolution. Should disclose platform and use Unix.gettimeofday or
Sys.time on Linux where resolution is 1μs.

### M7. "500 lines of Lean" is actually ~810 lines

Across 8 files. Even excluding blanks/comments, substantially more
than 500.

## PAPER NOTATION ISSUES

### N1. `\kw{}` overloaded for constructors, functions, types, errors

Should use distinct typographic treatments per PL convention.

### N2. Check judgment: function or relation?

Uses `→` (function arrow) in boxed form but `=` (equality) in the
Check rule. Mixing conventions.

### N3. Action grammar shows 4 constructors; OCaml has 7

The formal syntax in §5.1 is incomplete.

### N4. Ghost content from quantum computing paper

`background.tex`, `casestudies.tex`, `compilation.tex`,
`typesystem.tex`, `syntax.tex`, `theory.tex`, `distance.tex`,
`logicalops.tex` are all from a "LogiQ" quantum error correction
paper. Not included by main.tex but present in the directory.
Delete before submission.

### N5. Duplicate dead files

`formalization.tex` and `normalization.tex` overlap with
`verification.tex`. Only `verification.tex` is `\input`'d.
`architecture.tex`, `overview.tex`, `threat.tex`, `tcb.tex`,
`implementation.tex` are also dead (not included by main.tex).
Delete all dead .tex files before submission.

### N6. N6 is a duplicate of N2

`traversal_consumed` is literally `resolveDots_noDotDot segs`.
Listing it separately inflates the theorem count.

## COMPLETE ISSUE SUMMARY

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 7 | C1 (4/7 variants), C2 (T5 vacuous), C3 (no has_traversal), C4 (symlink), C5 (null byte), C6 (theorem count), C7 (overclaim) |
| MAJOR | 7 | M1 (no equivalence), M2 (pre-normalized), M3 (LOC wrong), M4 (empirical), M5 (vuln count), M6 (timing), M7 (Lean LOC) |
| MINOR | 6+ | N1-N6, m1-m5 |

## RECOMMENDED ACTIONS (priority order)

1. **Add ReadFile/WriteFile/ListDir to Lean model** and reprove all
   theorems. This closes C1 and C7.
2. **Replace T5 with a real theorem** connecting check acceptance to
   `".."` absence in effect paths, or downgrade it honestly. Closes C2.
3. **Add has_traversal to Lean authorizeEffect** or document the gap.
   Closes C3.
4. **Re-measure LOC** excluding support types from TCB count. Fix all
   "340" references. Closes M3.
5. **Add null byte rejection to shell_quote**. Closes C5.
6. **Document symlink limitation prominently** in paper and README.
   Closes C4.
7. **Delete all ghost .tex files** from paper directory. Closes N4, N5.
8. **Qualify "empirical" and "vulnerability" claims.** Closes M4, M5.
9. **Re-count theorems honestly** (drop N6 duplicate, note T5 is
   trivial). Closes C6.
10. **Fix LOC claims** (Lean ~810, not 500; TCB ~446, not 340). Closes M7.

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
