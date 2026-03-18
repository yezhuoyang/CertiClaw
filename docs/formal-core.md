# CertiClaw — Formal Core Specification

This document defines the formal model underlying CertiClaw's trusted
computing base.  Every definition here corresponds directly to OCaml
code in `lib/`.  The goal is to make the security properties precise
enough to mechanize in Coq or Lean in a later iteration.

---

## §1. Action Syntax

An **action** is a member of the type:

```
Action ::=
  | GrepRecursive(pattern, root, output)
  | RemoveByGlob(root, suffix, recursive)
  | CurlToFile(url, host, output)
  | McpCall(server, tool, args)
```

where all fields are strings (or bool for `recursive`).

**OCaml:** `Types.action`

---

## §2. Effect Domain and Inference

An **effect** describes a single observable side-effect:

```
Effect ::=
  | ReadPath(path)
  | WritePath(path)
  | ExecBin(binary)
  | NetTo(host)
  | McpUse(server, tool)
```

**OCaml:** `Types.action_effect`

### Effect inference function

The function **infer** : Action → Effect list is defined by:

```
infer(GrepRecursive(p, r, o))     = [ReadPath(r), ExecBin("grep"), WritePath(o)]
infer(RemoveByGlob(r, s, rec))    = [ExecBin("find"), WritePath(r)]
infer(CurlToFile(u, h, o))        = [ExecBin("curl"), NetTo(h), WritePath(o)]
infer(McpCall(s, t, a))           = [McpUse(s, t)]
```

**OCaml:** `Infer.infer_effects`

### Destructive predicate

```
destructive(a) = true   iff  a = RemoveByGlob(_, _, _)
destructive(a) = false  otherwise
```

**OCaml:** `Infer.is_destructive`

---

## §3. Policy and Authorization

A **policy** π is a record:

```
Policy = {
  readable_paths : Path set,
  writable_paths : Path set,
  allowed_bins   : String set,
  allowed_hosts  : String set,
  allowed_mcp    : (String × String) set
}
```

**OCaml:** `Types.policy`

### Path normalization

**normalize** : String → String option

1. Replace `\` with `/`
2. Split on `/`, filter empty segments
3. Resolve `.` (drop) and `..` (pop previous; clamp at root)
4. Reconstruct with leading `/` if originally absolute
5. Return `None` if empty after normalization

**OCaml:** `Path_check.normalize`

### Path containment

**contains**(parent, child) holds when:

```
let P = segments(normalize(parent))
let C = segments(normalize(child))
P is a prefix of C  (segment-wise equality)
```

**OCaml:** `Path_check.path_within`

### Traversal detection

**has_traversal**(p) = true iff `..` appears as a segment in p after
separator unification.

When has_traversal(p) is true, authorization returns
`PathTraversalBlocked(p)` immediately.

**OCaml:** `Path_check.has_traversal`

### Per-effect authorization

The judgment **authorized**(π, e) is defined by:

```
authorized(π, ReadPath(p))    ⟺  ¬has_traversal(p) ∧ ∃ d ∈ π.readable_paths. contains(d, p)
authorized(π, WritePath(p))   ⟺  ¬has_traversal(p) ∧ ∃ d ∈ π.writable_paths. contains(d, p)
authorized(π, ExecBin(b))     ⟺  b ∈ π.allowed_bins
authorized(π, NetTo(h))       ⟺  h ∈ π.allowed_hosts
authorized(π, McpUse(s, t))   ⟺  (s, t) ∈ π.allowed_mcp
```

**OCaml:** `Policy.authorize_effect`

### All-authorized lifting

**all-authorized**(π, E) ⟺ ∀ e ∈ E. authorized(π, e)

Returns the first unauthorized effect as an error, or None.

**OCaml:** `Policy.authorize_all`

---

## §4. Certificate

A **certificate** C is:

```
Certificate = {
  claimed_effects : Effect list,
  destructive     : bool,
  approval        : Approval option,
  explanation     : String option
}

Approval ::= NoApproval | ApprovedDestructive(reason)
```

**OCaml:** `Types.proof`

The certificate is the agent's claim.  The checker verifies it
against independently computed ground truth.

---

## §5. Check Judgment

The central judgment is:

**check**(π, C, a) → Accepted | Rejected(error)

Defined by four sequential steps:

```
check(π, C, a):
  let E = infer(a)                                      — Step 1
  if C.claimed_effects ≠ E (as sets)                    — Step 2
    then Rejected(ClaimedEffectsMismatch)
  else if ¬ all-authorized(π, E)                        — Step 3
    then Rejected(first-unauthorized-error)
  else if destructive(a) ∧ C.approval ≠ ApprovedDestructive(_)  — Step 4
    then Rejected(MissingDestructiveApproval)
  else Accepted
```

**OCaml:** `Check.check`

### Error domain

```
CheckError ::=
  | ClaimedEffectsMismatch
  | UnauthorizedRead(path)
  | UnauthorizedWrite(path)
  | UnauthorizedBinary(binary)
  | UnauthorizedHost(host)
  | UnauthorizedMcpTool(server, tool)
  | MissingDestructiveApproval
  | PathTraversalBlocked(path)
```

**OCaml:** `Types.check_error`

---

## §6. Security Theorems (Goals for Mechanization)

The following theorems should hold and are targets for future Coq/Lean
mechanization.  They are currently validated by invariant-style tests.

### Theorem 1: Effect Soundness

> If check(π, C, a) = Accepted, then C.claimed_effects = infer(a)
> as sets.

*Proof sketch:*  Step 2 rejects when they differ.  If we reach
Accepted, Step 2 did not fire, so they must be equal.

### Theorem 2: Policy Soundness

> If check(π, C, a) = Accepted, then ∀ e ∈ infer(a).
> authorized(π, e).

*Proof sketch:*  Step 3 rejects if any effect is unauthorized.
If we reach Accepted, Step 3 did not fire.

### Theorem 3: Approval Soundness

> If check(π, C, a) = Accepted and destructive(a), then
> C.approval = Some(ApprovedDestructive(_)).

*Proof sketch:*  Step 4 rejects when destructive(a) and approval
is not ApprovedDestructive.  If we reach Accepted and destructive(a)
holds, Step 4 must have matched ApprovedDestructive.

### Theorem 4: MCP Authorization Soundness

> If check(π, C, a) = Accepted and a = McpCall(s, t, _), then
> (s, t) ∈ π.allowed_mcp.

*Proof sketch:*  infer(McpCall(s, t, _)) = [McpUse(s, t)].
By Theorem 2, authorized(π, McpUse(s, t)) holds.
By definition, this requires (s, t) ∈ π.allowed_mcp.

### Theorem 5: Path Traversal Safety

> If check(π, C, a) = Accepted, then no effect in infer(a) contains
> a ".." segment in its path.

*Proof sketch:*  authorize_effect rejects any ReadPath or WritePath
with has_traversal = true before checking containment.

### Theorem 6: Default Deny

> For the empty policy (all fields = []), check(π, C, a) = Rejected
> for any a that produces at least one effect.

*Proof sketch:*  All effects require membership in a non-empty
set.  The empty policy has no members.

---

## §7. Trusted Computing Base Summary

| Component | LOC | Role |
|-----------|-----|------|
| `types.ml` (core section) | ~130 | Type definitions |
| `path_check.ml` | ~80 | Path normalization + containment |
| `infer.ml` | ~35 | Effect inference |
| `policy.ml` | ~45 | Per-effect authorization |
| `check.ml` | ~50 | Certificate validation |
| **Total TCB** | **~340** | |

Everything else (render, exec, plan, pipeline, audit, policy_load,
CLI) is outside the TCB.  A bug in a non-TCB module cannot cause
an unauthorized action to pass `Check.check`.

---

## §8. What Remains Before Mechanization

1. **Choose a proof assistant**: Coq or Lean 4.
2. **Encode the types**: Action, Effect, Policy, Certificate, CheckError
   as inductive types.
3. **Encode infer, authorize, check** as total functions.
4. **Prove Theorems 1–6** by structural induction / case analysis.
5. **Extract OCaml** from the proven model (Coq extraction or Lean
   codegen), or maintain a verified reference and test equivalence.
6. **Path normalization** is the hardest part to verify — resolve_dots
   and segment comparison need string/list lemmas.  Consider
   abstracting paths as `string list` in the formal model to simplify.
