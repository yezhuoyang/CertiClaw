# CertiClaw Developer Log

> **Current state (2026-03-18):** 6 iterations complete. 12 OCaml library
> modules, 75 passing tests, 1 CLI executable. **All 6 security theorems
> proved in Lean 4.** OCaml ↔ Lean correspondence tightened: effect
> comparison aligned (canonical list equality), normalization contract
> tested, 8-case correspondence corpus added. Only remaining gap:
> path normalization (tested, not proved).
> External deps: `yojson` (OCaml), Lean 4.28.0 (proofs).

---

## 2026-03-18 — Iteration 1: MVP

### Goal

Build the smallest proof-carrying enforcement pipeline that compiles,
runs, and demonstrates the core security property: the checker
independently recomputes effects and never trusts the agent's claims.

### What was built

**Pipeline:** `Typed IR → Effect Inference → Certificate Check → Render / Execute`

**Modules created:**

| File | Purpose | Trusted? |
|------|---------|----------|
| `lib/types.ml` | Action IR, effects, policy, approval, proof certificate | Yes |
| `lib/infer.ml` | Deterministic effect inference from IR | Yes |
| `lib/policy.ml` | Per-effect authorization (prefix-based path check) | Yes |
| `lib/check.ml` | Certificate validator: effects match + policy + approval | Yes |
| `lib/render.ml` | Bash rendering with `shell_quote`; MCP excluded | Partial |
| `lib/exec.ml` | check → render → execute; dry-run default | Partial |
| `test/tests.ml` | 12 unit tests | N/A |

**IR variants:** `GrepRecursive`, `RemoveByGlob`, `CurlToFile`, `McpCall`

**Effects:** `ReadPath`, `WritePath`, `ExecBin`, `NetTo`, `McpUse`

**Key decisions:**
- `action_effect` (not `effect`) — OCaml 5.x reserves `effect` as a keyword
- `(modes byte)` in dune — avoids native-linker mingw dependency on Windows
- No external test library — minimal pass/fail harness, exit code 1 on failure
- `RemoveByGlob` hard-coded as destructive; requires `ApprovedDestructive`
- McpCall not Bash-renderable; routed through simulated transport

**Known issues at end of iteration 1:**
- Path containment used naive `String.sub` prefix → sibling-prefix confusion
  (`/workspace/reports2` accepted under `/workspace/reports`)
- Traversal paths (`../../etc`) not detected
- Checker errors were ad-hoc strings — callers had to parse English
- No structured dry-run inspection

---

## 2026-03-18 — Iteration 2: Hardening the Trusted Core

### Goal

Fix the path safety bugs, replace string errors with typed errors, and
add structured execution plans — all without adding new IR variants or
external integrations.

### 1. Segment-based path authorization (`lib/path_check.ml` — new)

**Problems fixed:**
- `/workspace/reports2/x.txt` was accepted under `/workspace/reports`
  (byte-prefix confusion)
- `/home/user/src/../../etc/passwd` was accepted under `/home/user/src`
  (traversal bypass)

**How `normalize` works:**
1. Unify separators: `\` → `/`
2. Split on `/`, filter empty segments (collapses `//`)
3. Resolve `.` (drop) and `..` (pop previous; clamp at root)
4. Reconstruct with leading `/` if originally absolute

**How `segments_within` works:**
- Compare *lists of segments*, not byte strings
- `/workspace/reports` = `["workspace"; "reports"]`
- `/workspace/reports2/x` = `["workspace"; "reports2"; "x"]`
- Second segment `"reports2" ≠ "reports"` → rejected

**How `has_traversal` works:**
- Quick scan for any `..` segment after separator unification
- If present, `authorize_effect` returns `PathTraversalBlocked` immediately
- Provides a clear error; traversal would also fail containment, but the
  explicit variant is better for diagnostics

### 2. Typed checker errors (`check_error` in `lib/types.ml`)

Replaced `Rejected of string` with:

```ocaml
type check_error =
  | ClaimedEffectsMismatch
  | UnauthorizedRead     of string
  | UnauthorizedWrite    of string
  | UnauthorizedBinary   of string
  | UnauthorizedHost     of string
  | UnauthorizedMcpTool  of string * string
  | MissingDestructiveApproval
  | PathTraversalBlocked of string
```

- `check_result` = `Accepted | Rejected of check_error`
- `ExecBlocked` also carries `check_error`
- `show_check_error` for human-readable display
- Tests match exact constructors, not string contents

### 3. Structured execution plans (`lib/plan.ml` — new)

```ocaml
type rendered_form =
  | BashCommand of string
  | McpRequest  of { server : string; tool : string; args : string }

type execution_plan = {
  input_action     : action;
  inferred_effects : action_effect list;
  rendered         : rendered_form;
  dry_run          : bool;
}

val plan : ?dry_run:bool -> policy:policy -> proof:proof
         -> action -> (execution_plan, check_error) result
```

`plan` runs check + render without executing. `show_plan` formats the
result. The old `Render.render_result` local type was replaced by
`rendered_form` in types — `McpCall` now produces `McpRequest`
(structured record) instead of a free-form string.

### 4. Demo executable (`bin/demo.ml` — new)

Five sample actions through the plan pipeline:

| # | Action | Result |
|---|--------|--------|
| 1 | Grep `/home/user/src` → `/tmp/todos.txt` | Accepted |
| 2 | RemoveByGlob `/tmp/*.log` (no approval) | Rejected: MissingDestructiveApproval |
| 3 | Curl `evil.com` → `/tmp/backdoor.sh` | Rejected: UnauthorizedHost |
| 4 | McpCall `files/read_file` | Accepted |
| 5 | Grep with `../../../etc` traversal | Rejected: PathTraversalBlocked |

### 5. Test expansion: 12 → 40

| Section | Count | Covers |
|---------|-------|--------|
| Original MVP | 12 | Accept/reject for all IR variants, effect mismatch, executor |
| Path normalization | 9 | Absolute, trailing `/`, `//`, `.`, `..`, root-escape, `\`, root, empty |
| Segment containment | 11 | Exact, child, sibling-prefix, traversal, relative, nested, `has_traversal` |
| Typed errors | 6 | One test per `check_error` constructor |
| Plan module | 2 | Successful plan, rejected plan |

### Files changed in iteration 2

| File | Status | What changed |
|------|--------|-------------|
| `lib/types.ml` | Modified | Added `check_error`, `show_check_error`, `show_action`, `rendered_form`, `execution_plan` |
| `lib/path_check.ml` | **New** | Path normalization + segment-based containment |
| `lib/policy.ml` | Rewritten | Uses `Path_check`; returns `check_error` not strings |
| `lib/check.ml` | Modified | Returns typed `check_error` variants |
| `lib/render.ml` | Modified | Returns `rendered_form` from types |
| `lib/plan.ml` | **New** | Structured execution plan builder |
| `lib/exec.ml` | Modified | `ExecBlocked` carries `check_error`; new render types |
| `test/tests.ml` | Expanded | 12 → 40 tests |
| `bin/dune` | **New** | Dune config for demo |
| `bin/demo.ml` | **New** | Dry-run demo |
| `README.md` | Rewritten | Architecture, guarantees, limitations, build instructions |

### Remaining limitations

1. **No symlink resolution** — purely lexical normalization; a symlink
   could escape containment. Needs filesystem access to fix.
2. **No Windows drive-letter canonicalization** — `C:\foo` → `/C:/foo`
   (consistent internally, but not Windows-canonical).
3. **Relative paths** — handled but not anchored to a working directory;
   callers should use absolute paths for reliable results.
4. ~~**Policy is in-code**~~ → Fixed in iteration 3 (JSON file loading).
5. **MCP is simulated** — no real JSON-RPC transport.

---

## 2026-03-18 — Iteration 3: Policy-Driven Runtime

### Goal

Move policy out of code into JSON files, add structured audit logging
for every decision, and build a proper CLI executable.

### 1. Policy file loading (`lib/policy_load.ml` — new)

Loads a `Types.policy` from a JSON file using `yojson`.

**JSON schema:**
```json
{
  "readable_paths": ["/home/user/src"],
  "writable_paths": ["/tmp"],
  "allowed_bins":   ["grep"],
  "allowed_hosts":  ["example.com"],
  "allowed_mcp":    [["server", "tool"]]
}
```

**Key properties:**
- All fields are optional — missing fields default to `[]` (deny-by-default)
- Invalid shapes produce typed `policy_load_error` values:
  - `FileNotFound of string`
  - `JsonParseError of string`
  - `SchemaError of string`
- `empty_policy` provides an all-deny baseline
- MCP entries must be exactly 2-element string arrays

### 2. Audit logging (`lib/audit.ml` — new)

Every check/execute/plan decision produces an `audit_record`:

```ocaml
type audit_record = {
  seq              : int;
  action           : action;
  inferred_effects : action_effect list;
  claimed_effects  : action_effect list;
  decision         : decision;       (* Accepted | Rejected of check_error *)
  rendered         : rendered_form option;
  mode             : exec_mode;      (* DryRun | Live | CheckOnly *)
}
```

**Output formats:**
- `show_record` — human-readable multi-line text
- `json_record` — single JSON line (for JSONL log files)

**In-memory log:**
- `create_log ()` → append-only `audit_log`
- `log_record` / `get_records` for append and read
- `reset_seq ()` for testing

### 3. Pipeline integration

Both `Exec.execute` and `Plan.plan` now accept an optional
`?audit_log` parameter.  When provided, they append an audit record
for every decision — accepted or rejected, dry-run or live.

### 4. CLI executable (`bin/demo.ml` — rewritten)

Supports flags:

| Flag | Effect |
|------|--------|
| `--policy PATH` | Load policy from JSON file |
| `--demo` | Run 5 sample actions through the pipeline |
| `--dry-run` | (default) Don't execute commands |
| `--execute` | Actually execute validated commands |
| `--audit-json` | Print audit log as JSON lines |

Example: `dune exec bin/demo.exe -- --demo --policy examples/policy.json --audit-json`

### 5. Test expansion: 40 → 52

| New section | Count | Covers |
|-------------|-------|--------|
| Policy loading | 8 | Valid file, missing fields, malformed JSON, wrong types, bad MCP shape, not-object, file-not-found, deny-by-default |
| Audit logging | 4 | Accepted record, rejected record, log collection, JSON format |

### Files changed in iteration 3

| File | Status | What changed |
|------|--------|-------------|
| `lib/policy_load.ml` | **New** | JSON policy file parsing with typed errors |
| `lib/audit.ml` | **New** | Structured audit records, text + JSON formatting |
| `lib/exec.ml` | Modified | Optional `?audit_log` parameter; emits records |
| `lib/plan.ml` | Modified | Optional `?audit_log` parameter; emits records |
| `lib/dune` | Modified | Added `yojson` dependency |
| `bin/demo.ml` | Rewritten | Full CLI with --policy/--demo/--audit-json flags |
| `examples/policy.json` | **New** | Example policy file |
| `test/tests.ml` | Expanded | 40 → 52 tests |
| `README.md` | Updated | Policy format, CLI usage, audit docs, TCB table |

### Remaining limitations

1. **No symlink resolution** — purely lexical path normalization.
2. **No Windows drive-letter canonicalization**.
3. **Relative paths** — handled but not anchored to working directory.
4. **MCP is simulated** — no real JSON-RPC transport.
5. **Audit is in-memory** — no file-based log persistence yet.
6. **No policy hot-reload** — policy loaded once at startup.

---

## 2026-03-18 — Iteration 4: Formal Core Alignment

### Goal

Stabilize the formal core before adding more runtime features.  Make
the trusted computing base explicit, write a formal specification that
matches the code, and add invariant-style tests that witness the
security theorems.

### 1. Explicit TCB boundary

All modules now carry either `[TRUSTED CORE]` or `[SUPPORT]` in their
top-level doc comment.

**Trusted core (5 modules, ~340 LOC):**

| Module | Role |
|--------|------|
| `types.ml` (core section) | Type definitions — action, effect, policy, proof, check_error |
| `path_check.ml` | Path normalization + segment-based containment |
| `infer.ml` | Deterministic effect inference |
| `policy.ml` | Per-effect authorization |
| `check.ml` | Four-step certificate validation judgment |

**Support (7 modules):**

| Module | Role |
|--------|------|
| `render.ml` | Bash rendering |
| `pipeline.ml` | Structured pipeline result type |
| `plan.ml` | Execution plan builder |
| `exec.ml` | Check → render → execute |
| `audit.ml` | Audit record formatting |
| `policy_load.ml` | JSON policy file parsing |
| `core.ml` | Re-exports exactly the TCB |

**Why it matters:** A bug in any SUPPORT module cannot cause an
unauthorized action to pass `Check.check`.  The security argument
depends only on auditing ~340 lines, not ~2000.

### 2. Pipeline result type (`pipeline.ml` — new)

```ocaml
type rejection_context = {
  rejected_action  : action;
  inferred_effects : action_effect list;
  claimed_effects  : action_effect list;
}

type pipeline_result =
  | PipelineAccepted of execution_plan
  | PipelineRejected of check_error * rejection_context
```

`Pipeline.run` composes check + render into a single result.  Rejected
paths preserve full context (action, inferred effects, claimed effects)
for audit output — no information is lost.

### 3. Core facade (`core.ml` — new)

Re-exports exactly the five TCB modules:
```ocaml
module Types      = Types
module Path_check = Path_check
module Infer      = Infer
module Policy     = Policy
module Check      = Check
```

If a security property can be stated using only `Core.*` names, then
proving it depends only on the TCB.

### 4. Formal specification (`docs/formal-core.md` — new)

Defines the formal model in 8 sections:

| Section | Content |
|---------|---------|
| §1 | Action syntax |
| §2 | Effect domain + inference function ⟦·⟧ + destructive predicate |
| §3 | Policy, path normalization, containment, per-effect authorization |
| §4 | Certificate structure |
| §5 | Check judgment (four sequential steps) + error domain |
| §6 | Six security theorems (targets for mechanization) |
| §7 | TCB summary |
| §8 | Mechanization roadmap |

**Security theorems defined:**

1. **Effect soundness** — if accepted, claimed = inferred
2. **Policy soundness** — if accepted, all effects authorized
3. **Approval soundness** — if accepted and destructive, approval present
4. **MCP authorization soundness** — if accepted and McpCall, tool in policy
5. **Path traversal safety** — if accepted, no effects contain ".."
6. **Default deny** — empty policy rejects all non-trivial actions

### 5. Invariant-style tests: 52 → 62

| New test | Witnesses |
|----------|-----------|
| `inv: effect soundness` | Theorem 1 — over 8 actions |
| `inv: policy soundness` | Theorem 2 — over 8 actions |
| `inv: approval soundness` | Theorem 3 — over 8 actions |
| `inv: destructive requires approval` | Theorem 3 negative |
| `inv: mismatch always rejects` | Theorem 1 negative |
| `inv: unauthorized MCP rejects` | Theorem 4 |
| `inv: empty policy denies all` | Theorem 6 |
| `pipeline accepted` | Pipeline result type |
| `pipeline rejected preserves ctx` | Rejection context preservation |
| `pipeline mismatch preserves ctx` | Context on mismatch |

Tests iterate over a list of 8 diverse actions and check invariants
that must hold for all of them — not just one example.

### 6. Module doc comments

All 12 modules updated with:
- `[TRUSTED CORE]` or `[SUPPORT]` tag
- `{2 Formal correspondence}` section linking to formal-core.md sections
- Clear statement of what a bug in this module can/cannot break

### Files changed in iteration 4

| File | Status | What changed |
|------|--------|-------------|
| `lib/types.ml` | Modified | Added formal-core refs, `pipeline_result`, `rejection_context` |
| `lib/infer.ml` | Modified | TCB tag, formal correspondence |
| `lib/path_check.ml` | Modified | TCB tag, formal correspondence |
| `lib/policy.ml` | Modified | TCB tag, formal correspondence |
| `lib/check.ml` | Modified | TCB tag, formal correspondence, step comments |
| `lib/render.ml` | Modified | SUPPORT tag |
| `lib/plan.ml` | Modified | SUPPORT tag |
| `lib/exec.ml` | Modified | SUPPORT tag |
| `lib/audit.ml` | Modified | SUPPORT tag |
| `lib/core.ml` | **New** | TCB facade module |
| `lib/pipeline.ml` | **New** | Structured pipeline result |
| `docs/formal-core.md` | **New** | Formal specification (8 sections) |
| `test/tests.ml` | Expanded | 52 → 62 tests (invariants + pipeline) |
| `README.md` | Updated | TCB boundary, formal spec link, test table |

---

## 2026-03-18 — Iteration 5: Lean 4 Mechanization

### Goal

Prove all six security theorems from the formal specification in
Lean 4, with paths abstracted as `List String` (segment lists).

### What was built

5 Lean files in `formal/CertiClaw/`:

| File | Lines | What it defines |
|------|-------|-----------------|
| `Types.lean` | ~80 | Effect, Action, Policy, Certificate, CheckError, CheckResult |
| `Infer.lean` | ~30 | `infer`, `isDestructive` |
| `Policy.lean` | ~55 | `pathContains`, `authorizeEffect`, `authorizeAll`, `emptyPolicy` |
| `Check.lean` | ~40 | `check` (four-step judgment) |
| `Theorems.lean` | ~175 | All 6 theorems + helper lemmas |

### Key design decisions

1. **Paths as `List String`** — Not raw `String`.  This makes paths
   pre-normalized by construction.  `PathTraversalBlocked` is absent
   from the Lean model because traversal is impossible at the type level.
   Path normalization is treated as an implementation concern at the
   OCaml `Path_check.normalize` boundary.

2. **Decidable propositional equality** — The Lean `check` uses
   `if cert.claimedEffects ≠ inferred then` with `DecidableEq`,
   not BEq `!=`.  This is list equality (order-sensitive).
   (OCaml was aligned to match this in iteration 6.)

3. **Policy membership via `∈`** — Uses Lean's decidable `∈` on lists,
   which maps cleanly to OCaml's `List.mem`.

### Proved theorems

| # | Lean name | Statement |
|---|-----------|-----------|
| 1 | `effect_soundness` | accepted ⟹ claimed = inferred |
| 2 | `policy_soundness` | accepted ⟹ ∀ e ∈ inferred. authorized(π, e) |
| 3 | `approval_soundness` | accepted ∧ destructive ⟹ approval present |
| 4 | `mcp_authorization_soundness` | accepted ∧ mcpCall(s,t,_) ⟹ (s,t) ∈ π.allowedMcp |
| 5 | `path_traversal_safety` | trivially true (paths are `List String`) |
| 6 | `default_deny_all_actions` | emptyPolicy rejects every action |

### Proof techniques

- **`check_accepted_conditions`**: central lemma that decomposes a
  successful `check` into its three postconditions
- **`authorizeAll_none_imp_each`**: connects `authorizeAll = none` to
  per-element authorization
- **Case analysis**: most proofs work by `simp only [check]` then
  `split at h` to walk through the four steps
- **`Decidable.of_not_not`**: bridges `¬(a ≠ b)` to `a = b`

### Hardest proof obligation

**Theorem 3 (approval soundness)** required careful navigation of
nested `if`/`match` in the `check` definition.  After the `split`
on `isDestructive`, Lean automatically decomposed the inner `match`
on `cert.approval`, so the `ApprovedDestructive` case was directly
available as a hypothesis.

### Remaining gaps

1. **Path normalization not modeled** — the hardest missing piece.
   Would require formalizing `normalize : String → Option (List String)`
   and proving it preserves the containment semantics.

2. **Set vs list equality** — OCaml uses set equality for effects;
   Lean uses list equality.  Both are safe (list is stricter).

3. **No verified extraction** — Lean model is standalone.  Equivalence
   with OCaml is maintained by structural correspondence + tests.

### Files created/changed in iteration 5

| File | Status |
|------|--------|
| `formal/lakefile.toml` | **New** |
| `formal/lean-toolchain` | **New** |
| `formal/CertiClaw.lean` | **New** |
| `formal/CertiClaw/Types.lean` | **New** |
| `formal/CertiClaw/Infer.lean` | **New** |
| `formal/CertiClaw/Policy.lean` | **New** |
| `formal/CertiClaw/Check.lean` | **New** |
| `formal/CertiClaw/Theorems.lean` | **New** |
| `formal/README.md` | **New** |
| `.gitignore` | Updated (Lean build artifacts) |

---

## 2026-03-18 — Iteration 6: Model–Implementation Correspondence

### Goal

Close the gap between the Lean formal model and the OCaml implementation.

### 1. Effect equality aligned

**Before:** OCaml `Check.effects_match` used set equality (order-insensitive
mutual subset check). Lean used list equality (`≠`).

**After:** OCaml `check` now uses `<>` (structural list equality).
The old `effects_match` function is removed.  This makes the OCaml
checker's Step 2 identical to the Lean model's.

Reordered claimed effects are now rejected — this is stricter than
before but still safe.  A correct agent obtains claimed effects by
calling `infer_effects` directly, which always produces the same order.

### 2. Canonical effect ordering documented

Each action variant produces effects in a fixed order:

| Action | Canonical list |
|--------|---------------|
| GrepRecursive | [ReadPath root; ExecBin "grep"; WritePath output] |
| RemoveByGlob | [ExecBin "find"; WritePath root] |
| CurlToFile | [ExecBin "curl"; NetTo host; WritePath output] |
| McpCall | [McpUse (server, tool)] |

This order matches the Lean `infer` function exactly.

### 3. Normalization contract tests

Four tests verify the contract the Lean model relies on:

| Test | Property |
|------|----------|
| `no dot` | No "." segment after normalize |
| `no dotdot` | No ".." segment after normalize |
| `containment=prefix` | Containment is prefix-on-segments |
| `idempotent` | normalize(normalize(p)) = normalize(p) |

These document the boundary where the Lean abstraction (paths as
`List String`) meets the OCaml implementation (raw strings).

### 4. Correspondence test corpus

8 structured test cases exercising the same scenarios the Lean model
covers.  Each case documents which theorem it witnesses:

| Corpus | Scenario | Lean theorem |
|--------|----------|-------------|
| 1 | Accepted grep | Thm 1+2 |
| 2 | Rejected unauthorized write | Thm 2 |
| 3 | Rejected destructive (no approval) | Thm 3 |
| 4 | Accepted MCP | Thm 4 |
| 5 | Rejected MCP | Thm 4 neg |
| 6 | Default deny (empty policy) | Thm 6 |
| 7 | Effect mismatch | Thm 1 neg |
| 8 | Accepted destructive (with approval) | Thm 3 pos |

### 5. Correspondence status

| Aspect | Before | After |
|--------|--------|-------|
| Effect comparison | Set equality (mismatch) | **List equality (aligned)** |
| Effect ordering | Deterministic but undocumented | **Documented canonical order** |
| Path containment logic | Aligned | Aligned |
| Normalization contract | Untested | **4 contract tests** |
| Cross-model corpus | None | **8 correspondence tests** |
| Path normalization proof | Open | **Still open** (tested, not proved) |

### Tests: 62 → 75

| New section | Count | Covers |
|-------------|-------|--------|
| Normalization contract | 4 | No-dot, no-dotdot, containment=prefix, idempotent |
| Correspondence corpus | 8 | 8 Lean-aligned test cases |
| Reordered effects | 1 | List equality rejects reordered effects |

### Files changed

| File | Status | What changed |
|------|--------|-------------|
| `lib/check.ml` | Modified | Replaced `effects_match` with `<>` list equality |
| `lib/infer.ml` | Modified | Documented canonical effect ordering |
| `test/tests.ml` | Expanded | 62 → 75 tests |
| `formal/README.md` | Updated | Correspondence status table |
| `README.md` | Updated | Verification section, canonical ordering, normalization contract |
| `DEVLOG.md` | Updated | Iteration 6 entry |

---

## Roadmap

- [x] ~~Policy loading from JSON files~~ → Iteration 3
- [x] ~~Audit logging of all decisions~~ → Iteration 3
- [x] ~~Formal specification~~ → Iteration 4
- [x] ~~Explicit TCB boundary~~ → Iteration 4
- [x] ~~Invariant-style tests~~ → Iteration 4
- [x] ~~Lean 4 mechanization of Theorems 1–6~~ → Iteration 5
- [x] ~~OCaml ↔ Lean correspondence alignment~~ → Iteration 6
- [ ] Formalize path normalization in Lean
- [ ] Real MCP transport (JSON-RPC)
- [ ] Symlink / realpath resolution
- [ ] File-based audit log persistence
- [ ] LLM integration: agent generates IR + proof from natural language
- [ ] Richer IR variants (file copy, directory creation, git operations)
