# CertiClaw Developer Log

> **Current state (2026-03-18):** 3 iterations complete. 10 library modules,
> 52 passing tests, 1 CLI executable. Trusted core covers typed IR,
> effect inference, segment-based path checking, typed error reporting,
> and structured execution plans. Policy loaded from JSON files.
> Every decision is recorded in a structured audit log.
> External dependency: `yojson` (for policy file parsing).

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

## Roadmap

- [x] ~~Policy loading from JSON files~~ → Iteration 3
- [x] ~~Audit logging of all decisions~~ → Iteration 3
- [ ] Real MCP transport (JSON-RPC)
- [ ] Symlink / realpath resolution
- [ ] File-based audit log persistence
- [ ] Policy hot-reload
- [ ] Formal verification of checker properties in Coq or Lean
- [ ] LLM integration: agent generates IR + proof from natural language
- [ ] Richer IR variants (file copy, directory creation, git operations)
- [ ] Native compilation (fix mingw toolchain on Windows)
