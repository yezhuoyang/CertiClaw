# CertiClaw Developer Log

## 2026-03-18 — MVP: Proof-Carrying Agent Execution Framework

### What is CertiClaw?

CertiClaw is a proof-carrying enforcement framework for AI agent actions.
Instead of letting an agent execute arbitrary Bash or MCP calls, CertiClaw
requires every action to pass through a pipeline:

```
Typed IR  →  Effect Inference  →  Certificate Check  →  Render/Execute
```

The agent must supply a **proof certificate** alongside each action. The
checker independently verifies that the certificate is consistent with the
action before anything is executed. This is **proof-carrying enforcement**,
not natural-language trust.

---

### Architecture Overview

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Agent   │───>│  types   │───>│  infer   │───>│  check   │───>│  render  │
│ (future) │    │  (IR)    │    │ (effects)│    │ (verify) │    │  (bash)  │
└─────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                    │               │
                                               ┌────┴────┐    ┌────┴────┐
                                               │ policy  │    │  exec   │
                                               │ (authz) │    │(run/dry)│
                                               └─────────┘    └─────────┘
```

### Module Breakdown

| File | Purpose | Trusted? |
|------|---------|----------|
| `lib/types.ml` | Core types: action IR, effects, policy, approval, proof certificate | Yes — defines the language |
| `lib/infer.ml` | Computes effects from the IR (ground truth) | Yes — must be correct |
| `lib/policy.ml` | Checks each effect against the policy (path containment, allowed bins/hosts/MCP) | Yes — authorization logic |
| `lib/check.ml` | Validates proof certificate against IR and policy | Yes — the core verifier |
| `lib/render.ml` | Renders Bash-backed IR nodes into shell commands with quoting | Partially — output is trusted only because input was checked |
| `lib/exec.ml` | Orchestrates check → render → execute; dry-run by default | Partially — calls the trusted checker first |
| `test/tests.ml` | 12 unit tests covering accept/reject for all IR variants | N/A — test infrastructure |

### Core Types (types.ml)

**Action IR** — four variants, each with typed fields:
- `GrepRecursive { pattern; root; output }` — recursive grep, write results to file
- `RemoveByGlob { root; suffix; recursive }` — delete files matching a glob (destructive)
- `CurlToFile { url; host; output }` — download a URL to a local file
- `McpCall { server; tool; args }` — invoke an MCP tool (not Bash-renderable)

**Effects** — `action_effect` (named to avoid OCaml 5.x `effect` keyword):
- `ReadPath`, `WritePath`, `ExecBin`, `NetTo`, `McpUse`

**Policy** — allowlists for paths, binaries, hosts, and MCP server/tool pairs.

**Approval** — `NoApproval | ApprovedDestructive of string`. Destructive actions
(currently only `RemoveByGlob`) require an explicit approval token.

**Proof certificate** — `{ claimed_effects; destructive; approval; explanation }`.
The agent must fill this out honestly; the checker will catch any mismatch.

### How the Checker Works (check.ml)

The checker runs four steps in order:

1. **Infer effects** from the IR using `Infer.infer_effects`. This is the
   ground truth — it never reads the proof.
2. **Compare claimed vs inferred effects** as unordered sets. If they differ,
   reject immediately. This catches an agent that lies about what it will do.
3. **Authorize every effect** against the policy using `Policy.authorize_all`.
   Path effects use prefix containment; bins/hosts/MCP use exact match.
4. **Check destructive approval**. If `Infer.is_destructive action` is true,
   the proof must carry `ApprovedDestructive _`.

Any failure at any step returns `Rejected reason`.

### Bash Rendering (render.ml)

Only Bash-backed actions are rendered:
- `GrepRecursive` → `grep -R -n '<pattern>' '<root>' > '<output>'`
- `RemoveByGlob` → `find '<root>' [-maxdepth 1] -name '*<suffix>' -delete`
- `CurlToFile` → `curl -fsSL '<url>' -o '<output>'`

All arguments are single-quote escaped via `shell_quote`. McpCall returns
`NotBashRenderable` and is routed through a simulated MCP transport.

### Executor (exec.ml)

The executor is the only entry point for running actions:

```
execute ?dry_run ~policy ~proof action → ExecOk _ | ExecBlocked _ | ExecError _
```

1. Calls `Check.check`. If rejected → `ExecBlocked`.
2. Calls `Render.render`. Bash actions are executed (or dry-run printed).
   MCP calls go through `simulate_mcp`.
3. Default is `dry_run=true` — nothing actually runs unless you opt in.

### Test Coverage (test/tests.ml)

12 tests, all passing:

| # | Test | Expects |
|---|------|---------|
| 1 | Grep with valid paths | Accepted |
| 2 | Grep writing outside allowed path | Rejected |
| 3 | Remove with approval | Accepted |
| 4 | Remove without approval | Rejected |
| 5 | Curl to allowed host | Accepted |
| 6 | Curl to disallowed host | Rejected |
| 7 | MCP call with allowed tool | Accepted |
| 8 | MCP call with disallowed tool | Rejected |
| 9 | Effect mismatch (proof lies) | Rejected |
| 10 | Executor dry-run on valid action | ExecOk |
| 11 | Executor blocks rejected action | ExecBlocked |
| 12 | Executor MCP dry-run | ExecOk |

### Design Decisions & Rationale

1. **`action_effect` not `effect`** — OCaml 5.x reserves `effect` as a keyword
   for algebraic effects. Using `action_effect` makes the code forward-compatible
   without requiring compiler flags.

2. **Bytecode mode** — The `(modes byte)` dune setting avoids native-code linking,
   which requires a complete mingw cross-toolchain on Windows. Bytecode is
   sufficient for the MVP and removes a significant build-environment dependency.

3. **No external test library** — A minimal pass/fail harness avoids the need for
   `opam install alcotest`. The tests are simple assertions; if any fails, the
   process exits with code 1.

4. **Checker always recomputes effects** — The proof's `claimed_effects` are
   compared against independently inferred effects. This is the central security
   property: even if the agent is compromised, it cannot smuggle unauthorized
   effects past the checker.

5. **RemoveByGlob is always destructive** — This is a hard-coded classification,
   not a heuristic. The checker requires an `ApprovedDestructive` token for any
   `RemoveByGlob` action regardless of its arguments.

6. **Path containment is prefix-based** — Simple `String.sub` prefix check.
   Sufficient for the MVP but should be hardened (canonicalization, symlink
   resolution) before production use.

7. **MCP calls are not Bash-rendered** — MCP is a separate transport protocol.
   Rendering it as Bash would violate the type safety that the IR provides.

### How to Build and Test

```bash
# Set up the OCaml toolchain (opam default switch, OCaml 5.3 + dune 3.19)
export PATH="/c/Users/yezhu/AppData/Local/opam/.cygwin/root/bin:/c/Users/yezhu/AppData/Local/opam/default/bin:$PATH"
export OCAMLLIB="C:/Users/yezhu/AppData/Local/opam/default/lib/ocaml"

# Build
dune build

# Run tests
dune exec test/tests.exe
```

### What's Next

- [x] ~~Path canonicalization and symlink handling~~ → Hardened in iteration 2 (see below)
- [x] ~~Typed checker errors~~ → Added in iteration 2
- [ ] Policy loading from YAML/JSON config files
- [ ] Real MCP transport (JSON-RPC)
- [ ] Symlink / realpath resolution (requires filesystem access)
- [ ] Audit logging of all check/execute decisions
- [ ] Formal verification of checker properties in Coq or Lean
- [ ] LLM integration: agent generates IR + proof from natural language
- [ ] Native compilation (fix mingw toolchain setup)
- [ ] Richer IR variants (file copy, directory creation, git operations)

---

## 2026-03-18 — Iteration 2: Hardening the Trusted Core

### Overview

This iteration hardens the checking and execution boundary without adding
new IR variants or external integrations.  The focus is on three areas:
path safety, typed errors, and structured execution plans.

### 1. Segment-Based Path Authorization (path_check.ml)

**Problem**: The MVP used `String.sub` prefix matching for path
containment.  This had two bugs:

- **Sibling-prefix confusion**: `/workspace/reports2/x.txt` was accepted
  under the policy path `/workspace/reports` because `"reports"` is a
  byte-prefix of `"reports2"`.
- **Traversal bypass**: `/home/user/src/../../etc/passwd` was accepted
  under `/home/user/src` because the raw string starts with the allowed
  prefix.

**Solution**: New `Path_check` module with:

1. **Normalization** (`normalize`):
   - Unify separators: `\` → `/`
   - Split on `/`, filter empty segments (handles `//`)
   - Resolve `.` (drop) and `..` (pop previous segment; clamp at root)
   - Reconstruct with leading `/` if originally absolute

2. **Segment-based containment** (`segments_within`):
   - After normalization, compare *lists of segments*, not byte strings
   - `/workspace/reports` = segments `["workspace"; "reports"]`
   - `/workspace/reports2/x` = segments `["workspace"; "reports2"; "x"]`
   - The second segment `"reports2" ≠ "reports"` → correctly rejected

3. **Traversal detection** (`has_traversal`):
   - Quick pre-check: does the path contain any `..` segment?
   - If yes, `authorize_effect` returns `PathTraversalBlocked` immediately
   - This provides clear error messages; traversal would also fail the
     normalized containment check, but the explicit error is more helpful

**Tested with**: sibling-prefix, `../` escape, relative paths, nested
allowed paths, backslash normalization, root edge cases.

### 2. Typed Checker Errors (types.ml check_error)

**Problem**: The MVP used `Rejected of string` everywhere.  Callers had
to parse English to determine the rejection reason.

**Solution**: New `check_error` variant type:

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

`check_result` is now `Accepted | Rejected of check_error`.
`exec_result.ExecBlocked` also carries `check_error` instead of string.
`show_check_error` provides human-readable messages.

Tests assert exact error constructors, not just "rejected".

### 3. Structured Execution Plan (plan.ml)

**Problem**: The executor either ran the command or printed a dry-run
string.  There was no structured inspection of what *would* happen.

**Solution**: New `Plan` module and types:

```ocaml
type rendered_form =
  | BashCommand of string
  | McpRequest  of { server; tool; args }

type execution_plan = {
  input_action     : action;
  inferred_effects : action_effect list;
  rendered         : rendered_form;
  dry_run          : bool;
}

val plan : ?dry_run:bool -> policy:policy -> proof:proof
         -> action -> (execution_plan, check_error) result
```

`plan` runs check + render without executing, returning a structured
record.  `show_plan` formats it for display.  The `rendered_form` type
replaces the old `Render.render_result` — `McpCall` now produces
`McpRequest` (a structured record) instead of a free-form string.

### 4. Demo Executable (bin/demo.ml)

New `bin/demo.exe` runs five actions through the plan pipeline:

1. Valid grep → Accepted, shows Bash command
2. Remove without approval → Rejected (MissingDestructiveApproval)
3. Curl to disallowed host → Rejected (UnauthorizedHost)
4. Valid MCP call → Accepted, shows MCP request
5. Path traversal attempt → Rejected (PathTraversalBlocked)

### 5. Test Expansion

Test count: 12 → 40

| New section | Tests | What they cover |
|-------------|-------|-----------------|
| Path normalization | 9 | Absolute, trailing slash, `//`, `.`, `..`, root-escape, `\`, root, empty |
| Segment containment | 11 | Exact, child, sibling-prefix, traversal, relative, nested, `has_traversal` |
| Typed errors | 6 | Exact constructor matching for each `check_error` variant |
| Plan module | 2 | Successful plan, rejected plan |

### Changed Files

| File | Change |
|------|--------|
| `lib/types.ml` | Added `check_error` type, `show_check_error`, `show_action`, `rendered_form`, `execution_plan`; changed `check_result` to use `check_error` |
| `lib/path_check.ml` | **New** — path normalization and segment-based containment |
| `lib/policy.ml` | Rewritten to use `Path_check` and return `check_error` instead of strings |
| `lib/check.ml` | Updated to return typed `check_error` variants |
| `lib/render.ml` | Returns `rendered_form` (from types) instead of local `render_result` |
| `lib/plan.ml` | **New** — structured execution plan builder |
| `lib/exec.ml` | `ExecBlocked` now carries `check_error`; updated for new render types |
| `test/tests.ml` | Expanded from 12 → 40 tests |
| `bin/dune` | **New** — dune config for demo executable |
| `bin/demo.ml` | **New** — dry-run demo |
| `README.md` | Full rewrite with architecture, guarantees, limitations, build instructions |

### Remaining Limitations

1. **No symlink resolution** — Path normalization is purely lexical.  A
   symlink at `/home/user/src/link → /etc` would pass the containment
   check because we don't call `realpath`.  This requires filesystem
   access and is deferred.

2. **No Windows drive letters** — `C:\foo` normalizes to `/C:/foo` which
   works for internal consistency but is not canonicalized against
   actual Windows semantics.

3. **Relative paths** — The system handles them but cannot verify they
   resolve within allowed directories without knowing the working directory.
   Callers should use absolute paths.

4. **Policy is in-code** — No file-based policy loading yet.

5. **MCP is simulated** — No real JSON-RPC transport.

### What's Next

- [ ] Policy loading from YAML/JSON config files
- [ ] Real MCP transport (JSON-RPC)
- [ ] Symlink / realpath resolution
- [ ] Audit logging of all check/execute decisions
- [ ] Formal verification of checker properties in Coq or Lean
- [ ] LLM integration: agent generates IR + proof from natural language
- [ ] Richer IR variants (file copy, directory creation, git operations)
