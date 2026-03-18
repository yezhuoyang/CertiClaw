# CertiClaw

A proof-carrying agent execution framework in OCaml with Lean 4
verified security properties.

## Artifact Quick Start

```bash
# Prerequisites: OCaml 5.x + dune + yojson, Lean 4.28.0

# Full validation (tests + evaluation + proofs)
./run_all.sh

# Or individually:
dune exec test/tests.exe            # 75 unit tests
dune exec eval/run_eval.exe         # 29-case evaluation corpus
dune exec eval/run_eval.exe -- --summary   # paper-ready tables
cd formal && lake build             # 18 Lean theorems

# Other output formats
dune exec eval/run_eval.exe -- --csv       # CSV
dune exec eval/run_eval.exe -- --json      # JSON lines
dune exec bin/demo.exe -- --demo --audit-json  # demo with audit

# Docker (fully reproducible)
docker build -t certiclaw .
docker run --rm certiclaw
```

See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for expected outputs
and [ARTIFACT.md](ARTIFACT.md) for the full artifact manifest.

[![CI](https://github.com/yezhuoyang/CertiClaw/actions/workflows/ci.yml/badge.svg)](https://github.com/yezhuoyang/CertiClaw/actions/workflows/ci.yml)

## Purpose

CertiClaw prevents AI agents from executing unauthorized side effects.
Instead of trusting natural-language promises, it requires every action
to pass through a typed pipeline:

```
Typed IR  →  Effect Inference  →  Certificate Check  →  Render / Execute
                                        ↓
                                   Audit Record
```

The agent must supply a **proof certificate** alongside each action.  The
checker independently infers effects from the IR and verifies that:

1. The proof's claimed effects match the inferred effects exactly.
2. Every effect is authorized by the active policy.
3. Destructive actions carry explicit approval.

Only validated actions can be rendered to Bash or dispatched via MCP.
Every decision (accepted or rejected) is recorded in a structured audit log.

## Architecture

```
┌─────────┐    ┌────────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Agent   │───>│   types    │───>│  infer   │───>│  check   │───>│  render  │
│ (future) │    │   (IR)     │    │ (effects)│    │ (verify) │    │  (bash)  │
└─────────┘    └────────────┘    └──────────┘    └──────────┘    └──────────┘
                                                      │               │
                                                 ┌────┴────┐    ┌────┴────┐
                                                 │ policy  │    │  exec   │
                                                 │ (authz) │    │(run/dry)│
                                                 └─────────┘    └─────────┘
                                                      │               │
                                                 ┌────┴──────┐  ┌────┴────┐
                                                 │path_check │  │  audit  │
                                                 │(normalize)│  │  (log)  │
                                                 └───────────┘  └─────────┘
                                                      │
                                                 ┌────┴───────┐
                                                 │policy_load │
                                                 │  (JSON)    │
                                                 └────────────┘
```

### Modules

| Module | File | Trusted | Role |
|--------|------|---------|------|
| Types | `lib/types.ml` | Yes | IR variants, effects, policy, proof, typed errors, plan types |
| Path_check | `lib/path_check.ml` | Yes | Path normalization + segment-based containment |
| Infer | `lib/infer.ml` | Yes | Deterministic effect inference from IR |
| Policy | `lib/policy.ml` | Yes | Per-effect authorization against policy |
| Check | `lib/check.ml` | Yes | Certificate validator (core trusted component) |
| Policy_load | `lib/policy_load.ml` | Partial | JSON policy file parsing with validation |
| Render | `lib/render.ml` | Partial | Bash rendering with shell quoting; MCP routing |
| Audit | `lib/audit.ml` | Partial | Structured audit records, text + JSON formatting |
| Plan | `lib/plan.ml` | Partial | Structured dry-run execution plans |
| Exec | `lib/exec.ml` | Partial | Check → render → execute pipeline |

## Policy File Format

Policies are JSON files. All fields are optional — missing fields default
to empty lists, which means **deny-by-default**.

```json
{
  "readable_paths": ["/home/user/src", "/usr/share/doc"],
  "writable_paths": ["/home/user/src", "/tmp"],
  "allowed_bins":   ["grep", "curl", "find"],
  "allowed_hosts":  ["example.com", "api.github.com"],
  "allowed_mcp":    [["files", "read_file"], ["search", "query"]]
}
```

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `readable_paths` | string array | `[]` | Directories the agent may read from |
| `writable_paths` | string array | `[]` | Directories the agent may write to |
| `allowed_bins` | string array | `[]` | Binaries the agent may execute |
| `allowed_hosts` | string array | `[]` | Hostnames the agent may contact |
| `allowed_mcp` | array of `[server, tool]` pairs | `[]` | MCP tools the agent may invoke |

An empty policy `{}` denies everything.

## CLI Usage

```bash
# Run demo with built-in policy
dune exec bin/demo.exe -- --demo

# Run demo with a custom policy file
dune exec bin/demo.exe -- --demo --policy examples/policy.json

# Load and validate a policy file only (no demo)
dune exec bin/demo.exe -- --policy examples/policy.json

# Output audit log as JSON lines
dune exec bin/demo.exe -- --demo --audit-json

# Flags
#   --policy PATH    Load policy from JSON file
#   --demo           Run sample actions through the pipeline
#   --dry-run        (default) Do not actually execute commands
#   --execute        Actually execute validated commands
#   --audit-json     Print audit log as JSON lines instead of text
```

## Audit Logging

Every check/execute decision produces a structured audit record containing:

- Sequence number
- Action (IR)
- Inferred effects (ground truth)
- Claimed effects (from proof)
- Decision (accepted / rejected with typed error)
- Rendered command or MCP summary (if accepted)
- Execution mode (dry-run, live, check-only)

Records can be formatted as:
- **Human-readable text** (default)
- **JSON lines** (`--audit-json`) for machine consumption

Both accepted and rejected actions are logged.

## Current Guarantees

1. **Effect recomputation**: The checker always recomputes effects from the IR.
2. **Proof consistency**: Claimed ≠ inferred → `ClaimedEffectsMismatch`.
3. **Policy enforcement**: Every effect must be authorized. Path effects use
   segment-based containment with normalization.
4. **Destructive gating**: `RemoveByGlob` requires `ApprovedDestructive`.
5. **No arbitrary Bash**: Actions are typed IR only.
6. **Path safety**: Segment-based containment; `..` triggers `PathTraversalBlocked`.
7. **Typed errors**: Structured `check_error` variants, not strings.
8. **Default deny**: Missing policy fields = empty = nothing allowed.
9. **Audit trail**: Every decision is recorded with full context.

## Trusted Computing Base

The security-critical code ("trusted core") is explicitly tagged with
`[TRUSTED CORE]` in module doc comments.  The `Core` facade module
re-exports exactly the TCB:

| Module | Tag | Lines | Role |
|--------|-----|-------|------|
| `types.ml` (core section) | TRUSTED CORE | ~130 | Type definitions |
| `path_check.ml` | TRUSTED CORE | ~80 | Path normalization + containment |
| `infer.ml` | TRUSTED CORE | ~35 | Effect inference |
| `policy.ml` | TRUSTED CORE | ~45 | Per-effect authorization |
| `check.ml` | TRUSTED CORE | ~50 | Certificate validation |
| **Total TCB** | | **~340** | |

Everything outside the TCB is tagged `[SUPPORT]`:

| Module | Tag | Role |
|--------|-----|------|
| `render.ml` | SUPPORT | Bash rendering |
| `pipeline.ml` | SUPPORT | Structured pipeline result |
| `plan.ml` | SUPPORT | Execution plan builder |
| `exec.ml` | SUPPORT | Check → render → execute |
| `audit.ml` | SUPPORT | Audit record formatting |
| `policy_load.ml` | SUPPORT | JSON policy file parsing |
| `core.ml` | facade | Re-exports TCB modules |

**Why this separation matters:** A bug in any SUPPORT module cannot
cause an unauthorized action to pass `Check.check`.  The checker's
correctness depends only on the five TCB modules.  This makes the
security argument tractable: instead of auditing ~2000 lines, you
audit ~340 lines.  The TCB aligns with the formal specification in
[`docs/formal-core.md`](docs/formal-core.md).

## Formal Verification

[`docs/formal-core.md`](docs/formal-core.md) defines the formal model.
[`formal/`](formal/) contains a Lean 4 mechanization where **all 6
security theorems are proved**:

| # | Theorem | Status |
|---|---------|--------|
| 1 | Effect soundness: accepted ⟹ claimed = inferred | **Proved** |
| 2 | Policy soundness: accepted ⟹ all effects authorized | **Proved** |
| 3 | Approval soundness: accepted + destructive ⟹ approval present | **Proved** |
| 4 | MCP authorization: mcpCall accepted ⟹ tool in policy | **Proved** |
| 5 | Path traversal safety: trivially true (paths are segments) | **Proved** |
| 6 | Default deny: empty policy rejects everything | **Proved** |

### OCaml ↔ Lean correspondence

The OCaml and Lean implementations are aligned:

| Aspect | OCaml | Lean | Status |
|--------|-------|------|--------|
| Effect comparison | `<>` (canonical list equality) | `≠` (DecidableEq) | **Aligned** |
| Effect ordering | Deterministic per-variant | Same order | **Aligned** |
| Policy membership | `List.mem` | `∈` (decidable) | **Aligned** |
| Path containment | `segments_within` after `normalize` | `List.isPrefixOf` | **Aligned** (see below) |
| Path representation | Raw `string` → `normalize` → segments | `List String` (pre-normalized) | **Abstraction gap** |

### Canonical effect ordering

`infer_effects` returns effects in a fixed order per action variant:

| Action | Canonical effect list |
|--------|----------------------|
| `GrepRecursive` | `[ReadPath root; ExecBin "grep"; WritePath output]` |
| `RemoveByGlob` | `[ExecBin "find"; WritePath root]` |
| `CurlToFile` | `[ExecBin "curl"; NetTo host; WritePath output]` |
| `McpCall` | `[McpUse (server, tool)]` |

The checker compares claimed effects against this canonical list using
structural list equality.  Reordered effects are rejected.  This matches
the Lean model exactly.

### Path normalization contract

The Lean model abstracts paths as `List String` (pre-normalized segments).
The OCaml implementation bridges raw strings to this representation via
`Path_check.normalize`, which guarantees:

1. **No "." segments** remain after normalization
2. **No ".." segments** remain after normalization
3. **Containment is prefix-on-segments** after normalization
4. **Normalization is idempotent**: `normalize(normalize(p)) = normalize(p)`

These properties are verified by dedicated "normalization contract" tests.
Path normalization remains the biggest unformalized gap — it is tested,
not proved.

## Building

Requires OCaml (tested with 5.3.0), dune (tested with 3.19), and the
`yojson` library (for policy file loading).

```bash
# Set up toolchain (adjust paths for your system)
export PATH="/c/Users/yezhu/AppData/Local/opam/.cygwin/root/bin:/c/Users/yezhu/AppData/Local/opam/default/bin:$PATH"
export OCAMLLIB="C:/Users/yezhu/AppData/Local/opam/default/lib/ocaml"

# Build everything
dune build

# Run tests (75 tests)
dune exec test/tests.exe

# Build Lean proofs
cd formal && lake build

# Run demo
dune exec bin/demo.exe -- --demo
```

## Test Coverage

75 tests organized in sections:

| Section | Count | Covers |
|---------|-------|--------|
| Original MVP | 12 | Accept/reject for all IR variants, effect mismatch, executor |
| Path normalization | 9 | Absolute, trailing slash, double slash, dots, dotdot, backslash, root, empty |
| Segment containment | 11 | Exact match, child, sibling-prefix, traversal escape, relative, nested |
| Typed errors | 6 | One test per `check_error` constructor |
| Plan module | 2 | Successful plan, rejected plan |
| Policy loading | 8 | Valid file, missing fields, malformed JSON, wrong types, bad MCP, not-object, file-not-found, deny-by-default |
| Audit logging | 4 | Accepted record, rejected record, log collection, JSON format |
| Core invariants | 8 | Theorem witnesses + reordered-effects rejection |
| Pipeline result | 3 | Accepted plan, rejected with context, mismatch with context |
| **Normalization contract** | **4** | **No-dot, no-dotdot, containment=prefix, idempotent** |
| **Correspondence corpus** | **8** | **OCaml↔Lean alignment: grep, write, destructive, MCP×2, deny, mismatch, approved** |

## Non-Goals

- Formal verification of path normalization (tested, not proved)
- Real MCP networking (simulated transport only)
- Arbitrary shell parsing
- LLM integration
- Symlink/realpath resolution (pure lexical normalization only)
- Verified extraction from Lean to OCaml
