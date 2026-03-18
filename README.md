# CertiClaw

A proof-carrying agent execution framework in OCaml.

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

The security-critical code is:

| Module | Lines | What it does |
|--------|-------|-------------|
| `types.ml` | ~160 | Defines the type language |
| `path_check.ml` | ~80 | Path normalization + containment |
| `infer.ml` | ~30 | Effect inference |
| `policy.ml` | ~40 | Authorization checks |
| `check.ml` | ~50 | Certificate validation |
| **Total** | **~360** | |

Everything else (rendering, execution, policy loading, audit, CLI) is
outside the trusted core. A bug in those modules cannot cause an
unauthorized action to pass the checker.

## Building

Requires OCaml (tested with 5.3.0), dune (tested with 3.19), and the
`yojson` library (for policy file loading).

```bash
# Set up toolchain (adjust paths for your system)
export PATH="/c/Users/yezhu/AppData/Local/opam/.cygwin/root/bin:/c/Users/yezhu/AppData/Local/opam/default/bin:$PATH"
export OCAMLLIB="C:/Users/yezhu/AppData/Local/opam/default/lib/ocaml"

# Build everything
dune build

# Run tests (52 tests)
dune exec test/tests.exe

# Run demo
dune exec bin/demo.exe -- --demo
```

## Test Coverage

52 tests organized in sections:

| Section | Count | Covers |
|---------|-------|--------|
| Original MVP | 12 | Accept/reject for all IR variants, effect mismatch, executor |
| Path normalization | 9 | Absolute, trailing slash, double slash, dots, dotdot, backslash, root, empty |
| Segment containment | 11 | Exact match, child, sibling-prefix, traversal escape, relative, nested |
| Typed errors | 6 | One test per `check_error` constructor |
| Plan module | 2 | Successful plan, rejected plan |
| Policy loading | 8 | Valid file, missing fields, malformed JSON, wrong types, bad MCP, not-object, file-not-found, deny-by-default |
| Audit logging | 4 | Accepted record, rejected record, log collection, JSON format |

## Non-Goals

- Coq/Lean formal verification (planned for later)
- Real MCP networking (simulated transport only)
- Arbitrary shell parsing
- LLM integration
- Symlink/realpath resolution (pure lexical normalization only)
