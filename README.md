# CertiClaw

A proof-carrying agent execution framework in OCaml.

## Purpose

CertiClaw prevents AI agents from executing unauthorized side effects.
Instead of trusting natural-language promises, it requires every action
to pass through a typed pipeline:

```
Typed IR  →  Effect Inference  →  Certificate Check  →  Render / Execute
```

The agent must supply a **proof certificate** alongside each action.  The
checker independently infers effects from the IR and verifies that:

1. The proof's claimed effects match the inferred effects exactly.
2. Every effect is authorized by the active policy.
3. Destructive actions carry explicit approval.

Only validated actions can be rendered to Bash or dispatched via MCP.

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
                                                      │
                                                 ┌────┴──────┐
                                                 │path_check │
                                                 │(normalize)│
                                                 └───────────┘
```

### Modules

| Module | File | Trusted | Role |
|--------|------|---------|------|
| Types | `lib/types.ml` | Yes | IR variants, effects, policy, proof, typed errors, plan types |
| Path_check | `lib/path_check.ml` | Yes | Path normalization + segment-based containment |
| Infer | `lib/infer.ml` | Yes | Deterministic effect inference from IR |
| Policy | `lib/policy.ml` | Yes | Per-effect authorization against policy |
| Check | `lib/check.ml` | Yes | Certificate validator (core trusted component) |
| Render | `lib/render.ml` | Partial | Bash rendering with shell quoting; MCP routing |
| Plan | `lib/plan.ml` | Partial | Structured dry-run execution plans |
| Exec | `lib/exec.ml` | Partial | Check → render → execute pipeline |

## Current Guarantees

These properties hold by construction in the current codebase:

1. **Effect recomputation**: The checker always calls `Infer.infer_effects`
   to compute ground-truth effects.  It never trusts `proof.claimed_effects`
   directly.

2. **Proof consistency**: If claimed effects ≠ inferred effects, the action
   is rejected with `ClaimedEffectsMismatch`.

3. **Policy enforcement**: Every inferred effect must be authorized by the
   policy.  Path effects use segment-based containment with normalization.

4. **Destructive gating**: `RemoveByGlob` always requires an
   `ApprovedDestructive` token.

5. **No arbitrary Bash**: Actions are expressed in a typed IR.  Only the
   renderer converts them to shell commands, and only after checking.

6. **Path safety**: Path containment operates on normalized segments, not
   byte prefixes.  `/workspace/reports2` is correctly distinguished from
   `/workspace/reports`.  Paths containing `..` segments trigger
   `PathTraversalBlocked` before authorization.

7. **Typed errors**: Checker rejections use structured `check_error` variants,
   not ad-hoc strings.  Callers can match on exact error constructors.

## Path Normalization

The `Path_check` module normalizes paths before containment checks:

- Backslashes → forward slashes
- Doubled slashes collapsed
- `.` segments removed
- `..` segments resolved lexically (cannot escape above root)
- Containment compares path *segments*, not string prefixes

**Known limitations** (documented, not bugs):
- No symlink resolution (pure lexical; would need filesystem access)
- No Windows drive-letter canonicalization
- Relative paths work but callers should prefer absolute paths

## Non-Goals

These are explicitly out of scope for the current iteration:

- Coq/Lean formal verification (planned for later)
- Real MCP networking (simulated transport only)
- Arbitrary shell parsing
- LLM integration
- Policy file loading (policies are constructed in OCaml)
- Symlink/realpath resolution

## Building

Requires OCaml (tested with 5.3.0) and dune (tested with 3.19).

```bash
# Set up toolchain (adjust paths for your system)
export PATH="/c/Users/yezhu/AppData/Local/opam/.cygwin/root/bin:/c/Users/yezhu/AppData/Local/opam/default/bin:$PATH"
export OCAMLLIB="C:/Users/yezhu/AppData/Local/opam/default/lib/ocaml"

# Build everything
dune build

# Run tests (31 tests)
dune exec test/tests.exe

# Run dry-run demo
dune exec bin/demo.exe
```

## Test Coverage

31 tests organized in sections:

| Section | Count | Covers |
|---------|-------|--------|
| Original MVP | 12 | Accept/reject for all IR variants, effect mismatch, executor |
| Path normalization | 9 | Absolute, trailing slash, double slash, dots, dotdot, backslash, root, empty |
| Segment containment | 11 | Exact match, child, sibling-prefix, traversal escape, relative, nested, has_traversal |
| Typed errors | 6 | ClaimedEffectsMismatch, UnauthorizedWrite, UnauthorizedHost, UnauthorizedMcpTool, MissingDestructiveApproval, PathTraversalBlocked |
| Plan module | 2 | Successful plan, rejected plan |

## Demo

`dune exec bin/demo.exe` runs five sample actions and prints:

1. **Valid grep** → Accepted, shows rendered `grep -R -n ...` command
2. **Remove without approval** → Rejected (MissingDestructiveApproval)
3. **Curl to disallowed host** → Rejected (UnauthorizedHost)
4. **Valid MCP call** → Accepted, shows MCP request summary
5. **Path traversal attempt** → Rejected (PathTraversalBlocked)
