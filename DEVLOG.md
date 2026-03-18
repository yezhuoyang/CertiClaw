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

- [ ] Policy loading from YAML/JSON config files
- [ ] Real MCP transport (JSON-RPC)
- [ ] Path canonicalization and symlink handling
- [ ] Audit logging of all check/execute decisions
- [ ] Formal verification of checker properties in Coq or Lean
- [ ] LLM integration: agent generates IR + proof from natural language
- [ ] Native compilation (fix mingw toolchain setup)
- [ ] Richer IR variants (file copy, directory creation, git operations)
