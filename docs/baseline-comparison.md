# Baseline Comparison: CertiClaw vs. Nanobot vs. OpenClaw

## Overview

| Feature | CertiClaw | Nanobot | OpenClaw |
|---------|-----------|---------|----------|
| Language | OCaml + Lean 4 | Python | TypeScript |
| LOC (security core) | ~340 | ~300 | ~5,000+ |
| Formal verification | 18 Lean theorems | None | None |
| Effect inference | From typed IR | None | None |
| Certificate validation | Yes (proof-carrying) | No | No |
| Action representation | Typed IR (4 variants) | Free-form shell string | Free-form shell string |
| Policy model | Allowlist (JSON, default-deny) | Config flags + deny-list | Allowlist + ask modes |
| Path containment | Segment-based (proved) | resolve() + is_under | resolve() + relative() |
| Approval model | Typed ApprovedDestructive | None | Interactive ask (on-miss/always) |
| Audit logging | Structured (text/JSON) | Minimal (tool calls) | Security audit findings |

## Nanobot Security Model

**Architecture**: Ultra-lightweight Python agent (~1500 LOC core).
Executes shell commands via `asyncio.create_subprocess_shell()`.

**Permission system**:
- Channel-level `allowFrom` lists (user authentication)
- Global `restrictToWorkspace` flag
- Regex-based dangerous command deny-list (blocks `rm -rf /`, fork bombs, `mkfs`, etc.)
- SSRF protection via private IP blocking

**Key files**: `nanobot/agent/tools/shell.py`, `nanobot/security/network.py`

**Security gaps relevant to CertiClaw comparison**:
1. **No effect inference**: Commands are free-form strings; the system cannot reason about what effects a command will produce before execution.
2. **No certificate/proof**: The agent's intent is not declared or verified.
3. **Deny-list is bypassable**: Pattern matching on command strings is inherently fragile. Obfuscated commands can bypass regexes.
4. **No formal guarantees**: No proofs that the security checks are complete or correct.
5. **No structured audit**: Only logs tool call parameters, not inferred effects or policy decisions.

## OpenClaw Security Model

**Architecture**: Large TypeScript agent framework (~100K+ LOC total, ~5K+ LOC security).
Executes commands via parsed shell pipelines with approval workflows.

**Permission system** (three-tier):
- `ExecSecurity`: `deny` | `allowlist` | `full` — controls what commands can run
- `ExecAsk`: `off` | `on-miss` | `always` — controls when user approval is needed
- `ExecHost`: `sandbox` | `gateway` | `node` — controls where commands run

**Command analysis**: Parses shell pipelines, resolves commands to filesystem paths, checks against allowlists, handles heredocs, chain operators (`&&`, `||`, `;`).

**Dangerous tool lists**: Hardcoded sets (`DANGEROUS_ACP_TOOL_NAMES`) for tools requiring approval: `exec`, `spawn`, `shell`, `fs_write`, `fs_delete`, etc.

**Path checking**: `isPathInside()` uses `path.resolve()` + `path.relative()`. Optional `realpath` check for symlinks.

**Key files**: `src/infra/exec-approvals.ts`, `src/infra/exec-approvals-analysis.ts`, `src/security/dangerous-tools.ts`, `src/security/scan-paths.ts`

**Security gaps relevant to CertiClaw comparison**:
1. **No effect inference**: Despite sophisticated command parsing, the system cannot systematically infer what effects a command produces (read, write, network, etc.).
2. **No certificate**: The agent does not declare its intended effects; the system only checks syntactic patterns.
3. **Shell parsing is the TCB**: The security of the system depends on correctly parsing arbitrary shell syntax — a much larger and more fragile TCB than CertiClaw's 340 lines.
4. **No formal verification**: No proofs that the allowlist matching, pipeline parsing, or approval logic is correct.
5. **Approval is interactive**: Requires human in the loop for security decisions, which doesn't scale to autonomous agents.

## Key Insight: Why Proof-Carrying Is Better

All three systems must answer the same question: "Is this action safe to execute?"

| Approach | How it answers | Weakness |
|----------|---------------|----------|
| **Nanobot** | Regex deny-list on command string | Bypassable via obfuscation |
| **OpenClaw** | Parse shell → resolve commands → match allowlist | Fragile: depends on correct shell parsing |
| **CertiClaw** | Infer effects from typed IR → verify certificate → check policy | Sound: proved correct in Lean |

The fundamental difference: Nanobot and OpenClaw operate on **free-form shell strings** and must parse them to understand what they do. CertiClaw operates on a **typed IR** where effects are structurally determined — no parsing needed.
