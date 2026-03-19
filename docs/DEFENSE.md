# Defense of Baselines: Where the Paper Is Unfair

This document records where the CertiClaw paper weakens or
misrepresents the baseline systems (Nanobot and OpenClaw).
Each defense is backed by specific source code evidence.

## D1. Nanobot has an allowlist mode the paper never mentions

**Source**: `nanobot/nanobot/agent/tools/shell.py` lines 20, 37, 153-155

The ExecTool accepts `allow_patterns` in its constructor. When
configured, `_guard_command` checks the allowlist BEFORE the deny-list:

```python
if self.allow_patterns:
    if not any(re.search(p, lower) for p in self.allow_patterns):
        return "Error: Command blocked (not in allowlist)"
```

In allowlist mode, a base64-encoded `rm -rf` would NOT match any
legitimate pattern and would be blocked. The paper claims "base64
bypasses the deny-list" (true) but never tests or mentions the
allowlist mode that would catch it.

## D2. Paper cherry-picks weakest nanobot configuration

**Source**: `nanobot/SECURITY.md`, `nanobot/README.md`

The paper tests S4 (write /etc/shadow) and S6 (path traversal)
with `restrictToWorkspace=false` (the default). But:

- Nanobot's SECURITY.md recommends `restrictToWorkspace=true` for
  production deployments.
- Our own test script runs BOTH variants and the restricted version
  REJECTS both S4 and S6.
- The paper table only reports the unrestricted (weaker) result.

Fair approach: Add a "Nanobot (recommended)" column showing that
with recommended config, S4 and S6 are REJECTED.

## D3. SSRF "bypass" is a mischaracterization

**Source**: `nanobot/nanobot/security/network.py` lines 10-62

Nanobot's SSRF protection is designed to block access to INTERNAL
services (private IP ranges, cloud metadata endpoints, loopback).
Calling evil.com "passing" the SSRF check is like saying a firewall
"fails" because it allows outbound HTTP to the internet.

The SSRF module also has `validate_resolved_url` (lines 65-94) for
catching SSRF via HTTP redirects — a sophisticated defense the
paper does not acknowledge.

Blocking arbitrary external domains is a different security control
(URL allowlisting / content filtering) that neither the paper nor
CertiClaw itself addresses at the OS level.

## D4. "find -delete" is not equivalent to "rm -rf"

The paper frames `find /tmp -name '*.log' -delete` as a dangerous
destructive operation. But:

- It only deletes files matching `-name '*.log'` — not entire
  directory trees.
- With `restrictToWorkspace=true`, the `/tmp` path would be blocked.
- CertiClaw's own `RemoveByGlob` does essentially the same thing
  (`find <root> -name '*<suffix>' -delete`).

## D5. "No approval model" ignores compensating controls

The paper says "Approval model: None" for Nanobot. This ignores:

- Channel ACLs with deny-by-default (since v0.1.4.post4)
- 60-second default / 600-second max execution timeout
- 10KB output truncation (limits data exfiltration)
- Allowlist mode for exec
- Workspace sandboxing
- SSRF with redirect protection

These are not an "approval model" but they are substantial
compensating controls the paper dismisses.

## D6. OpenClaw "18 vulnerabilities" is inflated

Of the 18 claimed vulnerabilities:

### Only 3-4 of 11 "missing wrappers" are clearly exploitable

- `xargs`, `find -exec`, `parallel`: YES, these dispatch commands.
- `watch`: YES, repeatedly executes commands.
- `awk '{print $1}' file`: Does NOT call system(). Awk's system()
  must be explicitly used in the script text. Typical agent use of
  awk is text processing, not command dispatch.
- `sed`, `perl`: Text processing in typical agent use.
- `nmap`: Network scanner, not a command dispatcher.
- `strace`, `ltrace`: Debugging tools, not typical agent commands.
- `script`: Records terminal sessions, arguable.

Fair count: 4-5 clearly exploitable, not 11.

### Variable expansion is mitigated by allowlist mode

In `ExecSecurity=allowlist`, the RESOLVED binary path is checked.
`cat $HOME/.ssh/id_rsa` — the binary is `cat`, which is checked
against safe-bins. The variable expansion changes the ARGUMENT,
not the binary. The security decision (which binary runs) is
unaffected unless the variable is in the command position.

### Glob over-matching is likely mitigated by path.resolve()

OpenClaw's command resolution calls `path.resolve()` on the binary
path BEFORE matching. `path.resolve()` normalizes `../`, so
`/usr/local/bin/../../../etc/shadow` becomes `/etc/shadow`, which
does NOT match `/usr/local/bin/**`. Our test extracted the glob
matcher in isolation without the resolve step.

### OpenClaw's default is deny-all

The paper tests `ExecSecurity=full` (most permissive) to find
vulnerabilities. But the DEFAULT is `deny` — which blocks everything.
With `ExecAsk=on-miss` (default), even unknown commands in allowlist
mode prompt the user. The paper's framing that OpenClaw is "unsafe
when usable" ignores that the DEFAULT is safe.

### Docker sandbox ignored

OpenClaw can run commands in Docker containers with capability
dropping, seccomp filtering, and bind-mount validation. Even if
the shell parser is bypassed, sandbox containment limits the
blast radius. The paper does not mention sandbox mode at all in
the vulnerability analysis.

## D7. Test methodology: extracted functions, not integration tests

Our "empirical" tests extract individual security functions into
standalone scripts. This misses:

- The interaction of multiple defense layers (ExecSecurity +
  ExecAsk + ExecHost)
- The approval workflow (two-phase registration, SHA256 binding)
- The Docker sandbox boundary
- The actual command resolution pipeline (which calls path.resolve
  BEFORE glob matching)

A fair test would run the actual frameworks end-to-end with
recommended configurations.

## D8. OpenClaw safe-bin hardening single-quotes all argv tokens

**Source**: `openclaw/src/infra/exec-approvals-analysis.ts` line 633

When a command is matched as a safe-bin, `buildSafeBinsShellCommand`
rebuilds the command by single-quoting every argv token:
```typescript
argv.map((token) => shellEscapeSingleArg(token)).join(" ")
```

This means `$HOME` in `cat $HOME/.ssh/id_rsa` gets single-quoted
to `'$HOME'`, PREVENTING shell expansion entirely. Our test checked
the pipeline token filter in isolation and missed this critical
runtime hardening. The 3 "variable expansion" vulns are not
exploitable through the safe-bin path.

## D9. STRUCT-1 test is a hardcoded opinion, not empirical

**Source**: `eval/test_openclaw_deep.mjs` line 236

```javascript
test("STRUCT-1", "Approved command string != analyzed segments", () => {
  return { outcome: "VULN", detail: "..." };
});
```

This "test" unconditionally returns "VULN" with a hardcoded string.
It executes nothing. The paper claims "all confirmed by executing
extracted security functions" but this is an assertion, not evidence.

## D10. STRUCT-2 and STRUCT-3 double-count wrapper findings

STRUCT-2 (xargs dispatch) and STRUCT-3 (find -exec) are the same
issues already counted as W-xargs and W-find in the "missing
wrappers" category. The paper counts each twice to inflate the
total from ~12 to 18.

## D11. OpenClaw's approval binding is command-string-exact

**Source**: `openclaw/src/infra/exec-approvals.ts` lines 38-44

The `SystemRunApprovalBinding` binds to exact argv, cwd, agentId,
sessionKey, and envHash. Even if parser and shell disagree, the
user approved the exact string that runs. The paper's "parser-shell
gap" concern is mitigated by the approval binding.

## D12. Honest vulnerability reassessment

| Paper claim | Actual exploitable | Reason |
|-------------|-------------------|--------|
| 11 missing wrappers | 2 (xargs, find -exec) | 9 are category errors (awk/sed/perl are interpreters not wrappers; nmap/strace/ltrace are debug tools) |
| 3 variable expansion | 0 | Safe-bin hardening single-quotes all argv; allowlist rejects unknown binaries |
| 1 glob over-match | 0 | path.resolve() canonicalizes traversals before glob match; test bypassed this |
| 3 parser-shell gap | 0 unique | 1 hardcoded opinion + 2 duplicates of wrapper findings |
| **18 total** | **2 genuine gaps** | Both mitigated by default on-miss approval prompting |

## Recommended Paper Changes (Updated)

1. **Reduce "18 vulnerabilities" to "2 confirmed coverage gaps +
   several design scope limitations."** The xargs and find -exec
   gaps are real. Everything else is inflated.
2. **Add "Nanobot (recommended config)" column** to Table 5.
3. **Mention nanobot's allowlist mode** in baselines section.
4. **Rename "SSRF bypass" to "SSRF scope limitation."**
5. **Acknowledge OpenClaw's safe-bin argv hardening** which
   single-quotes all tokens, preventing variable expansion.
6. **Acknowledge OpenClaw's Docker sandbox** as defense in depth.
7. **Remove STRUCT-1** (not a test) and **de-duplicate STRUCT-2/3**
   from the wrapper findings.
8. **Acknowledge default deny + on-miss** is the recommended
   operational mode, not full mode.
9. **Re-test glob over-matching** with the full resolution
   pipeline (including path.resolve) to verify our claim.
10. **Be honest about methodology**: "unit-tested extracted
    functions" not "empirical evaluation of the full systems."
