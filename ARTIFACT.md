# CertiClaw Artifact Manifest

**Version:** 1.0.0
**License:** MIT

## Overview

CertiClaw is a proof-carrying enforcement framework for AI agent
actions.  This artifact includes the OCaml runtime, Lean 4 formal
proofs, evaluation harness, and reproducible build infrastructure.

## Artifact Structure

```
CertiClaw/
├── lib/                          # OCaml library (13 modules)
│   ├── types.ml                  #   [TCB] Core type definitions
│   ├── path_check.ml             #   [TCB] Path normalization + containment
│   ├── infer.ml                  #   [TCB] Effect inference
│   ├── policy.ml                 #   [TCB] Per-effect authorization
│   ├── check.ml                  #   [TCB] Certificate checker
│   ├── render.ml                 #   Bash rendering
│   ├── plan.ml                   #   Execution plan builder
│   ├── pipeline.ml               #   Structured pipeline result
│   ├── exec.ml                   #   Check → render → execute
│   ├── audit.ml                  #   Audit logging
│   ├── policy_load.ml            #   JSON policy loading
│   ├── core.ml                   #   TCB facade
│   └── eval_corpus.ml            #   Evaluation cases
├── formal/                       # Lean 4 formalization
│   └── CertiClaw/
│       ├── Types.lean            #   Datatypes
│       ├── Infer.lean            #   Effect inference
│       ├── Policy.lean           #   Authorization
│       ├── Check.lean            #   Check judgment
│       ├── Theorems.lean         #   6 security theorems
│       ├── Normalize.lean        #   Normalization definitions
│       ├── NormalizeTheorems.lean #   6 normalization theorems
│       └── PathFrontend.lean     #   6 frontend theorems
├── test/tests.ml                 # 75 unit tests
├── eval/run_eval.ml              # 29-case evaluation harness
├── bin/demo.ml                   # CLI demo
├── examples/policy.json          # Example policy file
├── docs/formal-core.md           # Formal specification
├── .github/workflows/ci.yml      # CI workflow
├── Dockerfile                    # Reproducible build
├── run_all.sh                    # One-command validation
├── run_tests.sh                  # OCaml tests only
├── run_proofs.sh                 # Lean proofs only
├── LICENSE                       # MIT
├── RELEASE_CHECKLIST.md          # Validation guide
└── ARTIFACT.md                   # This file
```

## Verification Claims

### Machine-Checked (Lean 4)

18 theorems, all proved:

| Category | # | Theorems |
|----------|---|----------|
| Security | 6 | effect soundness, policy soundness, approval soundness, MCP authorization, path traversal safety, default deny |
| Normalization | 6 | no-dot, no-dotdot, no-empty, idempotent, containment stability, traversal consumed |
| Frontend | 6 | split nonempty, split no-slash, filter no-empty, filter preserves, pipeline IsNormalized, pipeline idempotent |

### Tested (OCaml)

| Suite | Count | Coverage |
|-------|-------|----------|
| Unit tests | 75 | All checker paths, path normalization, policy loading, audit |
| Evaluation corpus | 29 | 7 benign + 17 attacks + 5 scalability |

### Trusted Computing Base

5 modules, ~340 LOC. Listed in `lib/` with `[TCB]` markers above.
A bug in any non-TCB module cannot cause an unauthorized action to
pass `Check.check`.

## Validation

```bash
# Option 1: Local
./run_all.sh

# Option 2: Docker
docker build -t certiclaw .
docker run --rm certiclaw

# Option 3: CI
# Push to GitHub — Actions run automatically
```

## Expected Results

- Unit tests: **75 passed, 0 failed**
- Evaluation: **29 passed, 0 failed** (7 benign, 17 attack, 5 scale)
- Lean proofs: **Build completed successfully** (18 theorems)
- Core check time: **< 15 us** per case (10k iterations average)
