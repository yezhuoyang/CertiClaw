# CertiClaw Release Checklist

## Prerequisites

- OCaml >= 5.3 with dune >= 3.0
- `opam install yojson`
- Lean 4.28.0 (via elan)

## Validation Commands

### 1. OCaml unit tests (75 tests)

```bash
dune build
dune exec test/tests.exe
```

Expected: `Results: 75 passed, 0 failed`

### 2. Evaluation corpus (29 cases)

```bash
dune exec eval/run_eval.exe
```

Expected:
- Benign accepted: 7 / 7
- Attacks blocked: 17 / 17
- Scale passed: 5 / 5
- All 29 passed, 0 failed

### 3. Paper-ready summary

```bash
dune exec eval/run_eval.exe -- --summary
```

### 4. Lean 4 proofs (18 theorems)

```bash
cd formal
lake build
```

Expected: `Build completed successfully`

### 5. Full validation (one command)

```bash
./run_all.sh
```

### 6. Docker (reproducible)

```bash
docker build -t certiclaw .
docker run --rm certiclaw
```

## Artifact Contents

| Component | Location | Description |
|-----------|----------|-------------|
| OCaml TCB | `lib/{types,path_check,infer,policy,check}.ml` | ~340 LOC trusted core |
| OCaml support | `lib/{render,plan,exec,audit,pipeline,policy_load,core,eval_corpus}.ml` | Runtime support |
| Lean proofs | `formal/CertiClaw/` | 8 files, 18 theorems |
| Unit tests | `test/tests.ml` | 75 tests |
| Eval corpus | `eval/run_eval.ml` | 29 cases with timing |
| Example policy | `examples/policy.json` | JSON policy file |
| Formal spec | `docs/formal-core.md` | Paper-aligned specification |

## Expected Outputs

- Unit tests: 75 passed
- Eval corpus: 29 passed (7 benign + 17 attack + 5 scale)
- Lean proofs: 18 theorems verified
- Avg check time: < 15 us per case
