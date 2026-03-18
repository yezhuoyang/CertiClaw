#!/bin/bash
# CertiClaw — Run all OCaml tests
# Usage: ./run_tests.sh

set -e
echo "=== Building CertiClaw ==="
dune build

echo ""
echo "=== Running unit tests (75 tests) ==="
dune exec test/tests.exe

echo ""
echo "=== Running evaluation corpus ==="
dune exec eval/run_eval.exe

echo ""
echo "=== All checks passed ==="
