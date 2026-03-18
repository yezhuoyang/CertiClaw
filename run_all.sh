#!/bin/bash
# CertiClaw — Full artifact validation
# Runs OCaml tests, evaluation corpus, and Lean proofs.
# Usage: ./run_all.sh

set -e

echo "========================================"
echo " CertiClaw Artifact Validation"
echo "========================================"
echo ""

echo "[1/3] OCaml unit tests..."
dune build
dune exec test/tests.exe
echo ""

echo "[2/3] Evaluation corpus..."
dune exec eval/run_eval.exe
echo ""

echo "[3/3] Lean formal proofs..."
cd formal
lake build
cd ..
echo ""

echo "========================================"
echo " All checks passed."
echo "========================================"
