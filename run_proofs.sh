#!/bin/bash
# CertiClaw — Build Lean 4 formal proofs
# Usage: ./run_proofs.sh
# Requires: Lean 4.28.0 (via elan)

set -e
echo "=== Building Lean formal model ==="
cd formal
lake build
echo ""
echo "=== All 18 theorems verified ==="
