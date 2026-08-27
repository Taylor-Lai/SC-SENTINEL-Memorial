#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-/mnt/vmshare/sentinel}"
cd "$PROJECT_ROOT"

echo "=== SENTINEL Part 6: Parse real ASan logs and update final report ==="
echo "[INFO] Project root: $PROJECT_ROOT"

echo
echo "[1/3] Check ASan logs..."
find harness_packages -name "*.log" -type f | sort

echo
echo "[2/3] Parse ASan logs..."
python3 tools/parse_asan_logs.py \
  --harness-root harness_packages \
  --output validation/asan_validation_results.json

echo
echo "[3/3] Re-run Agent E through full pipeline..."
python3 main.py --project ./samples/vulnerable_project

echo
echo "=== ASan lines in final report ==="
grep -n "ASan" outputs/final_report.md || true
