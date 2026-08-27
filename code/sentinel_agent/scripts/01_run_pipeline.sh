#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-/mnt/vmshare/sentinel}"
PROJECT_PATH="${PROJECT_ROOT}/samples/vulnerable_project"

cd "$PROJECT_ROOT"

echo "=== SENTINEL Part 6: Run full five-agent pipeline ==="
echo "[INFO] Project root: $PROJECT_ROOT"
echo "[INFO] Target project: $PROJECT_PATH"

python3 main.py --project "$PROJECT_PATH"

echo
echo "=== Key summary from final_report.md ==="
grep -n "Overall Risk\|Confirmed Findings\|ASan Confirmed Findings" outputs/final_report.md || true
