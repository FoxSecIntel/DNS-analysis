#!/bin/bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$repo_dir"

echo "[1/2] bash -n syntax checks"
for f in ./*.sh; do
  [[ -f "$f" ]] || continue
  bash -n "$f"
  echo "  OK  $f"
done

if command -v shellcheck >/dev/null 2>&1; then
  echo "[2/2] shellcheck"
  shellcheck ./*.sh
else
  echo "[2/2] shellcheck skipped (not installed)"
fi

echo "QA checks complete."
