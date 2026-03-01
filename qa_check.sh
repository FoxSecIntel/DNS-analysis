#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

HIDDEN_MESSAGE_B64="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$HIDDEN_MESSAGE_B64" | base64 --decode
  exit 0
fi

if [[ "${1:-}" == "-v" || "${1:-}" == "--version" ]]; then
  echo "qa_check.sh $VERSION"
  exit 0
fi


repo_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$repo_dir"

echo "[1/3] bash -n syntax checks"
for f in ./*.sh; do
  [[ -f "$f" ]] || continue
  bash -n "$f"
  echo "  OK  $f"
done

echo "[2/3] python syntax checks"
for f in ./*.py; do
  [[ -f "$f" ]] || continue
  python3 -m py_compile "$f"
  echo "  OK  $f"
done

if command -v shellcheck >/dev/null 2>&1; then
  echo "[3/3] shellcheck"
  shellcheck ./*.sh
else
  echo "[3/3] shellcheck skipped (not installed)"
fi

echo "QA checks complete."
