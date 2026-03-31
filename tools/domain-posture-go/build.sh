#!/usr/bin/env bash
if [[ "${1:-}" == "-a" || "${1:-}" == "--author" ]]; then
  echo "Author: FoxSecIntel"
  echo "Repository: https://github.com/FoxSecIntel/DNS-analysis
  echo "Tool: build.sh"
  exit 0
fi

set -euo pipefail

cd "$(dirname "$0")"

echo "Building domain-posture for Linux amd64"
GOOS=linux GOARCH=amd64 go build -o domain-posture main.go

echo "Building domain-posture.exe for Windows amd64"
GOOS=windows GOARCH=amd64 go build -o domain-posture.exe main.go

echo "Done"
