#!/usr/bin/env bash
if [[ "${1:-}" == "-a" || "${1:-}" == "--author" ]]; then
  echo "Author: FoxSecIntel"
  echo "Repository: https://github.com/FoxSecIntel/DNS-analysis"
  echo "Tool: build.sh"
  exit 0
fi

set -euo pipefail

export PATH="${PATH}:/usr/local/go/bin:${HOME}/go/bin"

if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go not found in PATH."
  echo "Try: export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
  exit 1
fi

echo "Using $(go version)"

echo "Running tidy/format..."
go mod tidy
go fmt ./...

echo "Building Linux amd64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mail-lens .

echo "Cross-compiling Windows amd64 binary..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mail-lens.exe .

echo "Build complete:"
ls -lh mail-lens mail-lens.exe
