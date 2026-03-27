# mail-lens (Go)

High-performance domain email security provider detection.

## Features

- Dual input mode:
  - single domain: `./mail-lens example.com`
  - file input: `./mail-lens -f domains.txt --workers 20`
- Worker pool concurrency for bulk runs
- 2-second timeout-safe lookups
- MX fingerprint detection
- SPF include-based hidden provider detection
- ASN mapping for unknown/internal MX
- Table output by default, `--json` for pipelines

## Build (Linux)

```bash
cd tools/mail-lens-go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mail-lens .
```

## Cross-compile (Windows)

```bash
cd tools/mail-lens-go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o mail-lens.exe .
```
