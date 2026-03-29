# domain-posture (Go)

`domain-posture` performs multi-threaded DNS and security posture reconnaissance for one or more domains.

## Features

- Single-domain mode (`--domain`)
- File input mode (`--file`, newline-delimited)
- Worker pool concurrency (`--concurrency`, default `10`)
- Per-domain timeout protection (8 seconds)
- DNS resolution (`A` and `AAAA`)
- HTTPS reachability and redirect target capture
- `/.well-known/security.txt` status check
- Security header capture:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
- TLS certificate expiry and days remaining
- WHOIS creation date extraction and domain age (days)
- Human-readable table output (default)
- JSON output (`--json`)

## Build

```bash
cd tools/domain-posture-go
./build.sh
```

## Usage

```bash
# Single domain
./domain-posture --domain example.com

# Batch from file
./domain-posture --file domains.txt --concurrency 20

# JSON output
./domain-posture --file domains.txt --json
```

## Notes

- WHOIS parsing can vary by registrar format. When date parsing fails, the error is reported in the row without stopping the whole batch.
- Output errors are per-domain and non-fatal to the overall run.
