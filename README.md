# 🧠 DNS-analysis

A collection of simple Bash scripts for performing DNS reconnaissance and discovery. Useful for OSINT, threat hunting, vulnerability management, and network security reviews.

---

## 🚀 Features

- Perform NS, MX, A, AAAA, TXT, and CNAME lookups
- Identify open resolvers
- Get whois and domain metadata
- Quickly parse DNS responses

---

## 📦 Requirements

These scripts are designed to run on Linux/macOS systems with common CLI tools:
- `dig`
- `host`
- `whois`
- `awk`, `sed`, `grep`

---

## 🛠️ Usage

All scripts are Bash. No install needed.

Example:
```bash
bash dns-lookup.sh example.com

