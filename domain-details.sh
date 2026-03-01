#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

__r17q_blob="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$__r17q_blob" | base64 --decode
  exit 0
fi

if [[ "${1:-}" == "-v" || "${1:-}" == "--version" ]]; then
  echo "domain-details.sh $VERSION"
  exit 0
fi


usage() {
  echo "Usage: domain-details.sh <domain>"
}

[[ $# -ge 1 ]] || { usage; exit 1; }
domain="$1"

caa="$(dig -t CAA +short "$domain")"
if [[ -n "$caa" ]]; then
  echo -e "\n\033[34mCAA record found:\033[0m\n\033[34m$caa\033[0m\n"
else
  echo "No CAA record found for $domain."
fi

dmarc="$(dig -t TXT +short "_dmarc.$domain" | tr -d '"' | tr '[:upper:]' '[:lower:]')"
if [[ -n "$dmarc" ]]; then
  echo -e "\n\033[33mDMARC record found:\033[0m\n\033[33m$dmarc\033[0m\n"
else
  echo "No DMARC record found for $domain."
fi

spf="$(dig -t TXT +short "$domain" | grep -ioE 'v=spf1[^" ]*.*' || true)"
if [[ -n "$spf" ]]; then
  echo -e "\n\033[32mSPF record found:\033[0m\n\033[32m$spf\033[0m\n"
else
  echo "No SPF record found for $domain."
fi
