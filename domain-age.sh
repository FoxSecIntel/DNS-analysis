#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

HIDDEN_MESSAGE_B64="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$HIDDEN_MESSAGE_B64" | base64 --decode
  exit 0
fi

if [[ "${1:-}" == "-v" || "${1:-}" == "--version" ]]; then
  echo "domain-age.sh $VERSION"
  exit 0
fi


usage() {
  echo "Usage: domain-age.sh <domain>"
}

[[ $# -ge 1 ]] || { usage; exit 1; }
domain="$1"

if [[ "$domain" == *.uk ]]; then
  search_string="Registered on:"
else
  search_string="Creation Date:"
fi

creation_line="$(whois "$domain" | grep -i "$search_string" | head -n1 || true)"
[[ -n "$creation_line" ]] || { echo "Could not determine creation date for $domain"; exit 1; }

creation_date="$(echo "$creation_line" | cut -d':' -f2- | xargs)"
[[ "$domain" != *.uk ]] && creation_date="${creation_date%%T*}"

parsed_date="$(date -d "$creation_date" +%s 2>/dev/null || true)"
[[ -n "$parsed_date" ]] || { echo "Could not parse creation date: $creation_date"; exit 1; }

current_date=$(date +%s)
time_diff=$((current_date - parsed_date))

years=$((time_diff / 31536000))
days=$((time_diff % 31536000 / 86400))
hours=$((time_diff % 86400 / 3600))

echo "The domain $domain is $years years, $days days, and $hours hours old."
echo "Created on: $creation_date"
