#!/bin/bash
set -euo pipefail

VERSION="1.2.0"
if [[ "${1:-}" == "-v" || "${1:-}" == "--version" ]]; then
  echo "domain-checkNS.sh $VERSION"
  exit 0
fi


usage() {
  cat <<'EOF'
Usage:
  domain-checkNS.sh -d <domain> [-n "ns1,ns2,ns3"]

Options:
  -d DOMAIN     Domain to check (required)
  -n NS_LIST    Comma-separated expected NS list
                default: ns1.example.com,ns2.example.com,ns3.example.com
EOF
}

domain=""
expected_csv="ns1.example.com,ns2.example.com,ns3.example.com"

while getopts ":d:n:h" opt; do
  case "$opt" in
    d) domain="$OPTARG" ;;
    n) expected_csv="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option -$OPTARG"; usage; exit 1 ;;
  esac
done

[[ -n "$domain" ]] || { echo "Error: domain required"; usage; exit 1; }

mapfile -t expected < <(echo "$expected_csv" | tr ',' '\n' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')
mapfile -t found < <(dig +short NS "$domain" | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')

[[ ${#found[@]} -gt 0 ]] || { echo "No name servers found for $domain."; exit 1; }

declare -a missing=()
for ns in "${expected[@]}"; do
  if printf '%s\n' "${found[@]}" | grep -qx "$ns"; then
    echo -e "\033[32mMatch: $ns\033[0m"
  else
    echo -e "\033[31mMissing expected NS: $ns\033[0m"
    missing+=("$ns")
  fi
done

echo
echo "Actual NS for $domain:"
printf '%s\n' "${found[@]}"

if [[ ${#missing[@]} -gt 0 ]]; then
  exit 2
fi
