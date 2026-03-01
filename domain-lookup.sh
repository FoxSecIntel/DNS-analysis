#!/bin/bash
set -euo pipefail

VERSION="1.2.0"

HIDDEN_MESSAGE_B64="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$HIDDEN_MESSAGE_B64" | base64 --decode
  exit 0
fi

if [[ "${1:-}" == "-v" || "${1:-}" == "--version" ]]; then
  echo "domain-lookup.sh $VERSION"
  exit 0
fi


usage() {
  cat <<'EOF'
Usage:
  domain-lookup.sh -d <domain> [-n names_file] [-o output_file]

Options:
  -d DOMAIN      Base domain (required)
  -n NAMES_FILE  Subdomain labels file (default: names.txt)
  -o OUTPUT      Output file (default: dns_lookup_results.txt)
EOF
}

domain=""
names_file="names.txt"
out_file="dns_lookup_results.txt"
public_file="dlr-public.txt"

while getopts ":d:n:o:h" opt; do
  case "$opt" in
    d) domain="$OPTARG" ;;
    n) names_file="$OPTARG" ;;
    o) out_file="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option -$OPTARG"; usage; exit 1 ;;
  esac
done

[[ -n "$domain" ]] || { echo "Error: domain is required"; usage; exit 1; }
[[ -f "$names_file" ]] || { echo "Error: names file not found: $names_file"; exit 1; }

: > "$out_file"
: > "$public_file"

line_count=0; public_ip_count=0; private_ip_count=0; error_count=0

is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]
}

while IFS= read -r name || [[ -n "$name" ]]; do
  [[ -z "$name" ]] && continue
  ((line_count+=1))
  fqdn="${name}.${domain}"
  echo -n "."

  lookup="$(host "$fqdn" 2>&1 || true)"
  echo "$lookup" >> "$out_file"

  if echo "$lookup" | grep -qiE 'not found|NXDOMAIN|failed'; then
    ((error_count+=1))
    continue
  fi

  mapfile -t ips < <(echo "$lookup" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

  if [[ ${#ips[@]} -eq 0 ]]; then
    ((error_count+=1))
    continue
  fi

  for ip in "${ips[@]}"; do
    if is_private_ip "$ip"; then
      ((private_ip_count+=1))
    else
      ((public_ip_count+=1))
      echo "$ip" >> "$public_file"
    fi
  done
done < "$names_file"

echo
printf "Number of lines: %d\n" "$line_count"
printf "Number of public IPs: %d\n" "$public_ip_count"
printf "Number of private IPs: %d\n" "$private_ip_count"
printf "Number of errors: %d\n" "$error_count"
printf "Output: %s\n" "$out_file"
printf "Public IP list: %s\n" "$public_file"
