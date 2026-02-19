#!/bin/bash
set -euo pipefail

m='wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=='

usage() {
  cat <<'EOF'
Usage:
  domain-info.sh [-a] <domain>
  domain-info.sh -h
  domain-info.sh -m

Options:
  -a  Show only CAA and TXT
  -h  Help
  -m  Decode hidden message
EOF
}

show_short=false

while getopts ":ahm" opt; do
  case "$opt" in
    a) show_short=true ;;
    h) usage; exit 0 ;;
    m) echo "$m" | base64 --decode; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG"; usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

[[ $# -ge 1 ]] || { echo "Please specify a domain"; usage; exit 1; }
DOMAIN="$1"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;36m'; NC='\033[0m'

if $show_short; then
  echo -e "${BLUE}CAA record:${NC}"; dig CAA "$DOMAIN" +short
  echo -e "${GREEN}TXT record:${NC}"; dig TXT "$DOMAIN" +short
  exit 0
fi

echo -e "${BLUE}SOA record:${NC}"; dig SOA "$DOMAIN" +short

echo -e "${GREEN}NS records:${NC}"; dig NS "$DOMAIN" +short

echo -e "${RED}MX records:${NC}"; dig MX "$DOMAIN" +short

echo -e "${BLUE}WWW A record:${NC}"; dig A "www.${DOMAIN}" +short
