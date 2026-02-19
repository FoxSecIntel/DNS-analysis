#!/bin/bash
set -euo pipefail

m='wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=='

usage() {
  cat <<'EOF'
Usage:
  domain-info.sh [-a] [-j] <domain>
  domain-info.sh -h
  domain-info.sh -m

Options:
  -a  Show only CAA and TXT (auth-oriented quick view)
  -j  Output JSON
  -h  Help
  -m  Decode hidden message
EOF
}

show_short=false
output_json=false

while getopts ":ahmj" opt; do
  case "$opt" in
    a) show_short=true ;;
    j) output_json=true ;;
    h) usage; exit 0 ;;
    m) echo "$m" | base64 --decode; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG"; usage; exit 1 ;;
  esac
done
shift $((OPTIND-1))

[[ $# -ge 1 ]] || { echo "Please specify a domain"; usage; exit 1; }
DOMAIN="$1"

[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || {
  echo "Invalid domain format: $DOMAIN"
  exit 1
}

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;36m'; NC='\033[0m'

digq() {
  local rr="$1"
  local name="$2"
  dig +time=3 +tries=1 "$rr" "$name" +short 2>/dev/null | grep -v '^;' || true
}

if $output_json; then
  # shell-safe JSON output using jq
  soa="$(digq SOA "$DOMAIN")"
  ns="$(digq NS "$DOMAIN")"
  mx="$(digq MX "$DOMAIN")"
  caa="$(digq CAA "$DOMAIN")"
  txt="$(digq TXT "$DOMAIN")"
  www_a="$(digq A "www.${DOMAIN}")"
  www_aaaa="$(digq AAAA "www.${DOMAIN}")"

  jq -n \
    --arg domain "$DOMAIN" \
    --arg soa "$soa" \
    --arg ns "$ns" \
    --arg mx "$mx" \
    --arg caa "$caa" \
    --arg txt "$txt" \
    --arg www_a "$www_a" \
    --arg www_aaaa "$www_aaaa" \
    '{
      domain: $domain,
      soa: ($soa | split("\n") | map(select(length>0))),
      ns: ($ns | split("\n") | map(select(length>0))),
      mx: ($mx | split("\n") | map(select(length>0))),
      caa: ($caa | split("\n") | map(select(length>0))),
      txt: ($txt | split("\n") | map(select(length>0))),
      www_a: ($www_a | split("\n") | map(select(length>0))),
      www_aaaa: ($www_aaaa | split("\n") | map(select(length>0)))
    }'
  exit 0
fi

if $show_short; then
  echo -e "${BLUE}CAA record:${NC}"; digq CAA "$DOMAIN"
  echo -e "${GREEN}TXT record:${NC}"; digq TXT "$DOMAIN"
  exit 0
fi

echo -e "${BLUE}SOA record:${NC}"; digq SOA "$DOMAIN"

echo -e "${GREEN}NS records:${NC}"; digq NS "$DOMAIN"

echo -e "${RED}MX records:${NC}"; digq MX "$DOMAIN"

echo -e "${BLUE}WWW A record:${NC}"; digq A "www.${DOMAIN}"

echo -e "${BLUE}WWW AAAA record:${NC}"; digq AAAA "www.${DOMAIN}"
