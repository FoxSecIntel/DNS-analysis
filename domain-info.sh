#!/bin/bash
set -euo pipefail

m='wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=='

usage() {
  cat <<'EOF'
Usage:
  domain-info.sh [-a] [-j] [-N] [-c] <domain>
  domain-info.sh [--no-color] [--compact] <domain>
  domain-info.sh -h
  domain-info.sh -m

Options:
  -a            Show only CAA and TXT (auth-oriented quick view)
  -j            Output JSON
  -N, --no-color  Disable colorized output
  -c, --compact   Compact terminal output
  -h            Help
  -m            Decode hidden message
EOF
}

show_short=false
output_json=false
no_color=false
compact=false

# support long options first
argv=()
for arg in "$@"; do
  case "$arg" in
    --no-color) no_color=true ;;
    --compact) compact=true ;;
    *) argv+=("$arg") ;;
  esac
done
set -- "${argv[@]}"

while getopts ":ahmjNc" opt; do
  case "$opt" in
    a) show_short=true ;;
    j) output_json=true ;;
    N) no_color=true ;;
    c) compact=true ;;
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
if $no_color; then
  RED=''; GREEN=''; BLUE=''; NC=''
fi

digq() {
  local rr="$1"
  local name="$2"
  dig +time=3 +tries=1 "$rr" "$name" +short 2>/dev/null | grep -v '^;' || true
}

to_array() {
  local data="$1"
  mapfile -t _arr < <(printf '%s\n' "$data" | sed '/^$/d')
}

print_section() {
  local title="$1"
  local color="$2"
  local data="$3"
  local count
  count=$(printf '%s\n' "$data" | sed '/^$/d' | wc -l)

  if $compact; then
    if [[ "$count" -eq 0 ]]; then
      printf "%s(%d): (no records found)\n" "$title" "$count"
    else
      printf "%s(%d): %s\n" "$title" "$count" "$(printf '%s' "$data" | tr '\n' '|' | sed 's/|$//' )"
    fi
    return
  fi

  echo -e "${color}== ${title} ==${NC}"
  if [[ "$count" -eq 0 ]]; then
    echo "  (no records found)"
  else
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "  - $line"
    done <<< "$data"
  fi
  echo
}

soa="$(digq SOA "$DOMAIN")"
ns="$(digq NS "$DOMAIN")"
mx="$(digq MX "$DOMAIN")"
caa="$(digq CAA "$DOMAIN")"
txt="$(digq TXT "$DOMAIN")"
www_a="$(digq A "www.${DOMAIN}")"
www_aaaa="$(digq AAAA "www.${DOMAIN}")"

if $output_json; then
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
  print_section "CAA" "$BLUE" "$caa"
  print_section "TXT" "$GREEN" "$txt"
else
  print_section "SOA" "$BLUE" "$soa"
  print_section "NS" "$GREEN" "$ns"
  print_section "MX" "$RED" "$mx"
  print_section "WWW_A" "$BLUE" "$www_a"
  print_section "WWW_AAAA" "$BLUE" "$www_aaaa"
fi

# Summary
count_lines() { printf '%s\n' "$1" | sed '/^$/d' | wc -l; }
if $show_short; then
  printf "Summary: CAA:%d TXT:%d\n" "$(count_lines "$caa")" "$(count_lines "$txt")"
else
  printf "Summary: SOA:%d NS:%d MX:%d WWW_A:%d WWW_AAAA:%d\n" \
    "$(count_lines "$soa")" "$(count_lines "$ns")" "$(count_lines "$mx")" "$(count_lines "$www_a")" "$(count_lines "$www_aaaa")"
fi
