#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  domain-emailsecurityproviders.sh [-f input_file]

Options:
  -f FILE   Input file with one domain per line (default: maildomains.txt)
EOF
}

input_file="maildomains.txt"
while getopts ":f:h" opt; do
  case "$opt" in
    f) input_file="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option -$OPTARG"; usage; exit 1 ;;
  esac
done

[[ -f "$input_file" ]] || { echo "Error: $input_file does not exist."; exit 1; }

printf "%-30s | %-45s | %-20s\n" "Domain" "MX Host" "Provider"
printf "%-30s-+-%-45s-+-%-20s\n" "------------------------------" "---------------------------------------------" "--------------------"

while IFS= read -r domain || [[ -n "$domain" ]]; do
  [[ -z "$domain" ]] && continue
  mapfile -t mx_hosts < <(dig MX "$domain" +short | awk '{print $2}' | sed 's/\.$//' )

  if [[ ${#mx_hosts[@]} -eq 0 ]]; then
    printf "%-30s | %-45s | %-20s\n" "$domain" "No MX records found" "N/A"
    continue
  fi

  for mx in "${mx_hosts[@]}"; do
    lower="${mx,,}"
    provider="Internal"
    [[ "$lower" =~ outlook|microsoft ]] && provider="Microsoft"
    [[ "$lower" =~ amazon|aws ]] && provider="Amazon"
    [[ "$lower" =~ iptwins ]] && provider="IP Twins"
    [[ "$lower" =~ fireeye ]] && provider="FireEye"
    [[ "$lower" =~ spamora ]] && provider="Spamora"
    [[ "$lower" =~ proofpoint ]] && provider="Proofpoint"

    printf "%-30s | %-45s | %-20s\n" "$domain" "$mx" "$provider"
  done
done < "$input_file"
