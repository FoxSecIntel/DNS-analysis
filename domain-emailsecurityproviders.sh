# File containing the list of domains
input_file="maildomains.txt"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
  echo "Error: $input_file does not exist."
  exit 1
fi

# Initialize an empty array to store the results
declare -a results

# Loop through each domain in the input file
while read domain; do
  # Find the mail servers for the domain
  mail_servers=($(dig MX $domain +short | awk '{print $2}'))

  if [ ${#mail_servers[@]} -eq 0 ]; then
    # If no MX records are found, print "No MX records found"
    email_server_domain="No MX records found"
    provider=""
    results+=( "$domain $email_server_domain $provider" )
  else
    for mail_server in "${mail_servers[@]}"; do
      # Extract the email server domain
      email_server_domain=$mail_server

      # Check for email security provider
      if echo "$email_server_domain" | grep -qE "outlook|microsoft"; then
        provider="Microsoft"
      elif echo "$email_server_domain" | grep -qE "amazon|aws"; then
        provider="Amazon"
      elif echo "$email_server_domain" | grep -qE "iptwins"; then
        provider="IP Twins"
      elif echo "$email_server_domain" | grep -qE "fireeye"; then
        provider="FireEye"
      elif echo "$email_server_domain" | grep -qE "spamora"; then
        provider="Spamora"
      elif echo "$email_server_domain" | grep -qE "proofpoint"; then
        provider="Proofpoint"
      else
        provider="Internal"
      fi

      # Add the domain, email server domain and provider to the results array
      results+=( "$domain $email_server_domain $provider" )
    done
  fi
done < "$input_file"

# Print the results in a table format
printf "%-25s | %-50s | %-30s\n" "Domain" "Email Server Domain" "Email Security Provider"
printf "%-25s | %-50s | %-30s\n" "-------" "--------------------" "----------------------"
for result in "${results[@]}"; do
  echo "$result" | awk '{printf "%-25s | %-50s | %-30s\n", $1, $2, $3}'
done
