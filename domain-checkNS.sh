#!/bin/bash

# Define list of DNS server hostnames to check against
dns_servers=("ns1.example.com" "ns2.example.com" "ns3.example.com")

# Check if domain name is provided as command line argument
if [ $# -eq 0 ]; then
  echo "Please provide a domain name as a command line argument."
  exit 1
fi

domain=$1

# Extract name servers for domain using dig
ns=$(dig +short NS $domain)

# Check if any name servers were found
if [ -z "$ns" ]; then
  echo "No name servers found for $domain."
  exit 1
fi

# Loop through list of DNS server hostnames and compare against name servers for domain
for server in "${dns_servers[@]}"
do
  if echo "$ns" | grep -q "$server"; then
    echo -e "\033[32mMatch found: $server is a name server for $domain.\033[0m"
  else
    echo -e "\033[31mNo match found: $server is not a name server for $domain.\033[0m"
    errors+=("$server")
  fi
done

# Check for errors and display actual name servers if there are any
if [ ${#errors[@]} -ne 0 ]; then
  echo -e "\n\033[31mThe following name servers were found for $domain:\033[0m"
  echo "$ns"
fi
