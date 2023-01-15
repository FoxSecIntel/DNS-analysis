#!/bin/bash

# File containing the list of domain names
file="domains.txt"

# Read the file and store the domain names in an array
domains=($(cat $file))

# Loop through each domain
for domain in ${domains[@]}
do
  # Use the 'whois' command to check if the domain is registered
  output=$(whois $domain)

  if echo $output | grep -q "is free"
  then
    echo -e "\n$domain is not registered."
  else
    echo -n "."
  fi
done
