#!/bin/bash

# File containing the list of domain names
file="domains.txt"

# Initialize variables
domains=()
registered=0
not_registered=0

# Check if the file exists
if [[ ! -f $file ]]; then
    echo "Error: the file $file does not exist."
    exit 1
fi

# Read the file and store the domain names in an array
while read -r line; do
    domains+=($line)
done < "$file"

# Get the number of domains
num_domains=${#domains[@]}

# Progress indicator
echo "Checking $num_domains domains..."

# Loop through each domain
for ((i=0; i<num_domains; i++)); do
  domain=${domains[i]}

  # Use the 'whois' command to check if the domain is registered
  output=$(whois $domain 2>&1)

  if echo $output | grep -q "is free"
  then
    not_registered=$((not_registered + 1))
    echo -e "\n$domain is not registered."
  else
    registered=$((registered + 1))
    echo -n "."
  fi

  # Print progress indicator
  echo -en "\r$((i+1))/$num_domains domains checked"
done

# Print summary
echo -e "\n\nSummary:"
echo "$registered domains are registered"
echo "$not_registered domains are not registered"
