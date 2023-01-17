#!/bin/bash

# Set number of domain names to generate
num_domains=13

# List of TLDs
tlds=(com net org io edu gov)

# List of generic words
words=(book shop mall car house)

# Loop to generate the specified number of domain names
for ((i=1; i<=$num_domains; i++))
do
  # Generate random domain name
  domain_name="$(tr -dc 'a-z' < /dev/urandom | head -c 8).${tlds[RANDOM%${#tlds[@]}]}"
  main_word="${words[RANDOM%${#words[@]}]}"
  # Print the generated domain name
  echo $main_word$domain_name
done
