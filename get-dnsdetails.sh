#!/bin/bash

# Check if domain name is provided as command line argument
if [ $# -eq 0 ]; then
  echo "Please provide a domain name as a command line argument."
  exit 1
fi

domain=$1

# Check CAA record
caa=$(dig -t CAA +short $domain)
if [ -n "$caa" ]; then
  echo -e "\n\033[34mCAA records specify which certificate authorities are allowed to issue SSL certificates for a domain.\033[0m"
  echo -e "\033[34mCAA record found:\033[0m"
  echo -e "\033[34m$caa\033[0m\n"
else
  echo "No CAA record found for $domain."
fi

# Check DMARC record
dmarc=$(dig -t TXT +short _dmarc.$domain | tr -d '"' | tr '[:upper:]' '[:lower:]')
if [ -n "$dmarc" ]; then
  echo -e "\n\033[33mDMARC records define how email messages from a domain should be handled by receiving email servers.\033[0m"
  echo -e "\033[33mDMARC record found:\033[0m"
  echo -e "\033[33m$dmarc\033[0m\n"
else
  echo "No DMARC record found for $domain."
fi

# Check SPF record
spf=$(dig -t TXT +short $domain | grep -oE 'v=spf1.*')
if [ -n "$spf" ]; then
  echo -e "\n\033[32mSPF records specify which mail servers are authorized to send email on behalf of a domain.\033[0m"
  echo -e "\033[32mSPF record found:\033[0m"
  echo -e "\033[32m$spf\033[0m\n"
else
  echo "No SPF record found for $domain."
fi
