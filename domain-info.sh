#!/bin/bash

# This script shows the SOA, NS, and MX records for a specified domain

# Check if a domain was specified
if [ -z "$1" ]; then
    echo "Please specify a domain"
    exit 1
fi

DOMAIN=$1

# Define some colors for use in the script
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Use the dig command to get the SOA record for the domain
echo -e "${BLUE}SOA record:${NC}"
dig SOA "$DOMAIN" +short

# Use the dig command to get the NS records for the domain
echo -e "${GREEN}NS records:${NC}"
dig NS "$DOMAIN" +short

# Use the dig command to get the MX records for the domain
echo -e "${RED}MX records:${NC}"
dig MX "$DOMAIN" +short

# Use the dig command to get the A record for the www subdomain
echo -e "${BLUE}WWW record:${NC}"
dig A www."$DOMAIN" +short
