#!/bin/bash

# This script shows the SOA, NS, and MX records for a specified domain

# Check if a domain was specified
if [ -z "$1" ]; then
    echo "Please specify a domain"
    exit 1
fi

# Get the SOA record for the domain
soa=$(host -t soa $1 | awk '{print $1, $2, $3, $4, $5, $6, $7}')

# Check if the domain has an SOA record
if [ -z "$soa" ]; then
    echo "The domain does not have an SOA record"
    exit 1
fi

# Print the SOA record
echo "SOA record for $1:"
echo "$soa"

# Get the NS records for the domain
ns=$(host -t ns $1 | awk '{print $4}' | grep -v "name")
echo "NS records for $1:"
echo "$ns"

# Get the MX records for the domain
mx=$(host -t mx $1 | awk '{print $7}')
echo "MX records for $1:"
echo "$mx"
