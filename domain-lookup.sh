#!/bin/bash
# Check if a command line parameter was provided
if [ $# -eq 0 ]; then
    # If no parameter was provided, display an error message and exit
    echo "Error: No domain name provided."
    exit 1
fi

# Read in the names from the file
while read name; do
    # Append the command line parameter to the name
    name="$name.$1"

    # Perform a DNS lookup on the name using the host command
    # and redirect the output to a file
    host "$name" >> dns_lookup_results.txt
done < names.txt
