#!/bin/bash

# Input file containing IP addresses
INPUT_FILE="ips.txt"

# Check if file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found."
    exit 1
fi

# Loop through each IP in the file
while read -r ip; do
    # Perform reverse DNS lookup using 'host'
    # Use awk to grab just the hostname from the end of the output
    hostname=$(host "$ip" | awk '/pointer/ {print $NF}')

    if [ -n "$hostname" ]; then
        echo "$ip => $hostname"
    else
        echo "$ip => No hostname found"
    fi
done < "$INPUT_FILE"
