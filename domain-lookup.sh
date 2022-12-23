#!/bin/bash
# Check if a command line parameter was provided

if [ $# -eq 0 ]; then
    # If no parameter was provided, display an error message and exit
    echo "Error: No domain name provided."
    exit 1
fi

# Initialize variables to track the number of lines, public IPs, private IPs, and errors
line_count=0
public_ip_count=0
private_ip_count=0
error_count=0
rm dns_lookup_results.txt
rm dlr-public.txt
touch dlr-public.txt

# Read in the names from the file
while read name; do
    # Increment the line count
    ((line_count++))
    echo -n "."

    # Append the command line parameter to the name
    name="$name.$1"

    # Perform a DNS lookup on the name using the host command
    # and redirect the output to a file
    host "$name" >> dns_lookup_results.txt

    # Check the exit status of the host command
    if [ $? -ne 0 ]; then
        # If the host command failed, increment the error count
        ((error_count++))
    else
        # If the host command succeeded, check the output for a public or private IP address

        # Extract the IP address from the output using grep and awk
        ip_address=$(grep "$name" dns_lookup_results.txt | awk '{print $4}')

        # Check if the IP address is a public or private IP
        if [[ "$ip_address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            # Check if the IP address is a private IP
if [[ "$ip_address" =~ ^(10(0|)\.[0-9]{1,3}|172.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}$ ]
]; then
                # If the IP address is a private IP, increment the private IP count
                ((private_ip_count++))
            else
                # If the IP address is a public IP, increment the public IP count
                ((public_ip_count++))
                  echo "$ip_address" >> dlr-public.txt
            fi
        fi
    fi
done < names.txt

# Print the results
echo ""
echo "Number of lines: $line_count"
echo "Number of public IPs: $public_ip_count"
echo "Number of private IPs: $private_ip_count"
echo "Number of errors: $error_count"

