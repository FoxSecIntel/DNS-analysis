#!/bin/bash

# Check if a domain argument was provided
if [[ $# -eq 0 ]] ; then
    echo "Please provide a domain as an argument."
    exit 1
fi
domain=$1

# Determine the string to search for in the output of the whois command
search_string=""
if [[ $domain == *".uk" ]]; then
    search_string="Registered on:"
else
    search_string="Creation Date:"
fi

# Get the creation date of the domain using whois
creation_date=$(whois $domain | grep "$search_string" | cut -d ":" -f2 )

if [[ $domain != *".uk" ]]; then
  creation_date=$(echo $creation_date | awk '{print substr($0,0,index($0,"T"))}')
  creation_date=${creation_date%?}
fi


parsed_date=$(date -d "$creation_date" +"%s")

# Get the current date in the same format
current_date=$(date +"%s")

# Calculate the difference between the current date and the creation date
time_diff=$((current_date - parsed_date))

# Calculate the number of years, days, and hours in the time difference
years=$((time_diff / 31536000))
days=$((time_diff % 31536000 / 86400))
hours=$((time_diff % 86400 / 3600))

# Print the age of the domain
echo "The domain $domain is $years years, $days days, and $hours hours old."
echo "Created on : $creation_date"
