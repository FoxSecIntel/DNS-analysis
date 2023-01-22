#!/bin/bash
#set -x

#This script shows the SOA, NS, MX, CAA and TXT records for a specified domain
m=wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg==

while getopts "ahm" opt; do
case $opt in
a)
DOMAIN=$2
echo -e "${BLUE}CAA record:${NC}"
dig CAA "$DOMAIN" +short
echo -e "${GREEN}TXT record:${NC}"
dig TXT "$DOMAIN" +short
exit 0
;;
h)
echo "This script shows the SOA, NS, MX, CAA, and TXT records for a specified domain"
exit 1
;;
m)
echo $(echo $m | base64 --decode)
exit 0
;;
?)
echo "Invalid option: -$OPTARG" >&2
exit 1
;;
esac
done

shift $((OPTIND-1))
if [ -z "$1" ]; then
echo "Please specify a domain"
exit 1
fi
DOMAIN=$1

#Define some colors for use in the script
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

#Use the dig command to get the SOA record for the domain
echo -e "${BLUE}SOA record:${NC}"
dig SOA "$DOMAIN" +short

#Use the dig command to get the NS records for the domain
echo -e "${GREEN}NS records:${NC}"
dig NS "$DOMAIN" +short

#Use the dig command to get the MX records for the domain
echo -e "${RED}MX records:${NC}"
dig MX "$DOMAIN" +short

#Use the dig command to get the A record for the www subdomain
echo -e "${BLUE}WWW record:${NC}"
dig A www."$DOMAIN" +short
