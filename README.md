# Examining DNS Records with a Bash Script or Two

A domain's DNS records are important for determining how the domain functions and how it can be accessed on the internet. Some of the key DNS records for a domain include the NS (name server) records, which determine which DNS servers are responsible for the domain's DNS records; the MX (mail exchange) records, which determine which servers are responsible for handling email for the domain; the SOA (start of authority) record, which provides information about the domain's DNS configuration; and the www record, which determines the IP address or hostname of the web server that serves the domain's website.

This repository will provide a bunch of scripts to make life easier when dealing with DNS at work ! 
<pre>
domain-age.sh - Determines the age of a domain name
$ ./domain-age.sh example.com

domain-info.sh - Find information about a domain from one script
$ ./domain-info.sh example.com

domain-analysis.sh - Cycle through a list of A records, with custom domain's to see what resolves
$ ./domain-lookup.sh example.com

domain-emailsecurityproviders.sh - Identify which MX records resoves for a domain and who the email security provider is
$ ./domain-emailsecurityproviders.sh

domain-registered.sh - Work out if a dns records is registered and live or not
$ ./domain-registered.sh

domain-details.sh - Work out the CAA, DMARC and SPF of a domain 
$ ./domain-registered.sh example.com
</pre>
