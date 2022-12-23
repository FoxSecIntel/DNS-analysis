# Examining DNS Records with a Bash Script

A domain's DNS records are important for determining how the domain functions and how it can be accessed on the internet. Some of the key DNS records for a domain include the NS (name server) records, which determine which DNS servers are responsible for the domain's DNS records; the MX (mail exchange) records, which determine which servers are responsible for handling email for the domain; the SOA (start of authority) record, which provides information about the domain's DNS configuration; and the www record, which determines the IP address or hostname of the web server that serves the domain's website.

This repository will provide a bunch of scripts to make life easier when dealing with DNS at work ! 

$ ./domain-info.sh example.com

SOA record: <br>
ns.icann.org. noc.dns.icann.org. 2022091162 7200 3600 1209600 3600<br>
NS records:<br>
a.iana-servers.net.<br>
b.iana-servers.net.<br>
MX records:<br>
0 .<br>
WWW record:<br>
93.184.216.34<br>

$ ./domain-info.sh example.com
