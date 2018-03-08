RFC 2136 DNS Authenticator plugin for Certbot

This authenticator requires a .ini file with the following contents:
---8<---
# TSIG keyname
dns_rfc2136_name=certbot-keyname
# TSIG key algorithm
dns_rfc2136_algorithm={ one of HMAC-MD5/HMAC-SHA1...}
# TSIG key secret
dns_rfc2136_secret=the-HMAC-hash-key-in-base64
# TSIG DNS server
#dns_rfc2136_server=ip.ad.re.ss
dns_rfc2136_server=ip:v6:ad:re::ss
---8<---

This file needs to addressed by using the  --dns-rfc2136-credentials {file} flag on the certbot command line
the secret key can be generated using dnssec-keygen -a {algorithm} -r /dev/urandom SomeKey
thefile KSomeKey-algonum-key.private holds the private key in base64.

Algorithm being one of the HMAC types.
