This page aims to track suggestions and references that people have offered or identified to improve the ciphersuites that Let's Encrypt enables when configuring TLS on servers.

Because of the Chatham House Rule applicable to some of the discussions, people are *not* individually credited for their suggestions, but most suggestions here were made or found by other people, and I thank them for their contributions.

Some people provided rationale information mostly having to do with compatibility of particular user-agents (especially UAs that don't support ECC, or that don't support DH groups > 1024 bits).  Some ciphersuite configurations have been chosen to try to increase compatibility with older UAs while allowing newer UAs to negotiate stronger crypto.  For example, some configurations forego forward secrecy entirely for connections from old UAs, like by offering ECDHE and RSA key exchange, but no DHE at all.  (There are UAs that can fail the negotiation completely if a DHE ciphersuite with prime > 1024 bits is offered.)

## References ##

### RFC 7575 ###

IETF has published a BCP document, RFC 7525, "Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)"

https://datatracker.ietf.org/doc/rfc7525/

### BetterCrypto.org ###

BetterCrypto.org, a collaboration of mostly European IT security experts, has published a draft paper, "Applied Crypto Hardening"

https://bettercrypto.org/static/applied-crypto-hardening.pdf

### FF-DHE Internet-Draft ###

Gillmor's Internet-Draft "Negotiated Discrete Log Diffie-Hellman Ephemeral Parameters for TLS" is being developed at the IETF TLS WG.  It advocates using *standardized* DH groups in all cases, not individually-chosen ones (mostly because of the Triple Handshake attack which can involve maliciously choosing invalid DH groups).  The draft provides a list of recommended groups, with primes beginning at 2048 bits and going up from there.  It also has a new protocol mechanism for agreeing to use these groups, with the possibility of backwards compatibility (and use of weaker DH groups) for older clients and servers that don't know about this mechanism.

https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe-10

### Mozilla ###

Mozilla's general server configuration guidance is available at https://wiki.mozilla.org/Security/Server_Side_TLS

Mozilla has also produced a configuration generator: https://mozilla.github.io/server-side-tls/ssl-config-generator/

### Dutch National Cyber Security Centre ###

The Dutch National Cyber Security Centre has published guidance on "ICT-beveiligingsrichtlijnen voor Transport Layer Security (TLS)" ("IT Security Guidelines for Transport Layer Security (TLS)").  These are available only in Dutch at

https://www.ncsc.nl/dienstverlening/expertise-advies/kennisdeling/whitepapers/ict-beveiligingsrichtlijnen-voor-transport-layer-security-tls.html

I have access to an English-language summary of the recommendations.

### Keylength.com ###

Damien Giry collects recommendations by academic researchers and standards organizations about keylengths for particular cryptoperiods, years, or security levels.  The keylength recommendations of the various sources are summarized in a chart.  This site has been updated over time and includes expert guidance from eight sources published between 2000 and 2015.

http://www.keylength.com/

### NIST ###

NISA published its "NIST Special Publication 800-52 Revision 1: Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations"

http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r1.pdf

and its "NIST Special Publication 800-57: Recommendation for Key Management – Part 1: General (Revision 3)"

http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf

### ENISA ###

ENISA published its "Algorithms, Key Sizes and Parameters Report - 2013"

https://www.enisa.europa.eu/activities/identity-and-trust/library/deliverables/algorithms-key-sizes-and-parameters-report

## WeakDH/Logjam ##

The WeakDH/Logjam research has thrown into question the safety of some existing practice using DH ciphersuites, especially the use of standardized groups with a prime ≤ 1024 bits.  The authors provided detailed guidance, including ciphersuite lists, at

https://weakdh.org/sysadmin.html

These lists may have been derived from Mozilla's recommendations.

One of the authors clarified his view of the priorities for various changes as a result of the research at

https://www.ietf.org/mail-archive/web/tls/current/msg16496.html

In particular, he supports ECDHE and also supports the use of the standardized groups in the FF-DHE Internet-Draft mentioned above (which isn't clear from the group's original recommendations).

## Particular sites' opinions or configurations ##

### Amazon ELB ###

Amazon ELB explains its current ciphersuite choices at

https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-table.html

### U.S. Government 18F ###

The 18F site (https://18f.gsa.gov/) is using 

`ssl_ciphers 'kEECDH+ECDSA+AES128 kEECDH+ECDSA+AES256 kEECDH+AES128 kEECDH+AES256 kEDH+AES128 kEDH+AES256 DES-CBC3-SHA +SHA !aNULL !eNULL !LOW !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !RC4 !SEED';`

### Duraconf ###

The Duraconf project collects particular configuration files, with an apparent focus on avoiding the use of obsolete symmetric ciphers and hash functions, and favoring forward secrecy while not requiring it.

https://github.com/ioerror/duraconf

## Site scanning or rating tools ##

### Qualys SSL Labs ###

Qualys offers the best-known TLS security scanner, maintained by Ivan Ristić.

https://www.ssllabs.com/

### Dutch NCSC ###

The Dutch NCSC, mentioned above, has also made available its own site security scanner which indicates how well sites comply with the recommendations.

https://en.internet.nl/

## Java compatibility issue ##

A lot of backward-compatibility concerns have to do with Java hard-coding DHE primes to a 1024-bit limit, accepting DHE ciphersuites in negotiation, and then aborting the connection entirely if a prime > 1024 bits is presented.  The simple summary is that servers offering a Java-compatible DHE ciphersuite in preference to other Java-compatible ciphersuites, and then presenting a DH group with a prime > 1024 bits, will be completely incompatible with clients running some versions of Java.  (This may also be the case with very old MSIE versions...?)  There are various strategies for dealing with this, and maybe we can document the options here.
