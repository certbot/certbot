======================
What is a Certificate?
======================

A digital (X.509) *certificate* uses a public key and a private key to enable secure communication between a client program (web browser, email client,
etc.) and a server over an encrypted TLS (transport layer security) connection.

The certificate is used both to encrypt the initial stage of communication (secure key exchange) and to identify the server. 

The certificate includes information about:
- the key
- validity dates
- the server identity
- the digital signature of the certificate issuer

If the issuer is trusted by the software that initiates the communication,
and the signature is valid, then the key can be used to communicate securely with the server identified by the certificate.

Using a certificate is a good way to prevent "machine-in-the-middle" attacks, in which someone in between you and the server you think you are talking to is able to insert their own (harmful) content.

You can use Certbot to easily obtain and configure a free certificate from Let's Encrypt, a joint project of EFF, Mozilla, and many other sponsors.

Certificates and Lineages
=========================

Certbot introduces the concept of a *lineage,* which is a collection of all the versions of a certificate plus Certbot configuration information maintained for that certificate from renewal to renewal.

Whenever you renew a certificate, Certbot keeps the same configuration unless
you explicitly change it, for example by adding or removing domains. If you add domains, you can either add them to an existing lineage or create a new one.

Certificate Chains & Trust
==========================

Certificates are issued by Certificate Authorities (CAs)—trusted entities like Let's Encrypt. A chain contains intermediate CA certificates between your cert and the root CA. Browsers use, store, and trust root CAs to verify the chain of trust. If the chain is broken, the certificate will not be trusted. You can possibily see an error like "Your connection is not private" or "NET::ERR_CERT_AUTHORITY_INVALID" in your browser.

Certbot manages: certificate, chain, and fullchain.

Domain Validation (DV)
=========================

The process to prove you control a domain before receiving a certificate. Certbot does this with something called ACME challenges.

Certbot can also handle multiple subdomains per certificate by generating wildcard certificates. e.g., [*].example.com.

ACME Protocol (RFC 8555)
=========================

The protocol for automating certificate lifecycle management.

Let's Encrypt supports ACME; Certbot implements it to request, renew, and revoke certificates. This removes the need to manually process renewals for your certificate.

See also:
:ref:`updating_certs`
