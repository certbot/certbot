=====================
What is a Certificate?
=====================

An SSL *certificate* contains a public key and a private key that work together to enable
a web browser to communicate with your server securely over an encrypted SSL (secure socket layer)
connection. The certificate also identifies your website so that the browser (and the person behind it)
can trust your identity. SSL certificates have mainly been used to provide secure,
encrypted communication for sensitive information like financial and health data, but
we now recommend all websites run on SSL to prevent eavesdropping and content hijacking.

You can use Certbot to easily obtain and configure a free certificate from Let's Encrypt, a
joint project of EFF, Mozilla, and many other sponsors.

Certificates and Lineages
=========================

Certbot introduces the concept of a *lineage,* which is a collection of all the versions of a certificate
plus additional information that Certbot uses to maintain the configuration of your webserver from
renewal to renewal. Whenever you renew a certificate, Certbot keeps the same configuration unless
you explicitly change it. If you add domains, you can either add them to an existing lineage or create
a new one. 

