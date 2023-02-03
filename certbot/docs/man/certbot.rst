:orphan:

=======
certbot
=======

Synopsis
========
The objective of Certbot, Let's Encrypt, and the ACME (Automated Certificate Management
Environment) protocol is to make it possible to set up an HTTPS server and have it automatically
obtain a browser-trusted certificate, without any human intervention. This is accomplished by
running a certificate management agent on the web server.

This agent is used to:

- Automatically prove to the Let's Encrypt CA that you control the website
- Obtain a browser-trusted certificate and set it up on your web server
- Keep track of when your certificate is going to expire, and renew it
- Help you revoke the certificate if that ever becomes necessary.

Options
=======
.. literalinclude:: ../cli-help.txt