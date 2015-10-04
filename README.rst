.. notice for github users

Disclaimer
==========

This is a **DEVELOPER PREVIEW** intended for developers and testers only.

**DO NOT RUN THIS CODE ON A PRODUCTION SERVER. IT WILL INSTALL CERTIFICATES
SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR USERS.**

Browser-trusted certificates will be available in the coming months.

For more information regarding the status of the project, please see
https://letsencrypt.org. Be sure to checkout the
`Frequently Asked Questions (FAQ) <https://community.letsencrypt.org/t/frequently-asked-questions-faq/26#topic-title>`_.

About the Let's Encrypt Client
==============================

|build-status| |coverage| |docs| |container|

In short: getting and installing SSL/TLS certificates made easy (`watch demo video`_).

The Let's Encrypt Client is a tool to automatically receive and install
X.509 certificates to enable TLS on servers. The client will
interoperate with the Let's Encrypt CA which will be issuing browser-trusted
certificates for free.

It's all automated:

* The tool will prove domain control to the CA and submit a CSR (Certificate
  Signing Request).
* If domain control has been proven, a certificate will get issued and the tool
  will automatically install it.

All you need to do to sign a single domain is::

  user@www:~$ sudo letsencrypt -d www.example.org auth

For multiple domains (SAN) use::

  user@www:~$ sudo letsencrypt -d www.example.org -d example.org auth

and if you have a compatible web server (Apache or Nginx), Let's Encrypt can
not only get a new certificate, but also deploy it and configure your
server automatically!::

  user@www:~$ sudo letsencrypt -d www.example.org run


**Encrypt ALL the things!**


.. |build-status| image:: https://travis-ci.org/letsencrypt/letsencrypt.svg?branch=master
   :target: https://travis-ci.org/letsencrypt/letsencrypt
   :alt: Travis CI status

.. |coverage| image:: https://coveralls.io/repos/letsencrypt/letsencrypt/badge.svg?branch=master
   :target: https://coveralls.io/r/letsencrypt/letsencrypt
   :alt: Coverage status

.. |docs| image:: https://readthedocs.org/projects/letsencrypt/badge/
   :target: https://readthedocs.org/projects/letsencrypt/
   :alt: Documentation status

.. |container| image:: https://quay.io/repository/letsencrypt/letsencrypt/status
   :target: https://quay.io/repository/letsencrypt/letsencrypt
   :alt: Docker Repository on Quay.io

.. _`installation instructions`:
   https://letsencrypt.readthedocs.org/en/latest/using.html

.. _watch demo video: https://www.youtube.com/watch?v=Gas_sSB-5SU


Current Features
----------------

* web servers supported:

  - apache/2.x (tested and working on Ubuntu Linux)
  - nginx/0.8.48+ (under development)
  - standalone (runs its own webserver to prove you control the domain)

* the private key is generated locally on your system
* can talk to the Let's Encrypt (demo) CA or optionally to other ACME
  compliant services
* can get domain-validated (DV) certificates
* can revoke certificates
* adjustable RSA key bitlength (2048 (default), 4096, ...)
* optionally can install a http->https redirect, so your site effectively
  runs https only (Apache only)
* fully automated
* configuration changes are logged and can be reverted using the CLI
* text and ncurses UI
* Free and Open Source Software, made with Python.


Installation Instructions
-------------------------

Official **documentation**, including `installation instructions`_, is
available at https://letsencrypt.readthedocs.org.


Links
-----

Documentation: https://letsencrypt.readthedocs.org

Software project: https://github.com/letsencrypt/letsencrypt

Notes for developers: CONTRIBUTING.md_

Main Website: https://letsencrypt.org/

IRC Channel: #letsencrypt on `Freenode`_

Community: https://community.letsencrypt.org

Mailing list: `client-dev`_ (to subscribe without a Google account, send an
email to client-dev+subscribe@letsencrypt.org)

.. _Freenode: https://freenode.net
.. _client-dev: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
.. _CONTRIBUTING.md: https://github.com/letsencrypt/letsencrypt/blob/master/CONTRIBUTING.md
