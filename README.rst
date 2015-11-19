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

  user@www:~$ sudo letsencrypt -d www.example.org certonly

For multiple domains (SAN) use::

  user@www:~$ sudo letsencrypt -d www.example.org -d example.org certonly

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

* Supports multiple web servers:

  - apache/2.x (tested and working on Ubuntu Linux)
  - nginx/0.8.48+ (under development)
  - standalone (runs its own simple webserver to prove you control a domain)

* The private key is generated locally on your system.
* Can talk to the Let's Encrypt (demo) CA or optionally to other ACME
  compliant services.
* Can get domain-validated (DV) certificates.
* Can revoke certificates.
* Adjustable RSA key bit-length (2048 (default), 4096, ...).
* Can optionally install a http -> https redirect, so your site effectively
  runs https only (Apache only)
* Fully automated.
* Configuration changes are logged and can be reverted.
* Text and ncurses UI.
* Free and Open Source Software, made with Python.


Installation Instructions
-------------------------

Official **documentation**, including `installation instructions`_, is
available at https://letsencrypt.readthedocs.org.


Links
-----

Documentation: https://letsencrypt.readthedocs.org

Software project: https://github.com/letsencrypt/letsencrypt

Notes for developers: https://letsencrypt.readthedocs.org/en/latest/contributing.html

Main Website: https://letsencrypt.org/

IRC Channel: #letsencrypt on `Freenode`_

Community: https://community.letsencrypt.org

Mailing list: `client-dev`_ (to subscribe without a Google account, send an
email to client-dev+subscribe@letsencrypt.org)

.. _Freenode: https://freenode.net
.. _client-dev: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
