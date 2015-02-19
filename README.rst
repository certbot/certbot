About the Let's Encrypt Client
==============================

In short: getting and installing SSL/TLS certificates made easy (`watch demo video`_).

The Let's Encrypt Client is a tool to automatically receive and install
X.509 certificates to enable TLS on servers. The client will
interoperate with the Let's Encrypt CA which will be issuing browser-trusted
certificates for free beginning the summer of 2015.

It's all automated:

* The tool will prove domain control to the CA and submit a CSR (Certificate
  Signing Request).
* If domain control has been proven, a certificate will get issued and the tool
  will automatically install it.

All you need to do is:

::

   user@www:~$ sudo letsencrypt www.example.org


**Encrypt ALL the things!**


[![Build Status](https://travis-ci.org/letsencrypt/lets-encrypt-preview.svg)](https://travis-ci.org/letsencrypt/lets-encrypt-preview)

[![Coverage Status](https://coveralls.io/repos/letsencrypt/lets-encrypt-preview/badge.svg)](https://coveralls.io/r/letsencrypt/lets-encrypt-preview)

.. _watch demo video: https://www.youtube.com/watch?v=Gas_sSB-5SU


Disclaimer
----------

This is a **DEVELOPER PREVIEW** intended for developers and testers only.

**DO NOT RUN THIS CODE ON A PRODUCTION SERVER. IT WILL INSTALL CERTIFICATES
SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR USERS.**


Current Features
----------------

* web servers supported:

  - apache2.x (tested and working on Ubuntu Linux)

* the private key is generated locally on your system
* can talk to the Let's Encrypt (demo) CA or optionally to other ACME
  compliant services
* can get domain-validated (DV) certificates
* can revoke certificates
* adjustable RSA key bitlength (2048 (default), 4096, ...)
* optionally can install a http->https redirect, so your site effectively
  runs https only
* fully automated
* configuration changes are logged and can be reverted using the CLI
* text and ncurses UI
* Free and Open Source Software, made with Python.


Links
-----

Documentation: https://letsencrypt.readthedocs.org/

Software project: https://github.com/letsencrypt/lets-encrypt-preview

Main Website: https://letsencrypt.org/

IRC Channel: #letsencrypt on `Freenode`_

Mailing list: `client-dev`_ (to subscribe without a Google account, send an
email to client-dev+subscribe@letsencrypt.org)

.. _Freenode: https://freenode.net
.. _client-dev: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
