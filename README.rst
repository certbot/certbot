.. notice for github users

Disclaimer
==========

The Let's Encrypt client is **BETA SOFTWARE**. It contains plenty of bugs and
rough edges, and should be tested thoroughly in staging evironments before use
on production systems.

For more information regarding the status of the project, please see
https://letsencrypt.org. Be sure to checkout the
`Frequently Asked Questions (FAQ) <https://community.letsencrypt.org/t/frequently-asked-questions-faq/26#topic-title>`_.

About the Let's Encrypt Client
==============================

Installation
------------

If `letsencrypt` is packaged for your OS, you can install it from there, and
run it by typing `letsencrypt`.  Because not all operating systems have
packages yet, we provide a temporary solution via the `letsencrypt-auto`
wrapper script, which obtains some dependencies from your OS and puts others
in an python virtual environment::

  user@www:~$ git clone https://github.com/letsencrypt/letsencrypt
  user@www:~$ cd letsencrypt
  user@www:~/letsencrypt$ ./letsencrypt-auto --help

`letsencrypt-auto` updates to the latest client release automatically.  And
since `letsencrypt-auto` is a wrapper to `letsencrypt`, it accepts exactly the
same command line flags and arguments.  More details about this script and
other installation methods can be found [in the User
Guide](https://letsencrypt.readthedocs.org/en/latest/using.html#installation)

Running the client and understanding client plugins
---------------------------------------------------

In many cases, you can just run `letsencrypt-auto` or `letsencrypt`, and the
client will guide you through the process of obtaining and installing certs
interactively.

But to understand what the client is doing in detail, it's important to
understand the way it uses plugins.  Please see the [explanation of
plugins](https://letsencrypt.readthedocs.org/en/latest/using.html#plugins) in
the User Guide.

|build-status| |coverage| |docs| |container|

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

  - apache/2.x (working on Debian 8+ and Ubuntu 12.04+)
  - standalone (runs its own simple webserver to prove you control a domain)
  - webroot (adds files to webroot directories in order to prove control of
    domains and obtain certs)
  - nginx/0.8.48+ (under development)

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
