.. notice for github users

Disclaimer
==========

The Let's Encrypt Client is **BETA SOFTWARE**. It contains plenty of bugs and
rough edges, and should be tested thoroughly in staging environments before use
on production systems.

For more information regarding the status of the project, please see
https://letsencrypt.org. Be sure to checkout the
`Frequently Asked Questions (FAQ) <https://community.letsencrypt.org/t/frequently-asked-questions-faq/26#topic-title>`_.

About the Let's Encrypt Client
==============================

The Let's Encrypt Client is a fully-featured, extensible client for the Let's
Encrypt CA (or any other CA that speaks the `ACME
<https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md>`_
protocol) that can automate the tasks of obtaining certificates and
configuring webservers to use them.

Installation
------------

If ``letsencrypt`` is packaged for your OS, you can install it from there, and
run it by typing ``letsencrypt``.  Because not all operating systems have
packages yet, we provide a temporary solution via the ``letsencrypt-auto``
wrapper script, which obtains some dependencies from your OS and puts others
in an python virtual environment::

  user@webserver:~$ git clone https://github.com/letsencrypt/letsencrypt
  user@webserver:~$ cd letsencrypt
  user@webserver:~/letsencrypt$ ./letsencrypt-auto --help

Or for full command line help, type::

  ./letsencrypt-auto --help all

``letsencrypt-auto`` updates to the latest client release automatically.  And
since ``letsencrypt-auto`` is a wrapper to ``letsencrypt``, it accepts exactly
the same command line flags and arguments.  More details about this script and
other installation methods can be found `in the User Guide
<https://letsencrypt.readthedocs.org/en/latest/using.html#installation>`_.

How to run the client
---------------------

In many cases, you can just run ``letsencrypt-auto`` or ``letsencrypt``, and the
client will guide you through the process of obtaining and installing certs
interactively.

You can also tell it exactly what you want it to do from the command line.
For instance, if you want to obtain a cert for ``thing.com``,
``www.thing.com``, and ``otherthing.net``, using the Apache plugin to both
obtain and install the certs, you could do this::

  ./letsencrypt-auto --apache -d thing.com -d www.thing.com -d otherthing.net

(The first time you run the command, it will make an account, and ask for an
email and agreement to the Let's Encrypt Subscriber Agreement; you can
automate those with ``--email`` and ``--agree-tos``)

If you want to use a webserver that doesn't have full plugin support yet, you
can still use "standalone" or "webroot" plugins to obtain a certificate::

  ./letsencrypt-auto certonly --standalone --email admin@thing.com -d thing.com -d www.thing.com -d otherthing.net


Understanding the client in more depth
--------------------------------------

To understand what the client is doing in detail, it's important to
understand the way it uses plugins.  Please see the `explanation of
plugins <https://letsencrypt.readthedocs.org/en/latest/using.html#plugins>`_ in
the User Guide.

Links
=====

Documentation: https://letsencrypt.readthedocs.org

Software project: https://github.com/letsencrypt/letsencrypt

Notes for developers: https://letsencrypt.readthedocs.org/en/latest/contributing.html

Main Website: https://letsencrypt.org/

IRC Channel: #letsencrypt on `Freenode`_

Community: https://community.letsencrypt.org

Mailing list: `client-dev`_ (to subscribe without a Google account, send an
email to client-dev+subscribe@letsencrypt.org)

|build-status| |coverage| |docs| |container|



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

System Requirements
===================

The Let's Encrypt Client presently only runs on Unix-ish OSes that include
Python 2.6 or 2.7; Python 3.x support will be added after the Public Beta
launch. The client requires root access in order to write to
``/etc/letsencrypt``, ``/var/log/letsencrypt``, ``/var/lib/letsencrypt``; to
bind to ports 80 and 443 (if you use the ``standalone`` plugin) and to read and
modify webserver configurations (if you use the ``apache`` or ``nginx``
plugins).  If none of these apply to you, it is theoretically possible to run
without root privilegess, but for most users who want to avoid running an ACME
client as root, either `letsencrypt-nosudo
<https://github.com/diafygi/letsencrypt-nosudo>`_ or `simp_le
<https://github.com/kuba/simp_le>`_ are more appropriate choices.

The Apache plugin currently requires a Debian-based OS with augeas version
1.0; this includes Ubuntu 12.04+ and Debian 7+.


Current Features
================

* Supports multiple web servers:

  - apache/2.x (working on Debian 8+ and Ubuntu 12.04+)
  - standalone (runs its own simple webserver to prove you control a domain)
  - webroot (adds files to webroot directories in order to prove control of
    domains and obtain certs)
  - nginx/0.8.48+ (highly experimental, not included in letsencrypt-auto)

* The private key is generated locally on your system.
* Can talk to the Let's Encrypt  CA or optionally to other ACME
  compliant services.
* Can get domain-validated (DV) certificates.
* Can revoke certificates.
* Adjustable RSA key bit-length (2048 (default), 4096, ...).
* Can optionally install a http -> https redirect, so your site effectively
  runs https only (Apache only)
* Fully automated.
* Configuration changes are logged and can be reverted.
* Supports ncurses and text (-t) UI, or can be driven entirely from the
  command line.
* Free and Open Source Software, made with Python.


.. _Freenode: https://freenode.net
.. _client-dev: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
