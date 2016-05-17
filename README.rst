.. notice for github users

Disclaimer
==========

Certbot (previously, the Let's Encrypt client) is **BETA SOFTWARE**. It
contains plenty of bugs and rough edges, and should be tested thoroughly in
staging environments before use on production systems.

For more information regarding the status of the project, please see
https://letsencrypt.org. Be sure to checkout the
`Frequently Asked Questions (FAQ) <https://community.letsencrypt.org/t/frequently-asked-questions-faq/26#topic-title>`_.

About Certbot
==============================

Certbot is a fully-featured, extensible client for the Let's
Encrypt CA (or any other CA that speaks the `ACME
<https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md>`_
protocol) that can automate the tasks of obtaining certificates and
configuring webservers to use them. This client runs on Unix-based operating
systems.

Until May 2016, Certbot was named simply ``letsencrypt`` or ``letsencrypt-auto``,
depending on install method. Instructions on the Internet, and some pieces of the
software, may still refer to this older name.

Contributing
------------

If you'd like to contribute to this project please read `Developer Guide
<https://certbot.eff.org/docs/contributing.html>`_.

.. _installation:

Installation
------------

If ``certbot`` (or ``letsencrypt``) is packaged for your Unix OS (visit
certbot.eff.org_ to find out), you can install it
from there, and run it by typing ``certbot`` (or ``letsencrypt``).  Because
not all operating systems have packages yet, we provide a temporary solution
via the ``certbot-auto`` wrapper script, which obtains some dependencies from
your OS and puts others in a python virtual environment::

  user@webserver:~$ wget https://dl.eff.org/certbot-auto
  user@webserver:~$ chmod a+x ./certbot-auto
  user@webserver:~$ ./certbot-auto --help

.. hint:: The certbot-auto download is protected by HTTPS, which is pretty good, but if you'd like to
          double check the integrity of the ``certbot-auto`` script, you can use these steps for verification before running it::

            user@server:~$ wget -N https://dl.eff.org/certbot-auto.asc
            user@server:~$ gpg2 --recv-key A2CFB51FA275A7286234E7B24D17C995CD9775F2
            user@server:~$ gpg2 --trusted-key 4D17C995CD9775F2 --verify certbot-auto.asc certbot-auto

And for full command line help, you can type::

  ./certbot-auto --help all

``certbot-auto`` updates to the latest client release automatically.  And
since ``certbot-auto`` is a wrapper to ``certbot``, it accepts exactly
the same command line flags and arguments.  More details about this script and
other installation methods can be found `in the User Guide
<https://certbot.eff.org/docs/using.html#installation>`_.

How to run the client
---------------------

In many cases, you can just run ``certbot-auto`` or ``certbot``, and the
client will guide you through the process of obtaining and installing certs
interactively.

You can also tell it exactly what you want it to do from the command line.
For instance, if you want to obtain a cert for ``example.com``,
``www.example.com``, and ``other.example.net``, using the Apache plugin to both
obtain and install the certs, you could do this::

  ./certbot-auto --apache -d example.com -d www.example.com -d other.example.net

(The first time you run the command, it will make an account, and ask for an
email and agreement to the Let's Encrypt Subscriber Agreement; you can
automate those with ``--email`` and ``--agree-tos``)

If you want to use a webserver that doesn't have full plugin support yet, you
can still use "standalone" or "webroot" plugins to obtain a certificate::

  ./certbot-auto certonly --standalone --email admin@example.com -d example.com -d www.example.com -d other.example.net


Understanding the client in more depth
--------------------------------------

To understand what the client is doing in detail, it's important to
understand the way it uses plugins.  Please see the `explanation of
plugins <https://certbot.eff.org/docs/using.html#plugins>`_ in
the User Guide.

Links
=====

Documentation: https://certbot.eff.org/docs

Software project: https://github.com/certbot/certbot

Notes for developers: https://certbot.eff.org/docs/contributing.html

Main Website: https://letsencrypt.org/

IRC Channel: #letsencrypt on `Freenode`_ or #certbot on `OFTC`_

Community: https://community.letsencrypt.org

ACME spec: http://ietf-wg-acme.github.io/acme/

ACME working area in github: https://github.com/ietf-wg-acme/acme


Mailing list: `client-dev`_ (to subscribe without a Google account, send an
email to client-dev+subscribe@letsencrypt.org)

|build-status| |coverage| |docs| |container|



.. |build-status| image:: https://travis-ci.org/certbot/certbot.svg?branch=master
   :target: https://travis-ci.org/certbot/certbot
   :alt: Travis CI status

.. |coverage| image:: https://coveralls.io/repos/certbot/certbot/badge.svg?branch=master
   :target: https://coveralls.io/r/certbot/certbot
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
Python 2.6 or 2.7; Python 3.x support will hopefully be added in the future. The
client requires root access in order to write to ``/etc/letsencrypt``,
``/var/log/letsencrypt``, ``/var/lib/letsencrypt``; to bind to ports 80 and 443
(if you use the ``standalone`` plugin) and to read and modify webserver
configurations (if you use the ``apache`` or ``nginx`` plugins).  If none of
these apply to you, it is theoretically possible to run without root privileges,
but for most users who want to avoid running an ACME client as root, either
`letsencrypt-nosudo <https://github.com/diafygi/letsencrypt-nosudo>`_ or
`simp_le <https://github.com/kuba/simp_le>`_ are more appropriate choices.

The Apache plugin currently requires a Debian-based OS with augeas version
1.0; this includes Ubuntu 12.04+ and Debian 7+.


Current Features
================

* Supports multiple web servers:

  - apache/2.x (working on Debian 8+ and Ubuntu 12.04+)
  - standalone (runs its own simple webserver to prove you control a domain)
  - webroot (adds files to webroot directories in order to prove control of
    domains and obtain certs)
  - nginx/0.8.48+ (highly experimental, not included in certbot-auto)

* The private key is generated locally on your system.
* Can talk to the Let's Encrypt CA or optionally to other ACME
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


.. _Freenode: https://webchat.freenode.net?channels=%23letsencrypt
.. _OFTC: https://webchat.oftc.net?channels=%23certbot
.. _client-dev: https://groups.google.com/a/letsencrypt.org/forum/#!forum/client-dev
.. _certbot.eff.org: https://certbot.eff.org/
