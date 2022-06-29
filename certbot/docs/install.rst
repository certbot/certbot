=====================
Get Certbot
=====================

.. contents:: Table of Contents
   :local:


About Certbot
=============

*Certbot is meant to be run directly on a web server*, normally by a system administrator. In most cases, running Certbot on your personal computer is not a useful option. The instructions below relate to installing and running Certbot on a server.

System administrators can use Certbot directly to request certificates; they should *not* allow unprivileged users to run arbitrary Certbot commands as ``root``, because Certbot allows its user to specify arbitrary file locations and run arbitrary scripts.

Certbot is packaged for many common operating systems and web servers. Check whether
``certbot`` (or ``letsencrypt``) is packaged for your web server's OS by visiting
certbot.eff.org_, where you will also find the correct installation instructions for
your system.

.. Note:: Unless you have very specific requirements, we kindly suggest that you use the installation instructions for your system found at certbot.eff.org_.

.. _certbot.eff.org: https://certbot.eff.org


.. _system_requirements:

System Requirements
===================

Certbot currently requires Python 3.7+ running on a UNIX-like operating
system. By default, it requires root access in order to write to
``/etc/letsencrypt``, ``/var/log/letsencrypt``, ``/var/lib/letsencrypt``; to
bind to port 80 (if you use the ``standalone`` plugin) and to read and
modify webserver configurations (if you use the ``apache`` or ``nginx``
plugins).  If none of these apply to you, it is theoretically possible to run
without root privileges, but for most users who want to avoid running an ACME
client as root, either `letsencrypt-nosudo
<https://github.com/diafygi/letsencrypt-nosudo>`_ or `simp_le
<https://github.com/zenhack/simp_le>`_ are more appropriate choices.

The Apache plugin currently requires an OS with augeas version 1.0; currently `it
supports
<https://github.com/certbot/certbot/blob/master/certbot-apache/certbot_apache/_internal/constants.py>`_
modern OSes based on Debian, Ubuntu, Fedora, SUSE, Gentoo and Darwin.

Alternate installation methods
================================

If you are offline or your operating system doesn't provide a package, you can use
an alternate method for installing ``certbot``.

.. _snap-install:

Snap
----

Most modern Linux distributions (basically any that use systemd) can install
Certbot packaged as a snap. Snaps are available for x86_64, ARMv7 and ARMv8
architectures. The Certbot snap provides an easy way to ensure you have the
latest version of Certbot with features like automated certificate renewal
preconfigured.

You can find instructions for installing the Certbot snap at
https://certbot.eff.org/instructions by selecting your server software and then
choosing "snapd" in the "System" dropdown menu. (You should select "snapd"
regardless of your operating system, as our instructions are the same across
all systems.)

.. _docker-user:

Running with Docker
-------------------

Docker_ is an amazingly simple and quick way to obtain a
certificate. However, this mode of operation is unable to install
certificates or configure your webserver, because our installer
plugins cannot reach your webserver from inside the Docker container.

Most users should use the instructions at certbot.eff.org_. You should only use
Docker if you are sure you know what you are doing and have a good reason to do
so.

You should definitely read the :ref:`where-certs` section, in order to
know how to manage the certificates
manually. `Our ciphersuites page <ciphers.html>`__
provides some information about recommended ciphersuites. If none of
these make much sense to you, you should definitely use the installation method
recommended for your system at certbot.eff.org_, which enables you to use
installer plugins that cover both of those hard topics.

If you're still not convinced and have decided to use this method, from
the server that the domain you're requesting a certificate for resolves
to, `install Docker`_, then issue a command like the one found below. If
you are using Certbot with the :ref:`Standalone` plugin, you will need
to make the port it uses accessible from outside of the container by
including something like ``-p 80:80`` or ``-p 443:443`` on the command
line before ``certbot/certbot``.

.. code-block:: shell

   sudo docker run -it --rm --name certbot \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               certbot/certbot certonly

Running Certbot with the ``certonly`` command will obtain a certificate and place it in the directory
``/etc/letsencrypt/live`` on your system. Because Certonly cannot install the certificate from
within Docker, you must install the certificate manually according to the procedure
recommended by the provider of your webserver.

There are also Docker images for each of Certbot's DNS plugins available
at https://hub.docker.com/u/certbot which automate doing domain
validation over DNS for popular providers. To use one, just replace
``certbot/certbot`` in the command above with the name of the image you
want to use. For example, to use Certbot's plugin for Amazon Route 53,
you'd use ``certbot/dns-route53``. You may also need to add flags to
Certbot and/or mount additional directories to provide access to your
DNS API credentials as specified in the :ref:`DNS plugin documentation
<dns_plugins>`.

For more information about the layout
of the ``/etc/letsencrypt`` directory, see :ref:`where-certs`.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/engine/installation/

Pip
---

Installing Certbot through pip is only supported on a best effort basis and
when using a virtual environment. Instructions for installing Certbot through
pip can be found at https://certbot.eff.org/instructions by selecting your
server software and then choosing "pip" in the "System" dropdown menu.
