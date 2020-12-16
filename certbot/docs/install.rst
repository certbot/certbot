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

Certbot currently requires Python 2.7 or 3.6+ running on a UNIX-like operating
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
know how to manage the certs
manually. `Our ciphersuites page <ciphers.html>`__
provides some information about recommended ciphersuites. If none of
these make much sense to you, you should definitely use the installation method
recommended for your system at certbot.eff.org_, which enables you to use
installer plugins that cover both of those hard topics.

If you're still not convinced and have decided to use this method, from
the server that the domain you're requesting a certficate for resolves
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

Operating System Packages
-------------------------

.. warning:: While the Certbot team tries to keep the Certbot packages offered
   by various operating systems working in the most basic sense, due to
   distribution policies and/or the limited resources of distribution
   maintainers, Certbot OS packages often have problems that other distribution
   mechanisms do not. The packages are often old resulting in a lack of bug
   fixes and features and a worse TLS configuration than is generated by newer
   versions of Certbot. They also may not configure certificate renewal for you
   or have all of Certbot's plugins available. For reasons like these, we
   recommend most users follow the instructions at
   https://certbot.eff.org/instructions and OS packages are only documented
   here as an alternative.

**Arch Linux**

.. code-block:: shell

   sudo pacman -S certbot

**Debian**

If you run Debian Buster or Debian testing/Sid, you can easily install certbot
packages through commands like:

.. code-block:: shell

   sudo apt-get update
   sudo apt-get install certbot

If you run Debian Stretch, we recommend you use the packages in Debian
backports repository. First you'll have to follow the instructions at
https://backports.debian.org/Instructions/ to enable the Stretch backports repo,
if you have not already done so. Then run:

.. code-block:: shell

   sudo apt-get install certbot -t stretch-backports

In all of these cases, there also packages available to help Certbot integrate
with Apache, nginx, or various DNS services. If you are using Apache or nginx,
we strongly recommend that you install the ``python-certbot-apache`` or
``python-certbot-nginx`` package so that Certbot can fully automate HTTPS
configuration for your server. A full list of these packages can be found
through a command like:

.. code-block:: shell

    apt search 'python-certbot*'

They can be installed by running the same installation command above but
replacing ``certbot`` with the name of the desired package.

**Ubuntu**

If you run Ubuntu, certbot can be installed using:

.. code-block:: shell

   sudo apt-get install certbot

Optionally to install the Certbot Apache plugin, you can use:

.. code-block:: shell

   sudo apt-get install python-certbot-apache

**Fedora**

.. code-block:: shell

    sudo dnf install certbot python2-certbot-apache

**FreeBSD**

  * Port: ``cd /usr/ports/security/py-certbot && make install clean``
  * Package: ``pkg install py27-certbot``

**Gentoo**

The official Certbot client is available in Gentoo Portage. From the 
official Certbot plugins, three of them are also available in Portage. 
They need to be installed separately if you require their functionality.

.. code-block:: shell

   emerge -av app-crypt/certbot
   emerge -av app-crypt/certbot-apache
   emerge -av app-crypt/certbot-nginx
   emerge -av app-crypt/certbot-dns-nsone

.. Note:: The ``app-crypt/certbot-dns-nsone`` package has a different 
   maintainer than the other packages and can lag behind in version.

**NetBSD**

  * Build from source: ``cd /usr/pkgsrc/security/py-certbot && make install clean``
  * Install pre-compiled package: ``pkg_add py27-certbot``

**OpenBSD**

  * Port: ``cd /usr/ports/security/letsencrypt/client && make install clean``
  * Package: ``pkg_add letsencrypt``

**Other Operating Systems**

OS packaging is an ongoing effort. If you'd like to package
Certbot for your distribution of choice please have a
look at the :doc:`packaging`.

.. _certbot-auto:

Certbot-Auto
------------

We used to have a shell script named ``certbot-auto`` to help people install
Certbot on UNIX operating systems, however, this script is no longer supported.

Problems with Python virtual environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using ``certbot-auto`` on a low memory system such as VPS with less than
512MB of RAM, the required dependencies of Certbot may fail to build.  This can
be identified if the pip outputs contains something like ``internal compiler
error: Killed (program cc1)``.  You can workaround this restriction by creating
a temporary swapfile::

  user@webserver:~$ sudo fallocate -l 1G /tmp/swapfile
  user@webserver:~$ sudo chmod 600 /tmp/swapfile
  user@webserver:~$ sudo mkswap /tmp/swapfile
  user@webserver:~$ sudo swapon /tmp/swapfile

Disable and remove the swapfile once the virtual environment is constructed::

  user@webserver:~$ sudo swapoff /tmp/swapfile
  user@webserver:~$ sudo rm /tmp/swapfile

Installing from source
----------------------

Installation from source is only supported for developers and the
whole process is described in the :doc:`contributing`.

.. warning:: Please do **not** use ``python certbot/setup.py install``, ``python pip
   install certbot``, or ``easy_install certbot``. Please do **not** attempt the
   installation commands as superuser/root and/or without virtual environment,
   e.g. ``sudo python certbot/setup.py install``, ``sudo pip install``, ``sudo
   ./venv/bin/...``. These modes of operation might corrupt your operating
   system and are **not supported** by the Certbot team!
