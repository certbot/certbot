=====================
Manual Installation
=====================

.. contents:: Table of Contents
   :local:

.. Note:: The easiest way to install Certbot is by visiting `certbot.eff.org`_, 
where you can find the correct installation instructions for many web server 
and OS combinations.

.. _certbot.eff.org: https://certbot.eff.org/


System Requirements
===================

Certbot currently requires Python 2.6, 2.7, or 3.3+. By default, it requires
root access in order to write to ``/etc/letsencrypt``,
``/var/log/letsencrypt``, ``/var/lib/letsencrypt``; to bind to ports 80 and 443
(if you use the ``standalone`` plugin) and to read and modify webserver
configurations (if you use the ``apache`` or ``nginx`` plugins).  If none of
these apply to you, it is theoretically possible to run without root privileges,
but for most users who want to avoid running an ACME client as root, either
`letsencrypt-nosudo <https://github.com/diafygi/letsencrypt-nosudo>`_ or
`simp_le <https://github.com/zenhack/simp_le>`_ are more appropriate choices.

The Apache plugin currently requires an OS with augeas version 1.0; currently `it
supports
<https://github.com/certbot/certbot/blob/master/certbot-apache/certbot_apache/constants.py>`_
modern OSes based on Debian, Fedora, SUSE, Gentoo and Darwin.

Installing with ``certbot-auto`` requires 512MB of RAM in order to build some
of the dependencies. Installing from pre-built OS packages avoids this
requirement. You can also temporarily set a swap file. See "Problems with
Python virtual environment" below for details.

Alternate installation methods
================================

If you are offline or your operating system doesn't provide a package, you can use
an alternate method for installing ``certbot``.

.. _certbot-auto:

Certbot-Auto
------------

The ``certbot-auto`` wrapper script installs Certbot, obtaining some dependencies
from your web server OS and putting others in a python virtual environment. You can
download and run it as follows::

  user@webserver:~$ wget https://dl.eff.org/certbot-auto
  user@webserver:~$ chmod a+x ./certbot-auto
  user@webserver:~$ ./certbot-auto --help

.. hint:: The certbot-auto download is protected by HTTPS, which is pretty good, but if you'd like to
          double check the integrity of the ``certbot-auto`` script, you can use these steps for verification before running it::

            user@server:~$ wget -N https://dl.eff.org/certbot-auto.asc
            user@server:~$ gpg2 --recv-key A2CFB51FA275A7286234E7B24D17C995CD9775F2
            user@server:~$ gpg2 --trusted-key 4D17C995CD9775F2 --verify certbot-auto.asc certbot-auto

The ``certbot-auto`` command updates to the latest client release automatically.
Since ``certbot-auto`` is a wrapper to ``certbot``, it accepts exactly
the same command line flags and arguments. For more information, see
`Certbot command-line options <https://certbot.eff.org/docs/using.html#command-line-options>`_.

For full command line help, you can type::

  ./certbot-auto --help all

Running with Docker
-------------------

Docker_ is an amazingly simple and quick way to obtain a
certificate. However, this mode of operation is unable to install
certificates or configure your webserver, because our installer
plugins cannot reach your webserver from inside the Docker container.

Most users should use the operating system packages (see instructions at
certbot.eff.org_) or, as a fallback, ``certbot-auto``. You should only
use Docker if you are sure you know what you are doing and have a
good reason to do so.

You should definitely read the :ref:`where-certs` section, in order to
know how to manage the certs
manually. `Our ciphersuites page <ciphers.html>`__
provides some information about recommended ciphersuites. If none of
these make much sense to you, you should definitely use the
certbot-auto_ method, which enables you to use installer plugins
that cover both of those hard topics.

If you're still not convinced and have decided to use this method,
from the server that the domain you're requesting a cert for resolves
to, `install Docker`_, then issue the following command:

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 -p 80:80 --name certbot \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               certbot/certbot certonly

Running Certbot with the ``certonly`` command will obtain a certificate and place it in the directory
``/etc/letsencrypt/live`` on your system. Because Certonly cannot install the certificate from
within Docker, you must install the certificate manually according to the procedure
recommended by the provider of your webserver.

For more information about the layout
of the ``/etc/letsencrypt`` directory, see :ref:`where-certs`.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/engine/installation/

Operating System Packages
-------------------------

**Arch Linux**

.. code-block:: shell

   sudo pacman -S certbot

**Debian**

If you run Debian Stretch or Debian Sid, you can install certbot packages.

.. code-block:: shell

   sudo apt-get update
   sudo apt-get install certbot python-certbot-apache

If you don't want to use the Apache plugin, you can omit the
``python-certbot-apache`` package.

Packages exist for Debian Jessie via backports. First you'll have to follow the
instructions at http://backports.debian.org/Instructions/ to enable the Jessie backports
repo, if you have not already done so. Then run:

.. code-block:: shell

   sudo apt-get install certbot python-certbot-apache -t jessie-backports

**Fedora**

.. code-block:: shell

    sudo dnf install certbot python2-certbot-apache

**FreeBSD**

  * Port: ``cd /usr/ports/security/py-certbot && make install clean``
  * Package: ``pkg install py27-certbot``

**Gentoo**

The official Certbot client is available in Gentoo Portage. If you
want to use the Apache plugin, it has to be installed separately:

.. code-block:: shell

   emerge -av app-crypt/certbot
   emerge -av app-crypt/certbot-apache

When using the Apache plugin, you will run into a "cannot find a cert or key
directive" error if you're sporting the default Gentoo ``httpd.conf``.
You can fix this by commenting out two lines in ``/etc/apache2/httpd.conf``
as follows:

Change

.. code-block:: shell

   <IfDefine SSL>
   LoadModule ssl_module modules/mod_ssl.so
   </IfDefine>

to

.. code-block:: shell

   #<IfDefine SSL>
   LoadModule ssl_module modules/mod_ssl.so
   #</IfDefine>

For the time being, this is the only way for the Apache plugin to recognise
the appropriate directives when installing the certificate.
Note: this change is not required for the other plugins.

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

Installing from source
----------------------

Installation from source is only supported for developers and the
whole process is described in the :doc:`contributing`.

.. warning:: Please do **not** use ``python setup.py install``, ``python pip
   install .``, or ``easy_install .``. Please do **not** attempt the
   installation commands as superuser/root and/or without virtual environment,
   e.g. ``sudo python setup.py install``, ``sudo pip install``, ``sudo
   ./venv/bin/...``. These modes of operation might corrupt your operating
   system and are **not supported** by the Certbot team!

Problems with Python virtual environment
----------------------------------------

On a low memory system such as VPS with less than 512MB of RAM, the required dependencies of Certbot will fail to build.
This can be identified if the pip outputs contains something like ``internal compiler error: Killed (program cc1)``.
You can workaround this restriction by creating a temporary swapfile::

  user@webserver:~$ sudo fallocate -l 1G /tmp/swapfile
  user@webserver:~$ sudo chmod 600 /tmp/swapfile
  user@webserver:~$ sudo mkswap /tmp/swapfile
  user@webserver:~$ sudo swapon /tmp/swapfile

Disable and remove the swapfile once the virtual environment is constructed::

  user@webserver:~$ sudo swapoff /tmp/swapfile
  user@webserver:~$ sudo rm /tmp/swapfile


.. _getting_certs:


Getting Certificates
==================== 




XXX This section needs to have command-line examples for each plug-in.

.. _apache:

Apache
------

The Apache plugin currently requires an OS with augeas version 1.0; currently `it
supports
<https://github.com/certbot/certbot/blob/master/certbot-apache/certbot_apache/constants.py>`_
modern OSes based on Debian, Fedora, SUSE, Gentoo and Darwin.
This automates both obtaining *and* installing certificates on an Apache
webserver. To specify this plugin on the command line, simply include
``--apache``.

* Apache plugin: (TLS-SNI-01) Tries to edit your Apache configuration files to temporarily serve 
  a Certbot-generated certificate for a specified name. Use the Apache plugin when you're running 
  Certbot on a web server with Apache listening on port 443.

.. _manual:

Manual
------

If you'd like to obtain a certificate running ``certbot`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a certificate by specifying
``certonly`` and ``--manual`` on the command line. This requires you
to copy and paste commands into another terminal session, which may
be on a different computer.

The manual plugin can use either the ``http``, ``dns`` or the
``tls-sni`` challenge. You can use the ``--preferred-challenges`` option
to choose the challenge of your preference.

The ``http`` challenge will ask you to place a file with a specific name and
specific content in the ``/.well-known/acme-challenge/`` directory directly
in the top-level directory (“web root”) containing the files served by your
webserver. In essence it's the same as the webroot_ plugin, but not automated.

When using the ``dns`` challenge, ``certbot`` will ask you to place a TXT DNS
record with specific contents under the domain name consisting of the hostname
for which you want a certificate issued, prepended by ``_acme-challenge``.

For example, for the domain ``example.com``, a zone file entry would look like::
        _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

When using the ``tls-sni`` challenge, ``certbot`` will prepare a self-signed
SSL certificate for you with the challenge validation appropriately
encoded into a subjectAlternatNames entry. You will need to configure
your SSL server to present this challenge SSL certificate to the ACME
server using SNI.

Additionally you can specify scripts to prepare for validation and
perform the authentication procedure and/or clean up after it by using
the ``--manual-auth-hook`` and ``--manual-cleanup-hook`` flags. This is
described in more depth in the hooks_ section.

* Manual plugin: (DNS-01 or HTTP-01) Either tells you what changes to make to your configuration or updates 
  your DNS records using an external script (for DNS-01) or your webroot (for HTTP-01). Use the Manual 
  plugin if you have the technical knowledge to make configuration changes yourself when asked to do so. 

.. _nginx:

Nginx
-----

The Nginx plugin has been distributed with Certbot since version 0.9.0 and should
work for most configurations. We recommend backing up Nginx
configurations before using it (though you can also revert changes to
configurations with ``certbot --nginx rollback``). You can use it by providing
the ``--nginx`` flag on the commandline::

   certbot –nginx

* NGINX plugin: (TLS-SNI-01) Tries to edit your NGINX configuration files to temporarily serve a
  Certbot-generated certificate for a specified name. Use the NGINX plugin when you're running 
  Certbot on a web server with NGINX listening on port 443.

.. _standalone:


Standalone
----------

Use standalone mode to obtain a certificate if you don't want to use (or don't currently have)
existing server software. The standalone plugin does not rely on any other server
software running on the machine where you obtain the certificate.

To obtain a certificate using a "standalone" webserver, you can use the
standalone plugin by including ``certonly`` and ``--standalone``
on the command line. This plugin needs to bind to port 80 or 443 in
order to perform domain validation, so you may need to stop your
existing webserver. To control which port the plugin uses, include
one of the options shown below on the command line.

    * ``--preferred-challenges http`` to use port 80
    * ``--preferred-challenges tls-sni`` to use port 443

It must still be possible for your machine to accept inbound connections from
the Internet on the specified port using each requested domain name.

.. note:: The ``--standalone-supported-challenges`` option has been
   deprecated since ``certbot`` version 0.9.0.

* Standalone plugin: (TLS-SNI-01 or HTTP-01) Tries to run a temporary web server listening on either HTTP on 
  port 80 (for HTTP-01) or HTTPS on port 443 (for TLS-SNI-01). Use the Standalone plugin if no existing program 
  is listening to these ports. Choose TLS-SNI-01 or HTTP-01 using the `--preferred-challenges` option.


.. _webroot:

Webroot
-------

If you're running a local webserver for which you have the ability
to modify the content being served, and you'd prefer not to stop the
webserver during the certificate issuance process, you can use the webroot
plugin to obtain a certificate by including ``certonly`` and ``--webroot`` on
the command line. In addition, you'll need to specify ``--webroot-path``
or ``-w`` with the top-level directory ("web root") containing the files
served by your webserver. For example, ``--webroot-path /var/www/html``
or ``--webroot-path /usr/share/nginx/html`` are two common webroot paths.

If you're getting a certificate for many domains at once, the plugin
needs to know where each domain's files are served from, which could
potentially be a separate directory for each domain. When requesting a
certificate for multiple domains, each domain will use the most recently
specified ``--webroot-path``. So, for instance::

  certbot certonly --webroot -w /var/www/example/ -d www.example.com -d example.com -w /var/www/other -d other.example.net -d another.other.example.net

would obtain a single certificate for all of those names, using the 
``/var/www/example`` webroot directory for the first two, and ``/var/www/other`` for the second two.

The webroot plugin works by creating a temporary file for each of your requested
domains in ``${webroot-path}/.well-known/acme-challenge``. Then the Let's Encrypt
validation server makes HTTP requests to validate that the DNS for each
requested domain resolves to the server running certbot. An example request
made to your web server would look like::

  66.133.109.36 - - [05/Jan/2016:20:11:24 -0500] "GET /.well-known/acme-challenge/HGr8U1IeTW4kY_Z6UIyaakzOkyQgPr_7ArlLgtZE8SX HTTP/1.1" 200 87 "-" "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)"

Note that to use the webroot plugin, your server must be configured to serve
files from hidden directories. If ``/.well-known`` is treated specially by
your webserver configuration, you might need to modify the configuration
to ensure that files inside ``/.well-known/acme-challenge`` are served by
the webserver.

* Webroot plugin: (HTTP-01) Tries to place a file where it can be served over HTTP on port 80 by a
  web server running on your system. Use the Webroot plugin when you're running Certbot on 
  a web server with any server application listening on port 80 serving files from a folder on disk in response.


.. _combination:


Combining plugins
-----------------

Sometimes you may want to specify a combination of distinct authenticator and
installer plugins. To do so, specify the authenticator plugin with
``--authenticator`` or ``-a`` and the installer plugin with ``--installer`` or
``-i``.

For instance, you may want to create a certificate using the webroot_ plugin
for authentication and the apache_ plugin for installation, perhaps because you
use a proxy or CDN for SSL and only want to secure the connection between them
and your origin server, which cannot use the tls-sni-01_ challenge due to the
intermediate proxy.

::
    certbot run -a webroot -i apache -w /var/www/html -d example.com



