==========
User Guide
==========

.. contents:: Table of Contents
   :local:

.. _installation:

Installation
============

.. _letsencrypt-auto:

letsencrypt-auto
----------------

``letsencrypt-auto`` is a wrapper which installs some dependencies
from your OS standard package repositories (e.g. using `apt-get` or
`yum`), and for other dependencies it sets up a virtualized Python
environment with packages downloaded from PyPI [#venv]_. It also
provides automated updates.

To install and run the client, just type...

.. code-block:: shell

   ./letsencrypt-auto

.. hint:: During the beta phase, Let's Encrypt enforces strict rate limits on
   the number of certificates issued for one domain. It is recommended to
   initially use the test server via `--test-cert` until you get the desired
   certificates.

Throughout the documentation, whenever you see references to
``letsencrypt`` script/binary, you can substitute in
``letsencrypt-auto``. For example, to get basic help you would type:

.. code-block:: shell

  ./letsencrypt-auto --help

or for full help, type:

.. code-block:: shell

  ./letsencrypt-auto --help all


``letsencrypt-auto`` is the recommended method of running the Let's Encrypt
client beta releases on systems that don't have a packaged version.  Debian,
Arch Linux, Gentoo, FreeBSD, and OpenBSD now have native packages, so on those
systems you can just install ``letsencrypt`` (and perhaps
``letsencrypt-apache``).  If you'd like to run the latest copy from Git, or
run your own locally modified copy of the client, follow the instructions in
the :doc:`contributing`.  Some `other methods of installation`_ are discussed
below.


Plugins
=======

The Let's Encrypt client supports a number of different "plugins" that can be
used to obtain and/or install certificates.  Plugins that can obtain a cert
are called "authenticators" and can be used with the "certonly" command.
Plugins that can install a cert are called "installers".  Plugins that do both
can be used with the "letsencrypt run" command, which is the default.

=========== ==== ==== ===============================================================
Plugin      Auth Inst Notes
=========== ==== ==== ===============================================================
apache_     Y    Y    Automates obtaining and installing a cert with Apache 2.4 on
                      Debian-based distributions with ``libaugeas0`` 1.0+.
standalone_ Y    N    Uses a "standalone" webserver to obtain a cert. This is useful
                      on systems with no webserver, or when direct integration with
                      the local webserver is not supported or not desired.
webroot_    Y    N    Obtains a cert by writing to the webroot directory of an
                      already running webserver.
manual_     Y    N    Helps you obtain a cert by giving you instructions to perform
                      domain validation yourself.
nginx_      Y    Y    Very experimental and not included in letsencrypt-auto_.
=========== ==== ==== ===============================================================

Future plugins for IMAP servers, SMTP servers, IRC servers, etc, are likely to
be installers but not authenticators.

Apache
------

If you're running Apache 2.4 on a Debian-based OS with version 1.0+ of
the ``libaugeas0`` package available, you can use the Apache plugin.
This automates both obtaining *and* installing certs on an Apache
webserver. To specify this plugin on the command line, simply include
``--apache``.

Webroot
-------

If you're running a local webserver for which you have the ability
to modify the content being served, and you'd prefer not to stop the
webserver during the certificate issuance process, you can use the webroot
plugin to obtain a cert by including ``certonly`` and ``--webroot`` on
the command line. In addition, you'll need to specify ``--webroot-path``
or ``-w`` with the top-level directory ("web root") containing the files
served by your webserver. For example, ``--webroot-path /var/www/html``
or ``--webroot-path /usr/share/nginx/html`` are two common webroot paths.

If you're getting a certificate for many domains at once, the plugin
needs to know where each domain's files are served from, which could
potentially be a separate directory for each domain. When requested a
certificate for multiple domains, each domain will use the most recently
specified ``--webroot-path``.  So, for instance,

``letsencrypt certonly --webroot -w /var/www/example/ -d www.example.com -d example.com -w /var/www/other -d other.example.net -d another.other.example.net``

would obtain a single certificate for all of those names, using the
``/var/www/example`` webroot directory for the first two, and
``/var/www/other`` for the second two.

The webroot plugin works by creating a temporary file for each of your requested
domains in ``${webroot-path}/.well-known/acme-challenge``. Then the Let's
Encrypt validation server makes HTTP requests to validate that the DNS for each
requested domain resolves to the server running letsencrypt. An example request
made to your web server would look like:

::

    66.133.109.36 - - [05/Jan/2016:20:11:24 -0500] "GET /.well-known/acme-challenge/HGr8U1IeTW4kY_Z6UIyaakzOkyQgPr_7ArlLgtZE8SX HTTP/1.1" 200 87 "-" "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)"

Note that to use the webroot plugin, your server must be configured to serve
files from hidden directories. If ``/.well-known`` is treated specially by
your webserver configuration, you might need to modify the configuration
to ensure that files inside ``/.well-known/acme-challenge`` are served by
the webserver.

Standalone
----------

To obtain a cert using a "standalone" webserver, you can use the
standalone plugin by including ``certonly`` and ``--standalone``
on the command line. This plugin needs to bind to port 80 or 443 in
order to perform domain validation, so you may need to stop your
existing webserver. To control which port the plugin uses, include
one of the options shown below on the command line.

    * ``--standalone-supported-challenges http-01`` to use port 80
    * ``--standalone-supported-challenges tls-sni-01`` to use port 443

The standalone plugin does not rely on any other server software running
on the machine where you obtain the certificate. It must still be possible
for that machine to accept inbound connections from the Internet on the
specified port using each requested domain name.

Manual
------

If you'd like to obtain a cert running ``letsencrypt`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a cert by specifying
``certonly`` and ``--manual`` on the command line. This requires you
to copy and paste commands into another terminal session, which may
be on a different computer.

Nginx
-----

In the future, if you're running Nginx you can use this plugin to
automatically obtain and install your certificate. The Nginx plugin
is still experimental, however, and is not installed with
letsencrypt-auto_. If installed, you can select this plugin on the
command line by including ``--nginx``.

Third-party plugins
-------------------

These plugins are listed at
https://github.com/letsencrypt/letsencrypt/wiki/Plugins. If you're
interested, you can also :ref:`write your own plugin <dev-plugin>`.

Renewal
=======

.. note:: Let's Encrypt CA issues short-lived certificates (90
   days). Make sure you renew the certificates at least once in 3
   months.

The ``letsencrypt`` client now supports a ``renew`` action to check
all installed certificates for impending expiry and attempt to renew
them. The simplest form is simply

``letsencrypt renew``

This will attempt to renew any previously-obtained certificates that
expire in less than 30 days. The same plugin and options that were used
at the time the certificate was originally issued will be used for the
renewal attempt, unless you specify other plugins or options.

If you're sure that this command executes successfully without human
intervention, you can add the command to ``crontab`` (since certificates
are only renewed when they're determined to be near expiry, the command
can run on a regular basis, like every week or every day); note that
the current version provides detailed output describing either renewal
success or failure.

The ``--force-renew`` flag may be helpful for automating renewal;
it causes the expiration time of the certificate(s) to be ignored when
considering renewal, and attempts to renew each and every installed
certificate regardless of its age. (This form is not appropriate to run
daily because each certificate will be renewed every day, which will
quickly run into the certificate authority rate limit.)

Note that options provided to ``letsencrypt renew`` will apply to
*every* certificate for which renewal is attempted; for example,
``letsencrypt renew --rsa-key-size 4096`` would try to replace every
near-expiry certificate with an equivalent certificate using a 4096-bit
RSA public key. If a certificate is successfully renewed using
specified options, those options will be saved and used for future
renewals of that certificate.


An alternative form that provides for more fine-grained control over the
renewal process (while renewing specified certificates one at a time),
is ``letsencrypt certonly`` with the complete set of subject domains of
a specific certificate specified via `-d` flags, like

``letsencrypt certonly -d example.com -d www.example.com``

(All of the domains covered by the certificate must be specified in
this case in order to renew and replace the old certificate rather
than obtaining a new one; don't forget any `www.` domains! Specifying
a subset of the domains creates a new, separate certificate containing
only those domains, rather than replacing the original certificate.)
The ``certonly`` form attempts to renew one individual certificate.


Please note that the CA will send notification emails to the address
you provide if you do not renew certificates that are about to expire.

Let's Encrypt is working hard on improving the renewal process, and we
apologize for any inconveniences you encounter in integrating these
commands into your individual environment.


.. _where-certs:

Where are my certificates?
==========================

First of all, we encourage you to use Apache or nginx installers, both
which perform the certificate management automatically. If, however,
you prefer to manage everything by hand, this section provides
information on where to find necessary files.

All generated keys and issued certificates can be found in
``/etc/letsencrypt/live/$domain``. Rather than copying, please point
your (web) server configuration directly to those files (or create
symlinks). During the renewal_, ``/etc/letsencrypt/live`` is updated
with the latest necessary files.

.. note:: ``/etc/letsencrypt/archive`` and ``/etc/letsencrypt/keys``
   contain all previous keys and certificates, while
   ``/etc/letsencrypt/live`` symlinks to the latest versions.

The following files are available:

``privkey.pem``
  Private key for the certificate.

  .. warning:: This **must be kept secret at all times**! Never share
     it with anyone, including Let's Encrypt developers. You cannot
     put it into a safe, however - your server still needs to access
     this file in order for SSL/TLS to work.

  This is what Apache needs for `SSLCertificateKeyFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatekeyfile>`_,
  and nginx for `ssl_certificate_key
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key>`_.

``cert.pem``
  Server certificate only.

  This is what Apache < 2.4.8 needs for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_.

``chain.pem``
  All certificates that need to be served by the browser **excluding**
  server certificate, i.e. root and intermediate certificates only.

  This is what Apache < 2.4.8 needs for `SSLCertificateChainFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatechainfile>`_,
  and what nginx >= 1.3.7 needs for `ssl_trusted_certificate
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_trusted_certificate>`_.

``fullchain.pem``
  All certificates, **including** server certificate. This is
  concatenation of ``chain.pem`` and ``cert.pem``.

  This is what Apache >= 2.4.8 needs for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_,
  and what nginx needs for `ssl_certificate
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate>`_.


For both chain files, all certificates are ordered from root (primary
certificate) towards leaf.

Please note, that **you must use** either ``chain.pem`` or
``fullchain.pem``. In case of webservers, using only ``cert.pem``,
will cause nasty errors served through the browsers!

.. note:: All files are PEM-encoded (as the filename suffix
   suggests). If you need other format, such as DER or PFX, then you
   could convert using ``openssl``, but this means you will not
   benefit from automatic renewal_!


.. _config-file:

Configuration file
==================

It is possible to specify configuration file with
``letsencrypt-auto --config cli.ini`` (or shorter ``-c cli.ini``). An
example configuration file is shown below:

.. include:: ../examples/cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

.. keep it up to date with constants.py


Getting help
============

If you're having problems you can chat with us on `IRC (#letsencrypt @
Freenode) <https://webchat.freenode.net?channels=%23letsencrypt>`_ or
get support on our `forums <https://community.letsencrypt.org>`_.

If you find a bug in the software, please do report it in our `issue
tracker
<https://github.com/letsencrypt/letsencrypt/issues>`_. Remember to
give us as much information as possible:

- copy and paste exact command line used and the output (though mind
  that the latter might include some personally identifiable
  information, including your email and domains)
- copy and paste logs from ``/var/log/letsencrypt`` (though mind they
  also might contain personally identifiable information)
- copy and paste ``letsencrypt --version`` output
- your operating system, including specific version
- specify which installation_ method you've chosen

Other methods of installation
=============================

Running with Docker
-------------------

Docker_ is an amazingly simple and quick way to obtain a
certificate. However, this mode of operation is unable to install
certificates or configure your webserver, because our installer
plugins cannot reach it from inside the Docker container.

You should definitely read the :ref:`where-certs` section, in order to
know how to manage the certs
manually. https://github.com/letsencrypt/letsencrypt/wiki/Ciphersuite-guidance
provides some information about recommended ciphersuites. If none of
these make much sense to you, you should definitely use the
letsencrypt-auto_ method, which enables you to use installer plugins
that cover both of those hard topics.

If you're still not convinced and have decided to use this method,
from the server that the domain you're requesting a cert for resolves
to, `install Docker`_, then issue the following command:

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 -p 80:80 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/letsencrypt:latest auth

and follow the instructions (note that ``auth`` command is explicitly
used - no installer plugins involved). Your new cert will be available
in ``/etc/letsencrypt/live`` on the host.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/userguide/


Operating System Packages
--------------------------

**FreeBSD**

  * Port: ``cd /usr/ports/security/py-letsencrypt && make install clean``
  * Package: ``pkg install py27-letsencrypt``

**OpenBSD**

  * Port: ``cd /usr/ports/security/letsencrypt/client && make install clean``
  * Package: ``pkg_add letsencrypt``

**Arch Linux**

.. code-block:: shell

   sudo pacman -S letsencrypt letsencrypt-apache

**Debian**

If you run Debian Stretch or Debian Sid, you can install letsencrypt packages.

.. code-block:: shell

   sudo apt-get update
   sudo apt-get install letsencrypt python-letsencrypt-apache

If you don't want to use the Apache plugin, you can omit the
``python-letsencrypt-apache`` package.

Packages for Debian Jessie are coming in the next few weeks.

**Gentoo**

The official Let's Encrypt client is available in Gentoo Portage. If you
want to use the Apache plugin, it has to be installed separately:

.. code-block:: shell

   emerge -av app-crypt/letsencrypt
   emerge -av app-crypt/letsencrypt-apache

Currently, only the Apache plugin is included in Portage. However, if you
want the nginx plugin, you can use Layman to add the mrueg overlay which
does include the nginx plugin package:

.. code-block:: shell

   emerge -av app-portage/layman
   layman -S
   layman -a mrueg
   emerge -av app-crypt/letsencrypt-nginx

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

**Other Operating Systems**

OS packaging is an ongoing effort. If you'd like to package
Let's Encrypt client for your distribution of choice please have a
look at the :doc:`packaging`.


From source
-----------

Installation from source is only supported for developers and the
whole process is described in the :doc:`contributing`.

.. warning:: Please do **not** use ``python setup.py install`` or
   ``python pip install .``. Please do **not** attempt the
   installation commands as superuser/root and/or without virtual
   environment, e.g. ``sudo python setup.py install``, ``sudo pip
   install``, ``sudo ./venv/bin/...``. These modes of operation might
   corrupt your operating system and are **not supported** by the
   Let's Encrypt team!


Comparison of different methods
-------------------------------

Unless you have a very specific requirements, we kindly ask you to use
the letsencrypt-auto_ method. It's the fastest, the most thoroughly
tested and the most reliable way of getting our software and the free
SSL certificates!

Beyond the methods discussed here, other methods may be possible, such as
installing Let's Encrypt directly with pip from PyPI or downloading a ZIP
archive from GitHub may be technically possible but are not presently
recommended or supported.


.. rubric:: Footnotes

.. [#venv] By using this virtualized Python environment (`virtualenv
           <https://virtualenv.pypa.io>`_) we don't pollute the main
           OS space with packages from PyPI!
