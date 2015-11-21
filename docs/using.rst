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
from your OS standard package repositories (e.g using `apt-get` or
`yum`), and for other dependencies it sets up a virtualized Python
environment with packages downloaded from PyPI [#venv]_. It also
provides automated updates.

Firstly, please `install Git`_ and run the following commands:

.. code-block:: shell

   git clone https://github.com/letsencrypt/letsencrypt
   cd letsencrypt

.. warning:: Alternatively you could `download the ZIP archive`_ and
   extract the snapshot of our repository, but it's strongly
   recommended to use the above method instead.

.. _`install Git`: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
.. _`download the ZIP archive`:
   https://github.com/letsencrypt/letsencrypt/archive/master.zip

To install and run the client you just need to type:

.. code-block:: shell

   ./letsencrypt-auto

.. note:: On RedHat/CentOS 6 you will need to enable the EPEL_
   repository before install.

.. _EPEL: http://fedoraproject.org/wiki/EPEL

Throughout the documentation, whenever you see references to
``letsencrypt`` script/binary, you can substitute in
``letsencrypt-auto``. For example, to get basic help you would type:

.. code-block:: shell

  ./letsencrypt-auto --help

or for full help, type:

.. code-block:: shell

  ./letsencrypt-auto --help all

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

**Arch Linux**

.. code-block:: shell

   sudo pacman -S letsencrypt letsencrypt-nginx letsencrypt-apache \
                  letshelp-letsencrypt

**Other Operating Systems**

Unfortunately, this is an ongoing effort. If you'd like to package
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


Plugins
=======

=========== = = ===============================================================
Plugin      A I Notes
=========== = = ===============================================================
apache_     Y Y Automates obtaining and installing a cert with Apache 2.4 on
                Debian-based distributions with ``libaugeas0`` 1.0+.
standalone_ Y N Uses a "standalone" webserver to obtain a cert.
webroot_    Y N Obtains a cert using an already running webserver.
manual_     Y N Helps you obtain a cert by giving you instructions to perform
                domain validation yourself.
nginx_      Y Y Very experimental and not included in letsencrypt-auto_.
=========== = = ===============================================================

Apache
------

If you're running Apache 2.4 on a Debian-based OS with version 1.0+ of
the ``libaugeas0`` package available, you can use the Apache plugin.
This automates both obtaining and installing certs on an Apache
webserver. To specify this plugin on the command line, simply include
``--apache``.

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

Webroot
-------

If you're running a webserver that you don't want to stop to use
standalone, you can use the webroot plugin to obtain a cert by
including ``certonly`` and ``-a webroot`` on the command line. In
addition, you'll need to specify ``--webroot-path`` with the root
directory of the files served by your webserver. For example,
``--webroot-path /var/www/html`` or
``--webroot-path /usr/share/nginx/html`` are two common webroot paths.
If multiple domains are specified, they must all use the same path.
Additionally, your server must be configured to serve files from
hidden directories.

Manual
------

If you'd like to obtain a cert running ``letsencrypt`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a cert by specifying
``certonly`` and ``-a manual`` on the command line. This requires you
to copy and paste commands into another terminal session.

Nginx
-----

In the future, if you're running Nginx you can use this plugin to
automatically obtain and install your certificate. The Nginx plugin
is still experimental, however, and is not installed with
letsencrypt-auto_. If installed, you can select this plugin on the
command line by including ``--nginx``.

Third party plugins
-------------------

These plugins are listed at
https://github.com/letsencrypt/letsencrypt/wiki/Plugins. If you're
interested, you can also :ref:`write your own plugin <dev-plugin>`.

Renewal
=======

.. note:: Let's Encrypt CA issues short lived certificates (90
   days). Make sure you renew the certificates at least once in 3
   months.

In order to renew certificates simply call the ``letsencrypt`` (or
letsencrypt-auto_) again, and use the same values when prompted. You
can automate it slightly by passing necessary flags on the CLI (see
`--help all`), or even further using the :ref:`config-file`. If you're
sure that UI doesn't prompt for any details you can add the command to
``crontab`` (make it less than every 90 days to avoid problems, say
every month).

Please note that the CA will send notification emails to the address
you provide if you do not renew certificates that are about to expire.

Let's Encrypt is working hard on automating the renewal process. Until
the tool is ready, we are sorry for the inconvenience!


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

  This is what Apache needs for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_.

``chain.pem``
  All certificates that need to be served by the browser **excluding**
  server certificate, i.e. root and intermediate certificates only.

  This is what Apache needs for `SSLCertificateChainFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatechainfile>`_.

``fullchain.pem``
  All certificates, **including** server certificate. This is
  concatenation of ``chain.pem`` and ``cert.pem``.

  This is what nginx needs for `ssl_certificate
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
give us us as much information as possible:

- copy and paste exact command line used and the output (though mind
  that the latter might include some personally identifiable
  information, including your email and domains)
- copy and paste logs from ``/var/log/letsencrypt`` (though mind they
  also might contain personally identifiable information)
- copy and paste ``letsencrypt --version`` output
- your operating system, including specific version
- specify which installation_ method you've chosen


.. rubric:: Footnotes

.. [#venv] By using this virtualized Python environment (`virtualenv
           <https://virtualenv.pypa.io>`_) we don't pollute the main
           OS space with packages from PyPI!
