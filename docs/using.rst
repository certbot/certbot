==========
User Guide
==========

.. contents:: Table of Contents
   :local:

Certbot Commands
================

Certbot uses a number of different commands (also referred
to as "subcommands") to request specific actions such as
obtaining, renewing, or revoking certificates. The most important
and commonly-used commands will be discussed throughout this
document; an exhaustive list also appears near the end of the document.

The ``certbot`` script on your web server might be named ``letsencrypt`` if your system uses an older package, or ``certbot-auto`` if you used an alternate installation method. Throughout the docs, whenever you see ``certbot``, swap in the correct name as needed.

.. _plugins:

Getting certificates (and choosing plugins)
===========================================

The Certbot client supports two types of plugins for
obtaining and installing certificates: authenticators and installers.

Authenticators are plugins used with the ``certonly`` command to obtain a cert.
The authenticator validates that you
control the domain(s) you are requesting a cert for, obtains a cert for the specified
domain(s), and places the cert in the ``/etc/letsencrypt`` directory on your
machine. The authenticator does not install the cert (it does not edit any of your server's configuration files to serve the
obtained certificate). If you specify multiple domains to authenticate, they will
all be listed in a single certificate. To obtain multiple separate certificates
you will need to run Certbot multiple times.

Installers are Plugins used with the ``install`` command to install a cert.
These plugins can modify your webserver's configuration to
serve your website over HTTPS using certificates obtained by certbot.

Plugins that do both can be used with the ``certbot run`` command, which is the default
when no command is specified. The ``run`` subcommand can also be used to specify
a combination of distinct authenticator and installer plugins.

=========== ==== ==== =============================================================== =============================
Plugin      Auth Inst Notes                                                           Challenge types (and port)
=========== ==== ==== =============================================================== =============================
apache_     Y    Y    | Automates obtaining and installing a cert with Apache 2.4 on  tls-sni-01_ (443)
                      | Debian-based distributions with ``libaugeas0`` 1.0+.
webroot_    Y    N    | Obtains a cert by writing to the webroot directory of an      http-01_ (80)
                      | already running webserver.
nginx_      Y    Y    | Automates obtaining and installing a cert with Nginx. Alpha   tls-sni-01_ (443)
                      | release shipped with Certbot 0.9.0.
standalone_ Y    N    | Uses a "standalone" webserver to obtain a cert. Requires      http-01_ (80) or
                      | port 80 or 443 to be available. This is useful on systems     tls-sni-01_ (443)
                      | with no webserver, or when direct integration with the local
                      | webserver is not supported or not desired.
manual_     Y    N    | Helps you obtain a cert by giving you instructions to perform http-01_ (80) or
                      | domain validation yourself. Additionally allows you to        dns-01_ (53)
                      | specify scripts to automate the validation task in a
                      | customized way.
=========== ==== ==== =============================================================== =============================

Under the hood, plugins use one of several ACME protocol challenges_ to
prove you control a domain.  The options are http-01_ (which uses port 80),
tls-sni-01_ (port 443) and dns-01_ (requiring configuration of a DNS server on
port 53, though that's often not the same machine as your webserver). A few
plugins support more than one challenge type, in which case you can choose one
with ``--preferred-challenges``.

There are also many third-party-plugins_ available. Below we describe in more detail
the circumstances in which each plugin can be used, and how to use it.

.. _challenges: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7
.. _tls-sni-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.3
.. _http-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.2
.. _dns-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.4

Apache
------

The Apache plugin currently requires an OS with augeas version 1.0; currently `it
supports
<https://github.com/certbot/certbot/blob/master/certbot-apache/certbot_apache/constants.py>`_
modern OSes based on Debian, Fedora, SUSE, Gentoo and Darwin.
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
potentially be a separate directory for each domain. When requesting a
certificate for multiple domains, each domain will use the most recently
specified ``--webroot-path``.  So, for instance,

::

    certbot certonly --webroot -w /var/www/example/ -d www.example.com -d example.com -w /var/www/other -d other.example.net -d another.other.example.net

would obtain a single certificate for all of those names, using the
``/var/www/example`` webroot directory for the first two, and
``/var/www/other`` for the second two.

The webroot plugin works by creating a temporary file for each of your requested
domains in ``${webroot-path}/.well-known/acme-challenge``. Then the Let's Encrypt
validation server makes HTTP requests to validate that the DNS for each
requested domain resolves to the server running certbot. An example request
made to your web server would look like:

::

    66.133.109.36 - - [05/Jan/2016:20:11:24 -0500] "GET /.well-known/acme-challenge/HGr8U1IeTW4kY_Z6UIyaakzOkyQgPr_7ArlLgtZE8SX HTTP/1.1" 200 87 "-" "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)"

Note that to use the webroot plugin, your server must be configured to serve
files from hidden directories. If ``/.well-known`` is treated specially by
your webserver configuration, you might need to modify the configuration
to ensure that files inside ``/.well-known/acme-challenge`` are served by
the webserver.

Nginx
-----

The Nginx plugin has been distributed with Certbot since version 0.9.0 and should
work for most configurations. Because it is alpha code, we recommend backing up Nginx
configurations before using it (though you can also revert changes to
configurations with ``certbot --nginx rollback``). You can use it by providing
the ``--nginx`` flag on the commandline.

::

   certbot --nginx

Standalone
----------

Use standalone mode to obtain a cert if you don't want to use (or don't currently have)
existing server software. The standalone plugin does not rely on any other server
software running on the machine where you obtain the cert.

To obtain a cert using a "standalone" webserver, you can use the
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

Manual
------

If you'd like to obtain a cert running ``certbot`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a cert by specifying
``certonly`` and ``--manual`` on the command line. This requires you
to copy and paste commands into another terminal session, which may
be on a different computer.

The manual plugin can use either the ``http`` or the ``dns`` challenge. You
can use the ``--preferred-challenges`` option to choose the challenge of your
preference.
The ``http`` challenge will ask you to place a file with a specific name and
specific content in the ``/.well-known/acme-challenge/`` directory directly
in the top-level directory (“web root”) containing the files served by your
webserver. In essence it's the same as the webroot_ plugin, but not automated.
When using the ``dns`` plugin, ``certbot`` will ask you to place a TXT DNS
record with specific contents under the domain name consisting of the hostname
for which you want a certificate issued, prepended by ``_acme-challenge``.

For example, for the domain ``example.com``, a zone file entry would look like:

::

        _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

Additionally you can specify scripts to prepare for validation and perform the
authentication procedure  and/or clean up after it by using the
``--manual-auth-hook`` and ``--manual-cleanup-hook`` flags. This is described in
more depth in the hooks_ section.

.. _third-party-plugins:

Third-party plugins
-------------------

There are also a number of third-party plugins for the client, provided by
other developers. Many are beta/experimental, but some are already in
widespread use:

=========== ==== ==== ===============================================================
Plugin      Auth Inst Notes
=========== ==== ==== ===============================================================
plesk_      Y    Y    Integration with the Plesk web hosting tool
haproxy_    Y    Y    Integration with the HAProxy load balancer
s3front_    Y    Y    Integration with Amazon CloudFront distribution of S3 buckets
gandi_      Y    Y    Integration with Gandi's hosting products and API
varnish_    Y    N    Obtain certs via a Varnish server
external_   Y    N    A plugin for convenient scripting (See also ticket 2782_)
icecast_    N    Y    Deploy certs to Icecast 2 streaming media servers
pritunl_    N    Y    Install certs in pritunl distributed OpenVPN servers
proxmox_    N    Y    Install certs in Proxmox Virtualization servers
postfix_    N    Y    STARTTLS Everywhere is becoming a Certbot Postfix/Exim plugin
heroku_     Y    Y    Integration with Heroku SSL
=========== ==== ==== ===============================================================

.. _plesk: https://github.com/plesk/letsencrypt-plesk
.. _haproxy: https://github.com/greenhost/certbot-haproxy
.. _s3front: https://github.com/dlapiduz/letsencrypt-s3front
.. _gandi: https://github.com/Gandi/letsencrypt-gandi
.. _icecast: https://github.com/e00E/lets-encrypt-icecast
.. _varnish: http://git.sesse.net/?p=letsencrypt-varnish-plugin
.. _2782: https://github.com/certbot/certbot/issues/2782
.. _pritunl: https://github.com/kharkevich/letsencrypt-pritunl
.. _proxmox: https://github.com/kharkevich/letsencrypt-proxmox
.. _external: https://github.com/marcan/letsencrypt-external
.. _postfix: https://github.com/EFForg/starttls-everywhere
.. _heroku: https://github.com/gboudreau/certbot-heroku

If you're interested, you can also :ref:`write your own plugin <dev-plugin>`.

.. _managing-certs:

Managing certificates
=====================

To view a list of the certificates Certbot knows about, run
the ``certificates`` subcommand:

``certbot certificates``

This returns information in the following format::

  Found the following certs:
    Certificate Name: example.com
      Domains: example.com, www.example.com
      Expiry Date: 2017-02-19 19:53:00+00:00 (VALID: 30 days)
      Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
      Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem

``Certificate Name`` shows the name of the certificate. Pass this name
using the ``--cert-name`` flag to specify a particular certificate for the ``run``,
``certonly``, ``certificates``, ``renew``, and ``delete`` commands. Example::

  certbot certonly --cert-name example.com


Re-creating and Updating Existing Certificates
----------------------------------------------

You can use ``certonly`` or ``run`` subcommands to request
the creation of a single new certificate even if you already have an
existing certificate with some of the same domain names.

If a certificate is requested with ``run`` or ``certonly`` specifying a
certificate name that already exists, Certbot updates
the existing certificate. Otherwise a new certificate
is created and assigned the specified name.

The ``--force-renewal``, ``--duplicate``, and ``--expand`` options
control Certbot's behavior when re-creating
a certificate with the same name as an existing certificate.
If you don't specify a requested behavior, Certbot may ask you what you intended.


``--force-renewal`` tells Certbot to request a new certificate
with the same domains as an existing certificate. Each domain
must be explicitly specified via ``-d``. If successful, this certificate
is saved alongside the earlier one and symbolic links (the "``live``"
reference) will be updated to point to the new certificate. This is a
valid method of renewing a specific individual
certificate.

``--duplicate`` tells Certbot to create a separate, unrelated certificate
with the same domains as an existing certificate. This certificate is
saved completely separately from the prior one. Most users will not
need to issue this command in normal circumstances.

``--expand`` tells Certbot to update an existing certificate with a new
certificate that contains all of the old domains and one or more additional
new domains.

``--allow-subset-of-names`` tells Certbot to continue with certificate generation if
only some of the specified domain authorizations can be obtained. This may
be useful if some domains specified in a certificate no longer point at this
system.

Whenever you obtain a new certificate in any of these ways, the new
certificate exists alongside any previously obtained certificates, whether
or not the previous certificates have expired. The generation of a new
certificate counts against several rate limits that are intended to prevent
abuse of the ACME protocol, as described
`here <https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769>`__.

Changing a Certificate's Domains
--------------------------------

The ``--cert-name`` flag can also be used to modify the domains a certificate contains,
by specifying new domains using the ``-d`` or ``--domains`` flag. If certificate ``example.com``
previously contained ``example.com`` and ``www.example.com``, it can be modified to only
contain ``example.com`` by specifying only ``example.com`` with the ``-d`` or ``--domains`` flag. Example::

  certbot certonly --cert-name example.com -d example.com

The same format can be used to expand the set of domains a certificate contains, or to
replace that set entirely::

  certbot certonly --cert-name example.com -d example.org,www.example.org


Revoking certificates
---------------------

If your account key has been compromised or you otherwise need to revoke a certificate,
use the ``revoke`` command to do so. Note that the ``revoke`` command takes the certificate path
(ending in ``cert.pem``), not a certificate name or domain. Example::

  certbot revoke --cert-path /etc/letsencrypt/live/CERTNAME/cert.pem

Additionally, if a certificate
is a test cert obtained via the ``--staging`` or ``--test-cert`` flag, that flag must be passed to the
``revoke`` subcommand.
Once a certificate is revoked (or for other cert management tasks), all of a certificate's
relevant files can be removed from the system with the ``delete`` subcommand::

  certbot delete --cert-name example.com

.. note:: If you don't use ``delete`` to remove the certificate completely, it will be renewed automatically at the next renewal event.

.. _renewal:

Renewing certificates
---------------------

.. note:: Let's Encrypt CA issues short-lived certificates (90
   days). Make sure you renew the certificates at least once in 3
   months.

As of version 0.10.0, Certbot supports a ``renew`` action to check
all installed certificates for impending expiry and attempt to renew
them. The simplest form is simply

``certbot renew``

This command attempts to renew any previously-obtained certificates that
expire in less than 30 days. The same plugin and options that were used
at the time the certificate was originally issued will be used for the
renewal attempt, unless you specify other plugins or options. Unlike ``certonly``, ``renew`` acts on
multiple certificates and always takes into account whether each one is near
expiry. Because of this, ``renew`` is suitable (and designed) for automated use,
to allow your system to automatically renew each certificate when appropriate.
Since ``renew`` only renews certificates that are near expiry it can be
run as frequently as you want - since it will usually take no action.

The ``renew`` command includes hooks for running commands or scripts before or after a certificate is
renewed. For example, if you have a single cert obtained using
the standalone_ plugin, you might need to stop the webserver
before renewing so standalone can bind to the necessary ports, and
then restart it after the plugin is finished. Example::

  certbot renew --pre-hook "service nginx stop" --post-hook "service nginx start"

If a hook exits with a non-zero exit code, the error will be printed
to ``stderr`` but renewal will be attempted anyway. A failing hook
doesn't directly cause Certbot to exit with a non-zero exit code, but
since Certbot exits with a non-zero exit code when renewals fail, a
failed hook causing renewal failures will indirectly result in a
non-zero exit code. Hooks will only be run if a certificate is due for
renewal, so you can run the above command frequently without
unnecessarily stopping your webserver.

``--pre-hook`` and ``--post-hook`` hooks run before and after every renewal
attempt. If you want your hook to run only after a successful renewal, use
``--renew-hook`` in a command like this.

``certbot renew --renew-hook /path/to/renew-hook-script``

For example, if you have a daemon that does not read its certificates as the
root user, a renew hook like this can copy them to the correct location and
apply appropriate file permissions.

/path/to/renew-hook-script

.. code-block:: none

   #!/bin/sh

   set -e

   for domain in $RENEWED_DOMAINS; do
           case $domain in
           example.com)
                   daemon_cert_root=/etc/some-daemon/certs

                   # Make sure the certificate and private key files are
                   # never world readable, even just for an instant while
                   # we're copying them into daemon_cert_root.
                   umask 077

                   cp "$RENEWED_LINEAGE/fullchain.pem" "$daemon_cert_root/$domain.cert"
                   cp "$RENEWED_LINEAGE/privkey.pem" "$daemon_cert_root/$domain.key"

                   # Apply the proper file ownership and permissions for
                   # the daemon to read its certificate and key.
                   chown some-daemon "$daemon_cert_root/$domain.cert" \
                           "$daemon_cert_root/$domain.key"
                   chmod 400 "$daemon_cert_root/$domain.cert" \
                           "$daemon_cert_root/$domain.key"

                   service some-daemon restart >/dev/null
                   ;;
           esac
   done

 More information about renewal hooks can be found by running
``certbot --help renew``.

If you're sure that this command executes successfully without human
intervention, you can add the command to ``crontab`` (since certificates
are only renewed when they're determined to be near expiry, the command
can run on a regular basis, like every week or every day). In that case,
you are likely to want to use the ``-q`` or ``--quiet`` quiet flag to
silence all output except errors.

If you are manually renewing all of your certificates, the
``--force-renewal`` flag may be helpful; it causes the expiration time of
the certificate(s) to be ignored when considering renewal, and attempts to
renew each and every installed certificate regardless of its age. (This
form is not appropriate to run daily because each certificate will be
renewed every day, which will quickly run into the certificate authority
rate limit.)

Note that options provided to ``certbot renew`` will apply to
*every* certificate for which renewal is attempted; for example,
``certbot renew --rsa-key-size 4096`` would try to replace every
near-expiry certificate with an equivalent certificate using a 4096-bit
RSA public key. If a certificate is successfully renewed using
specified options, those options will be saved and used for future
renewals of that certificate.

An alternative form that provides for more fine-grained control over the
renewal process (while renewing specified certificates one at a time),
is ``certbot certonly`` with the complete set of subject domains of
a specific certificate specified via `-d` flags. You may also want to
include the ``-n`` or ``--noninteractive`` flag to prevent blocking on
user input (which is useful when running the command from cron).

``certbot certonly -n -d example.com -d www.example.com``

All of the domains covered by the certificate must be specified in
this case in order to renew and replace the old certificate rather
than obtaining a new one; don't forget any `www.` domains! Specifying
a subset of the domains creates a new, separate certificate containing
only those domains, rather than replacing the original certificate.
When run with a set of domains corresponding to an existing certificate,
the ``certonly`` command attempts to renew that specific certificate.

Please note that the CA will send notification emails to the address
you provide if you do not renew certificates that are about to expire.

Certbot is working hard to improve the renewal process, and we
apologize for any inconvenience you encounter in integrating these
commands into your individual environment.

.. note:: ``certbot renew`` exit status will only be 1 if a renewal attempt failed.
  This means ``certbot renew`` exit status will be 0 if no cert needs to be updated.
  If you write a custom script and expect to run a command only after a cert was actually renewed
  you will need to use the ``--post-hook`` since the exit status will be 0 both on successful renewal
  and when renewal is not necessary.


Modifying the Renewal Configuration File
----------------------------------------

For advanced certificate management tasks, it is possible to manually modify the certificate's
renewal configuration file, located at ``/etc/letsencrypt/renewal/CERTNAME``.

.. warning:: Modifying any files in ``/etc/letsencrypt`` can damage them so Certbot can no longer properly manage its certificates, and we do not recommend doing so.

For most tasks, it is safest to limit yourself to pointing symlinks at the files there, or using
``--renew-hook`` to copy / make new files based upon those files, if your operational situation requires it
(for instance, combining certs and keys in different way, or having copies of things with different
specific permissions that are demanded by other programs).

If the contents of ``/etc/letsencrypt/archive/CERTNAME`` are moved to a new folder, first specify
the new folder's name in the renewal configuration file, then run ``certbot update_symlinks`` to
point the symlinks in ``/etc/letsencrypt/live/CERTNAME`` to the new folder.

If you would like the live certificate files whose symlink location Certbot updates on each run to
reside in a different location, first move them to that location, then specify the full path of
each of the four files in the renewal configuration file. Since the symlinks are relative links,
you must follow this with an invocation of ``certbot update_symlinks``.

For example, say that a certificate's renewal configuration file previously contained the following
directives::

  archive_dir = /etc/letsencrypt/archive/example.com
  cert = /etc/letsencrypt/live/example.com/cert.pem
  privkey = /etc/letsencrypt/live/example.com/privkey.pem
  chain = /etc/letsencrypt/live/example.com/chain.pem
  fullchain = /etc/letsencrypt/live/example.com/fullchain.pem

The following commands could be used to specify where these files are located::

  mv /etc/letsencrypt/archive/example.com /home/user/me/certbot/example_archive
  sed -i 's,/etc/letsencrypt/archive/example.com,/home/user/me/certbot/example_archive,' /etc/letsencrypt/renewal/example.com.conf
  mv /etc/letsencrypt/live/example.com/*.pem /home/user/me/certbot/
  sed -i 's,/etc/letsencrypt/live/example.com,/home/user/me/certbot,g' /etc/letsencrypt/renewal/example.com.conf
  certbot update_symlinks


.. _where-certs:

Where are my certificates?
==========================

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
     it with anyone, including Certbot developers. You cannot
     put it into a safe, however - your server still needs to access
     this file in order for SSL/TLS to work.

  This is what Apache needs for `SSLCertificateKeyFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatekeyfile>`_,
  and Nginx for `ssl_certificate_key
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key>`_.

``fullchain.pem``
  All certificates, **including** server certificate (aka leaf certificate or
  end-entity certificate). The server certificate is the first one in this file,
  followed by any intermediates.

  This is what Apache >= 2.4.8 needs for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_,
  and what Nginx needs for `ssl_certificate
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate>`_.

``cert.pem`` and ``chain.pem`` (less common)
  ``cert.pem`` contains the server certificate by itself, and
  ``chain.pem`` contains the additional intermediate certificate or
  certificates that web browsers will need in order to validate the
  server certificate. If you provide one of these files to your web
  server, you **must** provide both of them, or some browsers will show
  "This Connection is Untrusted" errors for your site, `some of the time
  <https://whatsmychaincert.com/>`_.

  Apache < 2.4.8 needs these for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_.
  and `SSLCertificateChainFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatechainfile>`_,
  respectively.

  If you're using OCSP stapling with Nginx >= 1.3.7, ``chain.pem`` should be
  provided as the `ssl_trusted_certificate
  <http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_trusted_certificate>`_
  to validate OCSP responses.

.. note:: All files are PEM-encoded.
   If you need other format, such as DER or PFX, then you
   could convert using ``openssl``. You can automate that with
   ``--renew-hook`` if you're using automatic renewal_.

.. _hooks:

Pre and Post Validation Hooks
=============================

Certbot allows for the specification of pre and post validation hooks when run
in manual mode. The flags to specify these scripts are ``--manual-auth-hook``
and ``--manual-cleanup-hook`` respectively and can be used as follows:

::

 certbot certonly --manual --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

This will run the ``authenticator.sh`` script, attempt the validation, and then run
the ``cleanup.sh`` script. Additionally certbot will pass three environment
variables to these scripts:

- ``CERTBOT_DOMAIN``: The domain being authenticated
- ``CERTBOT_VALIDATION``: The validation string
- ``CERTBOT_TOKEN``: Resource name part of the HTTP-01 challenge (HTTP-01 only)

Additionally for cleanup:

- ``CERTBOT_AUTH_OUTPUT``: Whatever the auth script wrote to stdout

Example usage for HTTP-01:

::

 certbot certonly --manual --preferred-challenges=http --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

/path/to/http/authenticator.sh

.. code-block:: none

   #!/bin/bash
   echo $CERTBOT_VALIDATION > /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

/path/to/http/cleanup.sh

.. code-block:: none

   #!/bin/bash
   rm -f /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

Example usage for DNS-01 (Cloudflare API v4) (for example purposes only, do not use as-is)

::

 certbot certonly --manual --preferred-challenges=dns --manual-auth-hook /path/to/dns/authenticator.sh --manual-cleanup-hook /path/to/dns/cleanup.sh -d secure.example.com

/path/to/dns/authenticator.sh

.. code-block:: none

   #!/bin/bash

   # Get your API key from https://www.cloudflare.com/a/account/my-account
   API_KEY="your-api-key"
   EMAIL="your.email@example.com"

   # Strip only the top domain to get the zone id
   DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')

   # Get the Cloudflare zone id
   ZONE_EXTRA_PARAMS="status=active&page=1&per_page=20&order=status&direction=desc&match=all"
   ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&$ZONE_EXTRA_PARAMS" \
        -H     "X-Auth-Email: $EMAIL" \
        -H     "X-Auth-Key: $API_KEY" \
        -H     "Content-Type: application/json" | python -c "import sys,json;print(json.load(sys.stdin)['result'][0]['id'])")

   # Create TXT record
   CREATE_DOMAIN="_acme-challenge.$CERTBOT_DOMAIN"
   RECORD_ID=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H     "X-Auth-Email: $EMAIL" \
        -H     "X-Auth-Key: $API_KEY" \
        -H     "Content-Type: application/json" \
        --data '{"type":"TXT","name":"'"$CREATE_DOMAIN"'","content":"'"$CERTBOT_VALIDATION"'","ttl":120}' \
                | python -c "import sys,json;print(json.load(sys.stdin)['result']['id'])")
   # Save info for cleanup
   if [ ! -d /tmp/CERTBOT_$CERTBOT_DOMAIN ];then
           mkdir -m 0700 /tmp/CERTBOT_$CERTBOT_DOMAIN
   fi
   echo $ZONE_ID > /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID
   echo $RECORD_ID > /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID

   # Sleep to make sure the change has time to propagate over to DNS
   sleep 25

/path/to/dns/cleanup.sh

.. code-block:: none

   #!/bin/bash

   # Get your API key from https://www.cloudflare.com/a/account/my-account
   API_KEY="your-api-key"
   EMAIL="your.email@example.com"

   if [ -f /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID ]; then
           ZONE_ID=$(cat /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID)
           rm -f /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID
   fi

   if [ -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID ]; then
           RECORD_ID=$(cat /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID)
           rm -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID
   fi

   # Remove the challenge TXT record from the zone
   if [ -n "${ZONE_ID}" ]; then
       if [ -n "${RECORD_ID}" ]; then
           curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                   -H "X-Auth-Email: $EMAIL" \
                   -H "X-Auth-Key: $API_KEY" \
                   -H "Content-Type: application/json"
       fi
   fi



.. _config-file:

Configuration file
==================

It is possible to specify configuration file with
``certbot-auto --config cli.ini`` (or shorter ``-c cli.ini``). An
example configuration file is shown below:

.. include:: ../examples/cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

.. keep it up to date with constants.py

.. _command-line:

Certbot command-line options
============================

Certbot supports a lot of command line options.  Here's the full list, from
``certbot --help all``:

.. literalinclude:: cli-help.txt

Getting help
============

If you're having problems, we recommend posting on the Let's Encrypt
`Community Forum <https://community.letsencrypt.org>`_.

You can also chat with us on IRC: `(#certbot @
OFTC) <https://webchat.oftc.net?channels=%23certbot>`_ or
`(#letsencrypt @ freenode) <https://webchat.freenode.net?channels=%23letsencrypt>`_.

If you find a bug in the software, please do report it in our `issue
tracker <https://github.com/certbot/certbot/issues>`_. Remember to
give us as much information as possible:

- copy and paste exact command line used and the output (though mind
  that the latter might include some personally identifiable
  information, including your email and domains)
- copy and paste logs from ``/var/log/letsencrypt`` (though mind they
  also might contain personally identifiable information)
- copy and paste ``certbot --version`` output
- your operating system, including specific version
- specify which installation method you've chosen
