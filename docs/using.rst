==========
User Guide
==========

.. contents:: Table of Contents
   :local:

Certbot Commands
================

Certbot uses a number of different "commands" (also referred
to, equivalently, as "subcommands") to request specific actions such as
obtaining, renewing, or revoking certificates. Some of the most important
and most commonly-used commands will be discussed throughout this
document; an exhaustive list also appears near the end of the document.

The ``certbot`` script on your web server might be named ``letsencrypt`` if your system uses an older package, or ``certbot-auto`` if you used an alternate installation method. Throughout the docs, whenever you see ``certbot``, swap in the correct name as needed.

.. _plugins:

Getting certificates (and choosing plugins)
===========================================

The Certbot client supports a number of different "plugins" that can be
used to obtain and/or install certificates.

Plugins that can obtain a cert are called "authenticators" and can be used with
the "certonly" command. This will carry out the steps needed to validate that you
control the domain(s) you are requesting a cert for, obtain a cert for the specified
domain(s), and place it in the ``/etc/letsencrypt`` directory on your
machine - without editing any of your server's configuration files to serve the
obtained certificate. If you specify multiple domains to authenticate, they will
all be listed in a single certificate. To obtain multiple seperate certificates
you will need to run Certbot multiple times.

Plugins that can install a cert are called "installers" and can be used with the
"install" command.  These plugins can modify your webserver's configuration to
serve your website over HTTPS using certificates obtained by certbot.

Plugins that do both can be used with the "certbot run" command, which is the default
when no command is specified. The "run" subcommand can also be used to specify
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

Under the hood, plugins use one of several ACME protocol "Challenges_" to
prove you control a domain.  The options are http-01_ (which uses port 80),
tls-sni-01_ (port 443) and dns-01_ (requring configuration of a DNS server on
port 53, though that's often not the same machine as your webserver). A few
plugins support more than one challenge type, in which case you can choose one
with ``--preferred-challenges``.

There are also many third-party-plugins_ available. Below we describe in more detail
the circumstances in which each plugin can be used, and how to use it.

.. _Challenges: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7
.. _tls-sni-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.3
.. _http-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.2
.. _dns-01: https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.4

Apache
------

The Apache plugin currently requires OS with augeas version 1.0; currently `it
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

If you'd like to obtain a cert running ``certbot`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a cert by specifying
``certonly`` and ``--manual`` on the command line. This requires you
to copy and paste commands into another terminal session, which may
be on a different computer.

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

If you're interested, you can also :ref:`write your own plugin <dev-plugin>`.

Re-running Certbot
==================

Running Certbot with the ``certonly`` or ``run`` commands always requests
the creation of a single new certificate, even if you already have an
existing certificate with some of the same domain names. The ``--force-renewal``,
``--duplicate``, and ``--expand`` options control Certbot's behavior in this case.
If you don't specify a requested behavior, Certbot may ask you what you intended.

``--force-renewal`` tells Certbot to request a new certificate
with the same domains as an existing certificate. (Each and every domain
must be explicitly specified via ``-d``.) If successful, this certificate
will be saved alongside the earlier one and symbolic links (the "``live``"
reference) will be updated to point to the new certificate. This is a
valid method of explicitly requesting the renewal of a specific individual
certificate.

``--duplicate`` tells Certbot to create a separate, unrelated certificate
with the same domains as an existing certificate. This certificate will
be saved completely separately from the prior one. Most users probably
do not want this behavior.

``--expand`` tells Certbot to update an existing certificate with a new
certificate that contains all of the old domains and one or more additional
new domains.

``--allow-subset-of-names`` tells Certbot to continue with cert generation if
only some of the specified domain authorizations can be obtained. This may
be useful if some domains specified in a certificate no longer point at this
system.

Whenever you obtain a new certificate in any of these ways, the new
certificate exists alongside any previously-obtained certificates, whether
or not the previous certificates have expired. The generation of a new
certificate counts against several rate limits that are intended to prevent
abuse of the ACME protocol, as described
`here <https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769>`__.

Certbot also provides a ``renew`` command. This command examines *all* existing
certificates to determine whether or not each is near expiry. For any existing
certificate that is near expiry, ``certbot renew`` will attempt to obtain a
new certificate for the same domains. Unlike ``certonly``, ``renew`` acts on
multiple certificates and always takes into account whether each one is near
expiry. Because of this, ``renew`` is suitable (and designed) for automated use,
to allow your system to automatically renew each certificate when appropriate.
Since ``renew`` will only renew certificates that are near expiry it can be
run as frequently as you want - since it will usually take no action.

Typically, ``certbot renew`` runs a reduced risk of rate-limit problems
because it renews certificates only when necessary, and because some of
the Let's Encrypt CA's rate limit policies treat the issuance of a new
certificate under these circumstances more generously. More details about
the use of ``certbot renew`` are provided below.

.. _renewal:

Renewing certificates
=====================

.. note:: Let's Encrypt CA issues short-lived certificates (90
   days). Make sure you renew the certificates at least once in 3
   months.

The ``certbot`` client now supports a ``renew`` action to check
all installed certificates for impending expiry and attempt to renew
them. The simplest form is simply

``certbot renew``

This will attempt to renew any previously-obtained certificates that
expire in less than 30 days. The same plugin and options that were used
at the time the certificate was originally issued will be used for the
renewal attempt, unless you specify other plugins or options.

You can also specify hooks to be run before or after a certificate is
renewed. For example, if you have only a single cert and you obtained it using
the standalone_ plugin, it will be used by default when renewing. In that case
you may want to use a command like this to renew your certificate.

``certbot renew --pre-hook "service nginx stop" --post-hook "service nginx start"``

This will stop Nginx so standalone can bind to the necessary ports and
then restart Nginx after the plugin is finished. The hooks will only be
run if a certificate is due for renewal, so you can run this command
frequently without unnecessarily stopping your webserver. More
information about renewal hooks can be found by running
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

(All of the domains covered by the certificate must be specified in
this case in order to renew and replace the old certificate rather
than obtaining a new one; don't forget any `www.` domains! Specifying
a subset of the domains creates a new, separate certificate containing
only those domains, rather than replacing the original certificate.)
When run with a set of domains corresponding to an existing certificate,
the ``certonly`` command attempts to renew that one individual certificate.

Please note that the CA will send notification emails to the address
you provide if you do not renew certificates that are about to expire.

Certbot is working hard on improving the renewal process, and we
apologize for any inconveniences you encounter in integrating these
commands into your individual environment.

.. _command-line:

Certbot command-line options
============================

Certbot supports a lot of command line options.  Here's the full list, from
``certbot --help all``:

.. literalinclude:: cli-help.txt

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

Certbot allows for the specification fo pre and post validation hooks when run
in manual mode. The flags to specify these scripts are ``--manual-auth-hook``
and ``--manual-cleanup-hook`` respectively and can be used as such:

::

 certbot certonly --manual --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

This will run the authenticator.sh script, attempt the validation, and then run
the cleanup.sh script. Additionally certbot will pass three environment
variables to these scripts:

- ``CERTBOT_DOMAIN``: The domain being authenticated
- ``CERTBOT_VALIDATION``: The validation string
- ``CERTBOT_TOKEN``: Resource name part of the HTTP-01 challenege (HTTP-01 only)

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

Example usage for DNS-01 (Cloudflare API v4) (for example purposes only, do not use)

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
