=====================
How it Works
=====================

This new section will cover general info about how the following things work. 
This is not a how-to, just a way of connecting the dots so that when people 
are doing these tasks later, it all makes sense.

XXX Description of the order of events. That is... you pick your webserver and OS on the interactive installation tool. Behind the scenes, certbot knows how to modify the config file and handle the challenge. You can optionally do hooks. You get authenticated and the cert gets installed. A config file gets created so that automatic renewal can happen. After that, you can manage, modify, or delete certs.


.. include:: challenges.rst


.. _plugins:


Plugins
=======

The Certbot client supports two types of plugins for
obtaining and installing certificates: authenticators and installers.

Authenticators are plugins used with the ``certonly`` command to obtain a certificate.
The authenticator satisfies a challenge to validate that you
control the domain(s) you are requesting a certificate for, obtains a certificate for the specified
domain(s), and places the certificate in the ``/etc/letsencrypt`` directory on your
machine. The authenticator does not install the certificate (it does not edit any of your server's configuration files to serve the
obtained certificate). If you specify multiple domains to authenticate, they will
all be listed in a single certificate. To obtain multiple separate certificates
you will need to run Certbot multiple times.


Installers are Plugins used with the ``install`` command to install a certificate.
These plugins can modify your webserver's configuration to
serve your website over HTTPS using certificates obtained by certbot.

Plugins that do both can be used with the ``certbot run`` command, which is the default
when no command is specified. The ``run`` subcommand can also be used to specify
a combination_ of distinct authenticator and installer plugins.

=========== ==== ==== =============================================================== =============================
Plugin      Auth Inst Notes                                                           Challenge types (and port)
=========== ==== ==== =============================================================== =============================
apache     Y    Y    | Automates obtaining and installing a certificate with Apache  :ref:`TLS-SNI-01 <tls_sni_01_challenge>` (443)
                      | 2.4 on Debian-based distributions with ``libaugeas0`` 1.0+.
webroot    Y    N    | Obtains a certificate by writing to the webroot directory of  :ref:`HTTP-01 <http_01_challenge>` (80)
                      | an already running webserver.
nginx      Y    Y    | Automates obtaining and installing a certificate with Nginx.  :ref:`TLS-SNI-01 <tls_sni_01_challenge>` (443)
                      | Shipped with Certbot 0.9.0.
standalone Y    N    | Uses a "standalone" webserver to obtain a certificate.        :ref:`HTTP-01 <http_01_challenge>` (80) or
                      | Requires port 80 or 443 to be available. This is useful on    :ref:`TLS-SNI-01 <tls_sni_01_challenge>` (443)
                      | systems with no webserver, or when direct integration with
                      | the local webserver is not supported or not desired.
manual     Y    N    | Helps you obtain a certificate by giving you instructions to  :ref:`HTTP-01 <http_01_challenge>` (80),
                      | perform domain validation yourself. Additionally allows you   :ref:`DNS-01 <dns_01_challenge>` (53) or
                      | to specify scripts to automate the validation task in a       :ref:`TLS-SNI-01 <tls_sni_01_challenge>` (443)
                      | customized way.
=========== ==== ==== =============================================================== =============================

A few
plugins support more than one challenge type, in which case you can choose one
with ``--preferred-challenges``.

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
varnish_    Y    N    Obtain certificates via a Varnish server
external_   Y    N    A plugin for convenient scripting (See also ticket 2782_)
icecast_    N    Y    Deploy certificates to Icecast 2 streaming media servers
pritunl_    N    Y    Install certificates in pritunl distributed OpenVPN servers
proxmox_    N    Y    Install certificates in Proxmox Virtualization servers
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


.. _lock-files:

Lock Files
==========

When processing a validation Certbot writes a number of lock files on your system
to prevent multiple instances from overwriting each other's changes. This means
that be default two instances of Certbot will not be able to run in parallel.

Since the directories used by Certbot are configurable, Certbot
will write a lock file for all of the directories it uses. This include Certbot's
``--work-dir``, ``--logs-dir``, and ``--config-dir``. By default these are
``/var/lib/letsencrypt``, ``/var/logs/letsencrypt``, and ``/etc/letsencrypt``
respectively. Additionally if you are using Certbot with Apache or nginx it will
lock the configuration folder for that program, which are typically also in the
``/etc`` directory.

Note that these lock files will only prevent other instances of Certbot from
using those directories, not other processes. If you'd like to run multiple
instances of Certbot simultaneously you should specify different directories
as the ``--work-dir``, ``--logs-dir``, and ``--config-dir`` for each instance
of Certbot that you would like to run.



.. _hooks:

Pre and Post Validation Hooks
=============================

Certbot allows for the specification of pre and post validation hooks when run
in manual mode. The flags to specify these scripts are ``--manual-auth-hook``
and ``--manual-cleanup-hook`` respectively and can be used as follows::

  certbot certonly --manual --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

This will run the ``authenticator.sh`` script, attempt the validation, and then run
the ``cleanup.sh`` script. Additionally certbot will pass relevant environment
variables to these scripts:

- ``CERTBOT_DOMAIN``: The domain being authenticated
- ``CERTBOT_VALIDATION``: The validation string (HTTP-01 and DNS-01 only)
- ``CERTBOT_TOKEN``: Resource name part of the HTTP-01 challenge (HTTP-01 only)
- ``CERTBOT_CERT_PATH``: The challenge SSL certificate (TLS-SNI-01 only)
- ``CERTBOT_KEY_PATH``: The private key associated with the aforementioned SSL certificate (TLS-SNI-01 only)
- ``CERTBOT_SNI_DOMAIN``: The SNI name for which the ACME server expects to be presented the self-signed certificate located at ``$CERTBOT_CERT_PATH`` (TLS-SNI-01 only)

Additionally for cleanup:

- ``CERTBOT_AUTH_OUTPUT``: Whatever the auth script wrote to stdout

Example usage for HTTP-01::

  certbot certonly --manual --preferred-challenges=http --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

/path/to/http/authenticator.sh

.. code-block:: none

   #!/bin/bash
   echo $CERTBOT_VALIDATION > /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

/path/to/http/cleanup.sh

.. code-block:: none

   #!/bin/bash
   rm -f /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

Example usage for DNS-01 (Cloudflare API v4) (for example purposes only, do not use as-is)::

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



