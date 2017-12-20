Working with Certificates
=========================

.. contents:: Table of Contents
   :local:

Before You Begin
================

The ``certbot`` script on your web server might be named ``letsencrypt`` if your system uses an older package, or ``certbot-auto`` if you used an alternate installation method. Throughout the docs, whenever you see ``certbot``, swap in the correct name as needed.


* Figure out which plugin to use
* Use the plugin to get the certificate



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

.. _updating_certs:

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
new domains. With the ``--expand`` option, use the ``-d`` option to specify
all existing domains and one or more new domains.

Example:

.. code-block:: none

  certbot --expand -d existing.com,example.com,newdomain.com

If you prefer, you can specify the domains individually like this:

.. code-block:: none

  certbot --expand -d existing.com -d example.com -d newdomain.com

Consider using ``--cert-name`` instead of ``--expand``, as it gives more control
over which certificate is modified and it lets you remove domains as well as adding them.


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

.. _changing:

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

You can also specify the reason for revoking your certificate by using the ``reason`` flag.
Reasons include ``unspecified`` which is the default, as well as ``keycompromise``,
``affiliationchanged``, ``superseded``, and ``cessationofoperation``::

  certbot revoke --cert-path /etc/letsencrypt/live/CERTNAME/cert.pem --reason keycompromise

Additionally, if a certificate
is a test certificate obtained via the ``--staging`` or ``--test-cert`` flag, that flag must be passed to the
``revoke`` subcommand.
Once a certificate is revoked (or for other certificate management tasks), all of a certificate's
relevant files can be removed from the system with the ``delete`` subcommand::

  certbot delete --cert-name example.com

.. note:: If you don't use ``delete`` to remove the certificate completely, it will be renewed automatically at the next renewal event.

.. note:: Revoking a certificate will have no effect on the rate limit imposed by the Let's Encrypt server.

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
renewed. For example, if you have a single certificate obtained using
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
``--deploy-hook`` in a command like this.

``certbot renew --deploy-hook /path/to/deploy-hook-script``

For example, if you have a daemon that does not read its certificates as the
root user, a deploy hook like this can copy them to the correct location and
apply appropriate file permissions.

/path/to/deploy-hook-script

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

You can also specify hooks by placing files in subdirectories of Certbot's
configuration directory. Assuming your configuration directory is
``/etc/letsencrypt``, any executable files found in
``/etc/letsencrypt/renewal-hooks/pre``,
``/etc/letsencrypt/renewal-hooks/deploy``, and
``/etc/letsencrypt/renewal-hooks/post`` will be run as pre, deploy, and post
hooks respectively when any certificate is renewed with the ``renew``
subcommand. These hooks are run in alphabetical order and are not run for other
subcommands. (The order the hooks are run is determined by the byte value of
the characters in their filenames and is not dependent on your locale.)

Hooks specified in the command line, :ref:`configuration file
<config-file>`, or :ref:`renewal configuration files <renewal-config-file>` are
run as usual after running all hooks in these directories. One minor exception
to this is if a hook specified elsewhere is simply the path to an executable
file in the hook directory of the same type (e.g. your pre-hook is the path to
an executable in ``/etc/letsencrypt/renewal-hooks/pre``), the file is not run a
second time. You can stop Certbot from automatically running executables found
in these directories by including ``--no-directory-hooks`` on the command line.

More information about hooks can be found by running
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
   ``--deploy-hook`` if you're using automatic renewal_.


