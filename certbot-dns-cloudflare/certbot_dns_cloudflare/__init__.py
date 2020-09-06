"""
The `~certbot_dns_cloudflare.dns_cloudflare` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Cloudflare API.


Named Arguments
---------------

========================================  =====================================
``--dns-cloudflare-credentials``          Cloudflare credentials_ INI file.
                                          (Required)
``--dns-cloudflare-propagation-seconds``  The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 10)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing Cloudflare API
credentials, obtained from your
`Cloudflare dashboard <https://dash.cloudflare.com/?to=/:account/profile/api-tokens>`_.

Previously, Cloudflare's "Global API Key" was used for authentication, however
this key can access the entire Cloudflare API for all domains in your account,
meaning it could cause a lot of damage if leaked.

Cloudflare's newer API Tokens can be restricted to specific domains and
operations, and are therefore now the recommended authentication option.

The Token needed by Certbot requires ``Zone:DNS:Edit`` permissions for only the
zones you need certificates for.

Using Cloudflare Tokens also requires at least version 2.3.1 of the ``cloudflare``
python module. If the version that automatically installed with this plugin is
older than that, and you can't upgrade it on your system, you'll have to stick to
the Global key.

.. code-block:: ini
   :name: certbot_cloudflare_token.ini
   :caption: Example credentials file using restricted API Token (recommended):

   # Cloudflare API token used by Certbot
   dns_cloudflare_api_token = 0123456789abcdef0123456789abcdef01234567

.. code-block:: ini
   :name: certbot_cloudflare_key.ini
   :caption: Example credentials file using Global API Key (not recommended):

   # Cloudflare API credentials used by Certbot
   dns_cloudflare_email = cloudflare@example.com
   dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234

The path to this file can be provided interactively or using the
``--dns-cloudflare-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Cloudflare account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-cloudflare \\
     --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-cloudflare \\
     --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-cloudflare \\
     --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \\
     --dns-cloudflare-propagation-seconds 60 \\
     -d example.com

"""
