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
credentials.

There are three ways to accomplish this. Using the `easy setup`_ or `advanced setup`_ is
recommended, however requires at least version 2.3.1 of the ``cloudflare`` python module.
If the version that automatically installed with this plugin is older than that,
and you can't upgrade it on your system, you'll have to stick to the `legacy setup`_.

The path to the configuration file can be provided interactively or using the
``--dns-cloudflare-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Cloudflare account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the configuration file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the file.
This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Easy setup
^^^^^^^^^^

Create a Token in your `Cloudflare dashboard <https://dash.cloudflare.com/profile/api-tokens>`_
with ``Zone:Zone:Read`` and ``Zone:DNS:Edit`` permissions for **all** zones in your account.
If you wish to restrict token access on a per-zone level, follow the `advanced setup`_.

Copy and save the token in a file like so:

.. code-block:: ini
   :name: certbot_cloudflare_token.ini
   :caption: Example credentials file using API Token:

   # Cloudflare API token used by Certbot
   dns_cloudflare_api_token = 0123456789abcdef0123456789abcdef01234567


Advanced setup
^^^^^^^^^^^^^^

Create a Token in your `Cloudflare dashboard <https://dash.cloudflare.com/profile/api-tokens>`_
with ``Zone:DNS:Edit`` permissions for the specific zones for which you need certificates.

You will also need to add the Zone ID for each zone(from the bottom right of each zone page in
your dashboard) to the configuration file like so:

.. code-block:: ini
   :name: certbot_cloudflare_credentials.ini
   :caption: Example credentials file using API Token with Zone IDs:

   # Cloudflare API token used by Certbot
   dns_cloudflare_api_token = 0123456789abcdef0123456789abcdef01234567

   [dns_cloudflare_zone_ids]
   example.com = 0123456789abcdef0123456789abcdef
   example.org = 0123456789abcdef0123456789abcdef


Legacy setup
^^^^^^^^^^^^

A Global Key was previously used by Cloudflare for authentication, however this key can access
the entire Cloudflare API for all domains in your account, meaning it could cause a lot of
damage if leaked. **If possible, you should use a Cloudflare Token.**

Copy your Global Key from your `Cloudflare dashboard <https://dash.cloudflare.com/profile/api-tokens>`_
and save it with your Cloudflare account's email address in the configuration file:

.. code-block:: ini
   :name: certbot_cloudflare_key.ini
   :caption: Example credentials file using Global API Key:

   # Cloudflare API credentials used by Certbot
   dns_cloudflare_email = cloudflare@example.com
   dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234


Usage
-----

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
