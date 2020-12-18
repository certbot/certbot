"""
The `~certbot_dns_dnsmadeeasy.dns_dnsmadeeasy` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the DNS Made Easy API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

=========================================  =====================================
``--dns-dnsmadeeasy-credentials``          DNS Made Easy credentials_ INI file.
                                           (Required)
``--dns-dnsmadeeasy-propagation-seconds``  The number of seconds to wait for DNS
                                           to propagate before asking the ACME
                                           server to verify the DNS record.
                                           (Default: 60)
=========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing DNS Made Easy API
credentials, obtained from your DNS Made Easy
`account page <https://cp.dnsmadeeasy.com/account/info>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # DNS Made Easy API credentials used by Certbot
   dns_dnsmadeeasy_api_key = 1c1a3c91-4770-4ce7-96f4-54c0eb0e457a
   dns_dnsmadeeasy_secret_key = c9b5625f-9834-4ff8-baba-4ed5f32cae55

The path to this file can be provided interactively or using the
``--dns-dnsmadeeasy-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   DNS Made Easy account. Users who can read this file can use these credentials
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
     --dns-dnsmadeeasy \\
     --dns-dnsmadeeasy-credentials ~/.secrets/certbot/dnsmadeeasy.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-dnsmadeeasy \\
     --dns-dnsmadeeasy-credentials ~/.secrets/certbot/dnsmadeeasy.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 2 minutes
             for DNS propagation

   certbot certonly \\
     --dns-dnsmadeeasy \\
     --dns-dnsmadeeasy-credentials ~/.secrets/certbot/dnsmadeeasy.ini \\
     --dns-dnsmadeeasy-propagation-seconds 120 \\
     -d example.com

"""
