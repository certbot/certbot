"""
The `~certbot_dns_luadns.dns_luadns` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the LuaDNS API.


Named Arguments
---------------

=========================================  =====================================
``--dns-luadns-credentials``               LuaDNS credentials_ INI file.
                                           (Required)
``--dns-luadns-propagation-seconds``       The number of seconds to wait for DNS
                                           to propagate before asking the ACME
                                           server to verify the DNS record.
                                           (Default: 30)
=========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing LuaDNS API
credentials, obtained from your LuaDNS
`account settings page <https://api.luadns.com/settings>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # LuaDNS API credentials used by Certbot
   dns_luadns_email = user@example.com
   dns_luadns_token = 0123456789abcdef0123456789abcdef

The path to this file can be provided interactively or using the
``--dns-luadns-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   LuaDNS account. Users who can read this file can use these credentials
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
     --dns-luadns \\
     --dns-luadns-credentials ~/.secrets/certbot/luadns.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-luadns \\
     --dns-luadns-credentials ~/.secrets/certbot/luadns.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 2 minutes
             for DNS propagation

   certbot certonly \\
     --dns-luadns \\
     --dns-luadns-credentials ~/.secrets/certbot/luadns.ini \\
     --dns-luadns-propagation-seconds 120 \\
     -d example.com

"""
