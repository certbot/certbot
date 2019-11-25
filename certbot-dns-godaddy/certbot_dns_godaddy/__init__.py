"""
The `~certbot_dns_godaddy.dns_godaddy` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Godaddy API.
NOTE: This plugin has a race condition if more than one client (api or otherwise)
tries to update DNS records at the same time. This is because the Godaddy API
does not allow individual addressing of DNS records.


Named Arguments
---------------

==========================================  ===================================
``--dns-godaddy-credentials``                Godaddy credentials_ INI file.
                                            (Required)
``--dns-godaddy-propagation-seconds``        The number of seconds to wait for
                                            DNS to propagate before asking the
                                            ACME server to verify the DNS
                                            record.
                                            (Default: 120)
==========================================  ===================================


Credentials
-----------

Use of this plugin requires a configuration file containing Godaddy API
credentials, obtained from your Godaddy account's `Developer
page <https://developer.godaddy.com/keys>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Godaddy API credentials used by Certbot
   dns_godaddy_key = 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
   dns_godaddy_secret = 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

The path to this file can be provided interactively or using the
``--dns-godaddy-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Godaddy account. Users who can read this file can use these credentials
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
     --dns-godaddy \\
     --dns-godaddy-credentials ~/.secrets/certbot/godaddy.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-godaddy \\
     --dns-godaddy-credentials ~/.secrets/certbot/godaddy.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 1000 seconds
             for DNS propagation (Godaddy updates its first DNS every 15 minutes
             and we allow some extra time for the update to reach the other 5
             servers)

   certbot certonly \\
     --dns-godaddy \\
     --dns-godaddy-credentials ~/.secrets/certbot/godaddy.ini \\
     --dns-godaddy-propagation-seconds 1000 \\
     -d example.com

"""
