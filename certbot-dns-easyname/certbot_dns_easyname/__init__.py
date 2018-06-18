"""
The `~certbot_dns_easyname.dns_easyname` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Easyname API.


Named Arguments
---------------

========================================  =====================================
``--dns-easyname-credentials``            Easyname credentials_ INI file.
                                          (Required)
``--dns-easyname-propagation-seconds``    The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 30)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing Easyname API
credentials, obtained from your Easyname
`account page <https://my.easyname.at/de/account/api>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Easyname API credentials used by Certbot
   dns_easyname_user_id = 123
   dns_easyname_email = easyname@example.com
   dns_easyname_api_key = 0123456789abcdef0123456789abcdef01234567
   dns_easyname_api_auth_salt = 012%s345%s678
   dns_easyname_api_signing_salt = 0123456789abcdef0123456789abcdef01234567

The path to this file can be provided interactively or using the
``--dns-easyname-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Easyname account. Users who can read this file can use these credentials
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
     --dns-easyname \\
     --dns-easyname-credentials ~/.secrets/certbot/easyname.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-easyname \\
     --dns-easyname-credentials ~/.secrets/certbot/easyname.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-easyname \\
     --dns-easyname-credentials ~/.secrets/certbot/easyname.ini \\
     --dns-easyname-propagation-seconds 60 \\
     -d example.com

"""
