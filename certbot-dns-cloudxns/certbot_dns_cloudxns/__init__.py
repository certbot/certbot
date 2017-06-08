"""
The `~certbot_dns_cloudxns.dns_cloudxns` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the CloudXNS API.


Named Arguments
---------------

========================================  =====================================
``--dns-cloudxns-credentials``            CloudXNS credentials_ INI file.
                                          (Required)
``--dns-cloudxns-propagation-seconds``    The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 30)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing CloudXNS API
credentials, obtained from your CloudXNS
`API page <https://www.cloudxns.net/en/AccountManage/apimanage.html>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # CloudXNS API credentials used by Certbot
   dns_cloudxns_api_key = 1234567890abcdef1234567890abcdef
   dns_cloudxns_secret_key = 1122334455667788

The path to this file can be provided interactively or using the
``--dns-cloudxns-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   CloudXNS account. Users who can read this file can use these credentials to
   issue arbitrary API calls on your behalf. Users who can cause Certbot to run
   using these credentials can complete a ``dns-01`` challenge to acquire new
   certificates or revoke existing certificates for associated domains, even if
   those domains aren't being managed by this server.

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
     --dns-cloudxns \\
     --dns-cloudxns-credentials ~/.secrets/certbot/cloudxns.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-cloudxns \\
     --dns-cloudxns-credentials ~/.secrets/certbot/cloudxns.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-cloudxns \\
     --dns-cloudxns-credentials ~/.secrets/certbot/cloudxns.ini \\
     --dns-cloudxns-propagation-seconds 60 \\
     -d example.com

"""
