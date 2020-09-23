"""
The `~certbot_dns_rfc2136.dns_rfc2136` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using RFC 2136 Dynamic Updates.


Named Arguments
---------------

===================================== =====================================
``--dns-rfc2136-credentials``         RFC 2136 credentials_ INI file.
                                      (Required)
``--dns-rfc2136-propagation-seconds`` The number of seconds to wait for DNS
                                      to propagate before asking the ACME
                                      server to verify the DNS record.
                                      (Default: 60)
===================================== =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing the target DNS
server and optional port that supports RFC 2136 Dynamic Updates, the name
of the TSIG key, the TSIG key secret itself and the algorithm used if it's
different to HMAC-MD5.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Target DNS server
   dns_rfc2136_server = 192.0.2.1
   # Target DNS port
   dns_rfc2136_port = 53
   # TSIG key name
   dns_rfc2136_name = keyname.
   # TSIG key secret
   dns_rfc2136_secret = 4q4wM/2I180UXoMyN4INVhJNi8V9BCV+jMw2mXgZw/CSuxUT8C7NKKFs \
AmKd7ak51vWKgSl12ib86oQRPkpDjg==
   # TSIG key algorithm
   dns_rfc2136_algorithm = HMAC-SHA512

The path to this file can be provided interactively or using the
``--dns-rfc2136-credentials`` command-line argument. Certbot records the
path to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect this TSIG key material as it can be used to potentially
   add, update, or delete any record in the target DNS server. Users who can
   read this file can use these credentials to issue arbitrary API calls on
   your behalf. Users who can cause Certbot to run using these credentials can
   complete a ``dns-01`` challenge to acquire new certificates or revoke
   existing certificates for associated domains, even if those domains aren't
   being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

Sample BIND configuration
'''''''''''''''''''''''''

Here's a sample BIND configuration for Certbot to use. You will need to
generate a new TSIG key, include it in the BIND configuration and grant it
permission to issue updates on the target DNS zone.

.. code-block:: bash
   :caption: Generate a new SHA512 TSIG key

   dnssec-keygen -a HMAC-SHA512 -b 512 -n HOST keyname.

.. note::
   There are a few tools shipped with BIND that can all generate TSIG keys;
   ``dnssec-keygen``, ``rndc-confgen``, and ``ddns-confgen``. Try and use the
   most secure algorithm supported by your DNS server.

.. code-block:: none
   :caption: Sample BIND configuration

   key "keyname." {
     algorithm hmac-sha512;
     secret "4q4wM/2I180UXoMyN4INVhJNi8V9BCV+jMw2mXgZw/CSuxUT8C7NKKFs \
AmKd7ak51vWKgSl12ib86oQRPkpDjg==";
   };

   zone "example.com." IN {
     type master;
     file "named.example.com";
     update-policy {
       grant keyname. name _acme-challenge.example.com. txt;
     };
   };

.. note::
   This configuration limits the scope of the TSIG key to just be able to
   add and remove TXT records for one specific host for the purpose of
   completing the ``dns-01`` challenge. If your version of BIND doesn't
   support the ``update-policy`` directive, then you can use the less-secure
   ``allow-update`` directive instead. `See the BIND documentation
   <https://bind9.readthedocs.io/en/latest/reference.html#dynamic-update-policies>`_
   for details.

Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-rfc2136 \\
     --dns-rfc2136-credentials ~/.secrets/certbot/rfc2136.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-rfc2136 \\
     --dns-rfc2136-credentials ~/.secrets/certbot/rfc2136.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 30 seconds
             for DNS propagation

   certbot certonly \\
     --dns-rfc2136 \\
     --dns-rfc2136-credentials ~/.secrets/certbot/rfc2136.ini \\
     --dns-rfc2136-propagation-seconds 30 \\
     -d example.com

"""
