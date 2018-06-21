"""
The `~certbot_dns_ovh.dns_ovh` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the OVH API.


Named Arguments
---------------

===================================  ==========================================
``--dns-ovh-credentials``            OVH credentials_ INI file.
                                     (Required)
``--dns-ovh-propagation-seconds``    The number of seconds to wait for DNS
                                     to propagate before asking the ACME
                                     server to verify the DNS record.
                                     (Default: 30)
===================================  ==========================================


Credentials
-----------

Use of this plugin requires a configuration file containing OVH API
credentials for an account with the following access rules:

* ``GET /domain/zone/*``
* ``PUT /domain/zone/*``
* ``POST /domain/zone/*``
* ``DELETE /domain/zone/*``

These credentials can be obtained there:

* `OVH Europe <https://eu.api.ovh.com/createToken/>`_ (endpoint: ``ovh-eu``)
* `OVH North America <https://ca.api.ovh.com/createToken/>`_ (endpoint:
  ``ovh-ca``)

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # OVH API credentials used by Certbot
   dns_ovh_endpoint = ovh-eu
   dns_ovh_application_key = MDAwMDAwMDAwMDAw
   dns_ovh_application_secret = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw
   dns_ovh_consumer_key = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw

The path to this file can be provided interactively or using the
``--dns-ovh-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   OVH account. Users who can read this file can use these credentials
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
     --dns-ovh \\
     --dns-ovh-credentials ~/.secrets/certbot/ohv.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-ovh \\
     --dns-ovh-credentials ~/.secrets/certbot/ovh.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-ovh \\
     --dns-ovh-credentials ~/.secrets/certbot/ovh.ini \\
     --dns-ovh-propagation-seconds 60 \\
     -d example.com

"""
