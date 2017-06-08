"""
The `~certbot_dns_google.dns_google` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Google Cloud DNS API.


Named Arguments
---------------

========================================  =====================================
``--dns-google-credentials``              Google Cloud Platform credentials_
                                          JSON file.
                                          (Required)
``--dns-google-propagation-seconds``      The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 60)
========================================  =====================================

Credentials
-----------

Use of this plugin requires a configuration file containing Google Cloud
Platform API credentials for an account with the following permissions:

* ``dns.changes.create``
* ``dns.changes.get``
* ``dns.managedZones.list``
* ``dns.resourceRecordSets.create``
* ``dns.resourceRecordSets.delete``

Google provides instructions for
`creating a service account <https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount>`_
and
`information about the required permissions <https://cloud.google.com/dns/access-control#permissions_and_roles>`_.

.. code-block:: json
   :name: credentials.json
   :caption: Example credentials file:

   {
     "type": "service_account",
     ...
   }

The path to this file can be provided interactively or using the
``--dns-google-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue some types of API calls
   on your behalf, limited by the permissions assigned to the account. Users who
   can cause Certbot to run using these credentials can complete a ``dns-01``
   challenge to acquire new certificates or revoke existing certificates for
   domains these credentials are authorized to manage.

Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-google \\
     --dns-google-credentials ~/.secrets/certbot/google.json \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-google \\
     --dns-google-credentials ~/.secrets/certbot/google.json \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 120 seconds
             for DNS propagation

   certbot certonly \\
     --dns-google \\
     --dns-google-credentials ~/.secrets/certbot/google.ini \\
     --dns-google-propagation-seconds 120 \\
     -d example.com

"""
