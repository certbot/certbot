"""
The `~certbot_dns_google.dns_google` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Google Cloud DNS API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

========================================  =====================================
``--dns-google-credentials``              Google Cloud Platform credentials_
                                          JSON file.
                                          (Required - Optional on Google Compute Engine)
``--dns-google-propagation-seconds``      The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 60)
========================================  =====================================


Credentials
-----------

Use of this plugin requires Google Cloud Platform API credentials
for an account with the following permissions:

* ``dns.changes.create``
* ``dns.changes.get``
* ``dns.changes.list``
* ``dns.managedZones.get``
* ``dns.managedZones.list``
* ``dns.resourceRecordSets.create``
* ``dns.resourceRecordSets.delete``
* ``dns.resourceRecordSets.list``
* ``dns.resourceRecordSets.update``

Google provides instructions for `creating a service account <https://developers
.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount>`_ and
`information about the required permissions <https://cloud.google.com/dns/access
-control#permissions_and_roles>`_. If you're running on Google Compute Engine,
you can `assign the service account to the instance <https://cloud.google.com/
compute/docs/access/create-enable-service-accounts-for-instances>`_ which
is running certbot. A credentials file is not required in this case, as they
are automatically obtained by certbot through the `metadata service
<https://cloud.google.com/compute/docs/storing-retrieving-metadata>`_ .

.. code-block:: json
   :name: credentials.json
   :caption: Example credentials file:

   {
      "type": "service_account",
      "project_id": "...",
      "private_key_id": "...",
      "private_key": "...",
      "client_email": "...",
      "client_id": "...",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://accounts.google.com/o/oauth2/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": "..."
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
     --dns-google-credentials ~/.secrets/certbot/google.json \\
     --dns-google-propagation-seconds 120 \\
     -d example.com

"""
