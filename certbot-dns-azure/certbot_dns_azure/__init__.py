"""
The `~certbot_dns_azure.dns_azure` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Azure Cloud DNS API.



Named Arguments
---------------

========================================  =====================================
``--dns-azure-credentials``              Azure credentials JSON file.
                                          (Alternately, this can be specified
                                          the AZURE_AUTH_LOCATION env variable)
``--dns-azure-resource-group``           Azure resource group that contains the
                                          DNS zone being used.
                                          (Required)
``--dns-azure-propagation-seconds``      The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 60)
========================================  =====================================


Credentials
-----------


Use of this plugin requires a Service Principal account create with the DNS Zone
Contributor role. A new service principal can be created using the Azure CLI
<https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>
by running the command
.. code-block:: bash
   az login
   az ad sp create-for-rbac --name Certbot --sdk-auth \\
      --role "DNS Zone Contributor" \\
      --scope /subscriptions/<SUBSCRIPTION ID>/resourceGroups/<RESOURCE GROUP ID> \\
      > mycredentials.json

This will create file "mycredentials.json" which you should secure, then
specify with this option or with the AZURE_AUTH_LOCATION environment variable.

Alternately, you can use an existing service principal account with the correct
role assignment. In this case, you can create a json file in the following
format (as per
<https://docs.microsoft.com/python/azure/python-sdk-azure-authenticate?view=azure-python#mgmt-auth-file>
):
.. code-block:: json
    {
        "clientId": "ad735158-65ca-11e7-ba4d-ecb1d756380e",
        "clientSecret": "b70bb224-65ca-11e7-810c-ecb1d756380e",
        "subscriptionId": "bfc42d3a-65ca-11e7-95cf-ecb1d756380e",
        "tenantId": "c81da1d8-65ca-11e7-b1d1-ecb1d756380e",
        "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
        "resourceManagerEndpointUrl": "https://management.azure.com/",
        "activeDirectoryGraphResourceId": "https://graph.windows.net/",
        "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
        "galleryEndpointUrl": "https://gallery.azure.com/",
        "managementEndpointUrl": "https://management.core.windows.net/"
    }

The path to this file can be provided interactively or using the
``--dns-azure-credentials`` command-line argument, or by specifying it in the
AZURE_AUTH_LOCATION environment variable. Certbot records the path
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
     --dns-azure \\
     --dns-azure-credentials ~/.secrets/certbot/azure.json \\
     --dns-azure-resource-group Foo-RG02 \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-azure \\
     --dns-azure-credentials ~/.secrets/certbot/azure.json \\
     --dns-azure-resource-group Foo-RG02 \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 120 seconds
             for DNS propagation

   certbot certonly \\
     --dns-azure \\
     --dns-azure-credentials ~/.secrets/certbot/azure.json \\
     --dns-azure-resource-group Foo-RG02 \\
     --dns-azure-propagation-seconds 120 \\
     -d example.com

"""
