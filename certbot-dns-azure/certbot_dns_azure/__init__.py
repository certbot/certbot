"""
The `~certbot_dns_azure.dns_azure` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Azure API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

========================================  =====================================
``--dns-azure-config``                    Azure config INI file.
                                          (Required)
========================================  =====================================


Configuration
-------------

Use of this plugin requires a configuration file containing Azure API
credentials or information.

This plugin supported API authentication using either Service Principals or
utilising a Managed Identity assigned to the virtual machine.

Regardless which authentication method used, the identity will need the
"DNS Zone Contributor" role assigned to it.

As multiple Azure DNS Zones in multiple resource groups can exist, the config
file needs a mapping of zone to resource group ID. Multiple zones -> ID mappings
can be listed by using the key ``dns_azure_zoneX`` where X is a unique number.
At least 1 zone mapping is required.

.. code-block:: ini
   :name: certbot_azure_service_principal.ini
   :caption: Example config file using a service principal

   dns_azure_sp_client_id = 912ce44a-0156-4669-ae22-c16a17d34ca5
   dns_azure_sp_client_secret = E-xqXU83Y-jzTI6xe9fs2YC~mck3ZzUih9
   dns_azure_tenant_id = ed1090f3-ab18-4b12-816c-599af8a88cf7

   dns_azure_zone1 = example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1  # pylint: disable=line-too-long
   dns_azure_zone2 = example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2  # pylint: disable=line-too-long

.. code-block:: ini
   :name: certbot_azure_user_msi.ini
   :caption: Example config file using used assigned MSI:

   dns_azure_msi_client_id = 912ce44a-0156-4669-ae22-c16a17d34ca5

   dns_azure_zone1 = example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1  # pylint: disable=line-too-long
   dns_azure_zone2 = example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2  # pylint: disable=line-too-long

.. code-block:: ini
   :name: certbot_azure_system_msi.ini
   :caption: Example config file using system assigned MSI:

   dns_azure_msi_system_assigned = true

   dns_azure_zone1 = example.com:/subscriptions/c135abce-d87d-48df-936c-15596c6968a5/resourceGroups/dns1  # pylint: disable=line-too-long
   dns_azure_zone2 = example.org:/subscriptions/99800903-fb14-4992-9aff-12eaf2744622/resourceGroups/dns2  # pylint: disable=line-too-long

The path to this file can be provided interactively or using the
``--dns-azure-config`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Azure account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for domains the identity
   has access to.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on configuration file", followed by the path to the config
file. This warning will be emitted each time Certbot uses the config file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-azure \\
     --dns-azure-config ~/.secrets/certbot/azure.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``example.org``

   certbot certonly \\
     --dns-azure \\
     --dns-azure-config ~/.secrets/certbot/azure.ini \\
     -d example.com \\
     -d example.org

"""
