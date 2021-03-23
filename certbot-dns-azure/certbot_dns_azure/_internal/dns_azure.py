"""DNS Authenticator for Azure DNS."""
import logging
from typing import Dict

import zope.interface
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord
from azure.common.exceptions import CloudError
from azure.common.credentials import ServicePrincipalCredentials
from msrestazure.azure_active_directory import MSIAuthentication

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Azure DNS

    This Authenticator uses the Azure DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using '
                   'Azure for DNS).')
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credential = None
        self.domain_zoneid = {}  # type: Dict[str, str]

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('config', help='Azure config INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Azure DNS API.'

    def _validate_credentials(self, credentials):
        sp_client_id = credentials.conf('sp_client_id')
        sp_client_secret = credentials.conf('sp_client_secret')
        tenant_id = credentials.conf('tenant_id')
        has_sp = all((sp_client_id, sp_client_secret, tenant_id))

        msi_client_id = credentials.conf('msi_client_id')
        msi_system_assigned = credentials.conf('msi_system_assigned')

        if not any((has_sp, msi_system_assigned, msi_client_id)):
            raise errors.PluginError('{}: No authentication methods have been '
                                     'configured for Azure DNS. Either configure '
                                     'a service principal or system/user assigned '
                                     'managed identity'.format(credentials.confobj.filename))

        has_zone_mapping = any((key for key in credentials.confobj.keys() if 'azure_zone' in key))

        if not has_zone_mapping:
            raise errors.PluginError('{}: At least one zone mapping needs to be provided,'
                                     ' e.g dns_azure_zone1 = DOMAIN:DNS_ZONE_RESOURCE_GROUP_ID'
                                     ''.format(credentials.confobj.filename))

        # Check we have key value
        dns_zone_mapping_items_has_colon = [':' in value
                                            for key, value in credentials.confobj.items()
                                            if 'azure_zone' in key]
        if not all(dns_zone_mapping_items_has_colon):
            raise errors.PluginError('{}: DNS Zone mapping is not in the format of '
                                     'DOMAIN:DNS_ZONE_RESOURCE_GROUP_ID'
                                     ''.format(credentials.confobj.filename))

    def _setup_credentials(self):
        valid_creds = self._configure_credentials(
            'config',
            'Azure config INI file',
            None,
            self._validate_credentials
        )

        # Convert dns_azure_zoneX = key:value into key:value
        dns_zone_mapping_items = [value for key, value in valid_creds.confobj.items()
                                  if 'azure_zone' in key]
        self.domain_zoneid = dict([item.split(':', 1) for item in dns_zone_mapping_items])

        # Figure out which credential type we're going to use
        sp_client_id = valid_creds.conf('sp_client_id')
        sp_client_secret = valid_creds.conf('sp_client_secret')
        tenant_id = valid_creds.conf('tenant_id')
        msi_client_id = valid_creds.conf('msi_client_id')

        self.credential = self._get_azure_credentials(
            sp_client_id, sp_client_secret, tenant_id, msi_client_id
        )

    @staticmethod
    def _get_azure_credentials(client_id=None, client_secret=None, tenant=None, msi_client_id=None):
        has_sp = all((client_id, client_secret, tenant))
        if has_sp:
            return ServicePrincipalCredentials(
                client_id=client_id,
                secret=client_secret,
                tenant=tenant
            )
        elif msi_client_id:
            return MSIAuthentication(client_id=msi_client_id)
        else:
            return MSIAuthentication()

    def _get_ids_for_domain(self, domain):
        try:
            rg = self.domain_zoneid[domain]
            subscription_id = rg.split('/')[2]
            rg_name = rg.split('/')[4]
            return subscription_id, rg_name
        except KeyError:
            raise errors.PluginError('Domain {} does not have a valid domain to '
                                     'resource group id mapping'.format(domain))
        except IndexError:
            raise errors.PluginError('Domain {} has an invalid resource group id'.format(domain))

    def _perform(self, domain, validation_name, validation):
        subscription_id, resource_group_name = self._get_ids_for_domain(domain)
        client = self._get_azure_client(subscription_id)

        # Check to see if there are any existing TXT validation record values
        txt_value = {validation}
        try:
            existing_rr = client.record_sets.get(
                resource_group_name=resource_group_name,
                zone_name=domain,
                relative_record_set_name=validation_name,
                record_type='TXT')
            for record in existing_rr.txt_records:
                for value in record.value:
                    txt_value.add(value)
        except CloudError as err:
            if err.status_code != 404:  # Ignore RR not found
                raise errors.PluginError('Failed to check TXT record for domain '
                                         '{}, error: {}'.format(domain, err))

        try:
            client.record_sets.create_or_update(
                resource_group_name=resource_group_name,
                zone_name=domain,
                relative_record_set_name=validation_name,
                record_type='TXT',
                parameters=RecordSet(ttl=self.ttl, txt_records=[TxtRecord(value=list(txt_value))])
            )
        except CloudError as err:
            raise errors.PluginError('Failed to add TXT record to domain '
                                     '{}, error: {}'.format(domain, err))

    def _cleanup(self, domain, validation_name, validation):
        if self.credential is None:
            self._setup_credentials()

        subscription_id, resource_group_name = self._get_ids_for_domain(domain)
        client = self._get_azure_client(subscription_id)

        txt_value = set()
        try:
            existing_rr = client.record_sets.get(resource_group_name=resource_group_name,
                                                 zone_name=domain,
                                                 relative_record_set_name=validation_name,
                                                 record_type='TXT')
            for record in existing_rr.txt_records:
                for value in record.value:
                    txt_value.add(value)
        except CloudError as err:
            if err.status_code != 404:  # Ignore RR not found
                raise errors.PluginError('Failed to check TXT record for domain '
                                         '{}, error: {}'.format(domain, err))

        txt_value -= {validation}

        try:
            if txt_value:
                client.record_sets.create_or_update(
                    resource_group_name=resource_group_name,
                    zone_name=domain,
                    relative_record_set_name=validation_name,
                    record_type='TXT',
                    parameters=RecordSet(ttl=self.ttl,
                                         txt_records=[TxtRecord(value=list(txt_value))])
                )
            else:
                client.record_sets.delete(
                    resource_group_name=resource_group_name,
                    zone_name=domain,
                    relative_record_set_name=validation_name,
                    record_type='TXT'
                )
        except CloudError as err:
            if err.status_code != 404:  # Ignore RR not found
                raise errors.PluginError('Failed to remove TXT record for domain '
                                         '{}, error: {}'.format(domain, err))

    def _get_azure_client(self, subscription_id):
        """
        Gets azure DNS client

        :param subscription_id: Azure subscription ID
        :type subscription_id: str
        :return: Azure DNS client
        :rtype: DnsManagementClient
        """
        return DnsManagementClient(self.credential, subscription_id)
