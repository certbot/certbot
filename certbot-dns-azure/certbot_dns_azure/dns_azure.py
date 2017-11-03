"""DNS Authenticator for Azure DNS."""
import json
import logging
import os

import httplib2
import zope.interface

from azure.mgmt.dns import DnsManagementClient
from azure.common.client_factory import get_client_from_auth_file
from azure.mgmt.dns.models import RecordSet, TxtRecord
from msrestazure.azure_exceptions import CloudError


from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCT_URL = 'https://docs.microsoft.com/en-au/python/azure/python-sdk-azure-authenticate?view=azure-python#mgmt-auth-file'
AZURE_CLI_URL = 'https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest'
AZURE_CLI_COMMAND = 'az ad sp create-for-rbac --name Certbot --sdk-auth --role "DNS Zone Contributor" --scope /subscriptions/<YOUR SUBSCRIPTION ID>/resourceGroups/<YOUR RESOURCE GROUP ID > mycredentials.json'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Azure DNS

    This Authenticator uses the Azure DNS API to fulfill a dns-01 challenge.
    """

    description = (
    'Obtain certificates using a DNS TXT record (if you are using Azure DNS '
    'for DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add,
                                                       default_propagation_seconds=60)
        add('credentials',
            help=(
                'Path to Azure DNS service account JSON file. If you already have a Service ' +
                'Principal with the required permissions, you can create your own file as per ' +
                'the JSON file format at {0}. ' +
                'Otherwise, you can create a new Service Principal using the Azure CLI ' +
                '(available at {1}) by running "az login" then "{2}"' +
                'This will create file "mycredentials.json" which you should secure, then ' +
                'specify with this option or with the AZURE_AUTH_LOCATION environment variable.')
            .format(ACCT_URL, AZURE_CLI_URL, AZURE_CLI_COMMAND),
            default=None)
        add('resource-group',
            help=('Resource Group in which the DNS zone is located'),
            default=None)

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Azure DNS API.'

    def _setup_credentials(self):
        if self.conf('resource-group') is None:
            raise errors.PluginError('Please specify a resource group using '
                                     '--dns-azure-resource-group <RESOURCEGROUP>')

        if self.conf(
                'credentials') is None and 'AZURE_AUTH_LOCATION' not in os.environ:
            raise errors.PluginError(
                'Please specify credentials file using the '
                'AZURE_AUTH_LOCATION environment variable or '
                'using --dns-azure-credentials <file>')
        else:
            self._configure_file('credentials',
                                 'path to Azure DNS service account JSON file')

            dns_common.validate_file_permissions(self.conf('credentials'))

    def _perform(self, domain, validation_name, validation):
        self._get_azure_client().add_txt_record(domain, validation_name,
                                                validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_azure_client().del_txt_record(domain, validation_name,
                                                validation, self.ttl)

    def _get_azure_client(self):
        return _AzureClient(self.conf('resource-group'),
                            self.conf('credentials'))


class _AzureClient(object):
    """
    Encapsulates all communication with the Azure Cloud DNS API.
    """

    def __init__(self, resource_group, account_json=None):
        self.resource_group = resource_group
        self.dns_client = get_client_from_auth_file(DnsManagementClient,
                                                    auth_path=account_json)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Azure API
        """
        try:
            record = RecordSet(ttl=record_ttl,
                               txt_records=[TxtRecord(value=[record_content])])
            zone = self._find_managed_zone(record_name)
            relative_record_name = ".".join(
                record_name.split('.')[0:-len(zone.split('.'))])
            self.dns_client.record_sets.create_or_update(self.resource_group,
                                                         zone,
                                                         relative_record_name,
                                                         'TXT',
                                                         record)
        except CloudError as e:
            logger.error('Encountered error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Azure DNS API: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Azure API
        """

        try:
            zone = self._find_managed_zone(record_name)
            relative_record_name = ".".join(
                record_name.split('.')[0:-len(zone.split('.'))])
            self.dns_client.record_sets.delete(self.resource_group,
                                               zone,
                                               relative_record_name,
                                               'TXT')
        except (CloudError, errors.PluginError) as e:
            logger.warning('Encountered error deleting TXT record: %s', e)

    def _find_managed_zone(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The name of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """
        try:
            azure_zones = self.dns_client.zones.list()  # TODO - catch errors
            azure_zones_list = []
            while True:
                for zone in azure_zones.current_page:
                    azure_zones_list.append(zone.name)
                azure_zones.next()
        except StopIteration:
            pass
        except CloudError as e:
            logger.error('Error finding zone: {0}'.format(e))
            raise errors.PluginError('Error finding zone form the Azure DNS API: {0}'.format(e))
        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)

        for zone_name in zone_dns_name_guesses:
            if zone_name in azure_zones_list:
                return zone_name

        raise errors.PluginError(
            'Unable to determine managed zone for {0} using zone names: {1}.'
            .format(domain, zone_dns_name_guesses))
