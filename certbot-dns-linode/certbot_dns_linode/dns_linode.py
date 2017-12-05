"""DNS Authenticator for Linode."""
import logging

from linode import api as linodeApi
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Linode

    This Authenticator uses the Linode API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Linode for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=930)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Linode credentials INI file',
            {
                'key': 'API key for Linode account'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_linode_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_linode_client().del_txt_record(domain, validation_name, validation)

    def _get_linode_client(self):
        return _LinodeClient(self.credentials.conf('key'))

class _LinodeClient(object):
    """
    Encapsulates all communication with the Linode API.
    """
    
    def __init__(self, api_key):
        self.linode_api = linodeApi.Api(key=api_key)
    
    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Linode
                                            API
        """

        try:
            domain = self._find_domain(domain_name)
        except linodeApi.ApiError as e:
            hint = None

            logger.debug('Error finding domain using the Linode API: %s', e)
            raise errors.PluginError('Error finding domain using the Linode API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        try:
            result = self.linode_api.domain_resource_create(
                DomainID=domain['DOMAINID'],
                Type='TXT',
                Name=self._compute_record_name(domain['DOMAIN'], record_name),
                Target=record_content)
            record_id = result['ResourceID']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except linode.Error as e:
            logger.debug('Error adding TXT record using the Linode API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Linode API: {0}'
                                     .format(e))
    
    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except linodeApi.ApiError as e:
            logger.debug('Error finding domain using the Linode API: %s', e)
            return

        try:
            domain_records = self.linode_api.domain_resource_list(DomainID=domain['DOMAINID'])

            matching_records = [record for record in domain_records
                                if record['TYPE'] == 'TXT'
                                and record['NAME'] == self._compute_record_name(domain['DOMAIN'], record_name)
                                and record['TARGET'] == record_content]
        except linodeApi.ApiError as e:
            logger.debug('Error getting DNS records using the Linode API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id: %s', record['RESOURCEID'])
                self.linode_api.domain_resource_delete(DomainID=domain['DOMAINID'], ResourceID=record['RESOURCEID'])
            except linodeApi.ApiError as e:
                logger.warn('Error deleting TXT record %s using the Linode API: %s',
                            record['RESOURCEID'], e)
    
    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `(dict of str: str)`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.linode_api.domain_list()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain['DOMAIN'] == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))
    
    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Linode's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain)[0]

