"""DNS Authenticator for Godaddy."""
import logging

import godaddypy
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Godaddy

    This Authenticator uses the Godaddy API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Godaddy for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Godaddy credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Godaddy API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Godaddy credentials INI file',
            {
                'key': 'API key for Godaddy account',
                'secret': 'API secret for Godaddy account'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_godaddy_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_godaddy_client().del_txt_record(domain, validation_name, validation)

    def _get_godaddy_client(self):
        return _GodaddyClient(self.credentials.conf('key'), self.credentials.conf('secret'))


class _GodaddyClient(object):
    """
    Encapsulates all communication with the Godaddy API.
    """

    def __init__(self, key, secret):
        account = godaddypy.Account(api_key=key, api_secret=secret)
        self.client = godaddypy.Client(account)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Godaddy
                                            API
        """

        try:
            domain = self._find_domain(domain_name)
        except godaddypy.client.BadResponse as e:
            hint = None

            if "UNABLE_TO_AUTHENTICATE" in str(e):
                hint = 'Did you provide a valid API token?'

            logger.debug('Error finding domain using the Godaddy API: %s', e)
            raise errors.PluginError('Error finding domain using the Godaddy API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        try:
            self.client.add_record(domain, {
                'data': record_content,
                'name': self._compute_record_name(domain, record_name),
                'type': 'TXT'
            })
            logger.debug('Successfully added TXT record')
        except godaddypy.client.BadResponse as e:
            logger.debug('Error adding TXT record using the Godaddy API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Godaddy API: {0}'
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
        except godaddypy.client.BadResponse as e:
            logger.debug('Error finding domain using the Godaddy API: %s', e)
            return

        try:
            domain_records = self.client.get_records(domain, record_type='TXT')

            matching_records = [record for record in domain_records
                                if record['type'] == 'TXT'
                                and record['name'] == self._compute_record_name(domain, record_name)
                                and record['data'] == record_content]
        except godaddypy.client.BadResponse as e:
            logger.debug('Error getting DNS records using the Godaddy API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with name: %s', record['name'])
                self.client.delete_records(domain, name=record['name'], record_type='TXT')
            except godaddypy.client.BadResponse as e:
                logger.warn('Error deleting TXT record %s using the Godaddy API: %s',
                            record['name'], e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.client.get_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Godaddy's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain)[0]
