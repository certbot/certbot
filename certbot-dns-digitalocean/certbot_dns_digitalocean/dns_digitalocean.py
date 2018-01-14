"""DNS Authenticator for DigitalOcean."""
import logging

import digitalocean
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DigitalOcean

    This Authenticator uses the DigitalOcean API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using DigitalOcean for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='DigitalOcean credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DigitalOcean API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'DigitalOcean credentials INI file',
            {
                'token': 'API token for DigitalOcean account'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_digitalocean_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_digitalocean_client().del_txt_record(domain, validation_name, validation)

    def _get_digitalocean_client(self):
        return _DigitalOceanClient(self.credentials.conf('token'))


class _DigitalOceanClient(object):
    """
    Encapsulates all communication with the DigitalOcean API.
    """

    def __init__(self, token):
        self.manager = digitalocean.Manager(token=token)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DigitalOcean
                                            API
        """

        try:
            domain = self._find_domain(domain_name)
        except digitalocean.Error as e:
            hint = None

            if str(e).startswith("Unable to authenticate"):
                hint = 'Did you provide a valid API token?'

            logger.debug('Error finding domain using the DigitalOcean API: %s', e)
            raise errors.PluginError('Error finding domain using the DigitalOcean API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        try:
            result = domain.create_new_domain_record(
                type='TXT',
                name=self._compute_record_name(domain, record_name),
                data=record_content)

            record_id = result['domain_record']['id']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except digitalocean.Error as e:
            logger.debug('Error adding TXT record using the DigitalOcean API: %s', e)
            raise errors.PluginError('Error adding TXT record using the DigitalOcean API: {0}'
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
        except digitalocean.Error as e:
            logger.debug('Error finding domain using the DigitalOcean API: %s', e)
            return

        try:
            domain_records = domain.get_records()

            matching_records = [record for record in domain_records
                                if record.type == 'TXT'
                                and record.name == self._compute_record_name(domain, record_name)
                                and record.data == record_content]
        except digitalocean.Error as e:
            logger.debug('Error getting DNS records using the DigitalOcean API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id: %s', record.id)
                record.destroy()
            except digitalocean.Error as e:
                logger.warn('Error deleting TXT record %s using the DigitalOcean API: %s',
                            record.id, e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `~digitalocean.Domain`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.manager.get_all_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain.name == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from DigitalOcean's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain.name)[0]
