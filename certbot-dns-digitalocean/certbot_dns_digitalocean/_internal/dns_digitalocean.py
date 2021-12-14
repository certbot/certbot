"""DNS Authenticator for DigitalOcean."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

import digitalocean

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DigitalOcean

    This Authenticator uses the DigitalOcean API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are ' + \
                  'using DigitalOcean for DNS).'
    ttl = 30

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='DigitalOcean credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DigitalOcean API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'DigitalOcean credentials INI file',
            {
                'token': 'API token for DigitalOcean account'
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_digitalocean_client().add_txt_record(domain, validation_name, validation,
                                                       self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_digitalocean_client().del_txt_record(domain, validation_name, validation)

    def _get_digitalocean_client(self) -> "_DigitalOceanClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _DigitalOceanClient(self.credentials.conf('token'))


class _DigitalOceanClient:
    """
    Encapsulates all communication with the DigitalOcean API.
    """

    def __init__(self, token: str) -> None:
        self.manager = digitalocean.Manager(token=token)

    def add_txt_record(self, domain_name: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL.
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
                data=record_content,
                ttl=record_ttl) # ttl kwarg is only effective starting python-digitalocean 1.15.0

            record_id = result['domain_record']['id']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except digitalocean.Error as e:
            logger.debug('Error adding TXT record using the DigitalOcean API: %s', e)
            raise errors.PluginError('Error adding TXT record using the DigitalOcean API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name: str, record_name: str, record_content: str) -> None:
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
                logger.warning('Error deleting TXT record %s using the DigitalOcean API: %s',
                            record.id, e)

    def _find_domain(self, domain_name: str) -> digitalocean.Domain:
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

            if matches:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError(f'Unable to determine base domain for {domain_name} using names: '
                                 f'{domain_name_guesses}.')

    @staticmethod
    def _compute_record_name(domain: digitalocean.Domain, full_record_name: str) -> str:
        # The domain, from DigitalOcean's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain.name)[0]
