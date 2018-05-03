"""DNS Authenticator for Alwaysdata."""
import logging

import requests
import zope.interface

from certbot import errors, __version__
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

# only for informational display in help
API_KEY_URL = 'https://admin.alwaysdata.com/admin/details/'
ACCOUNT_URL = 'https://admin.alwaysdata.com/admin/account/'

# https://help.alwaysdata.com/api/references
API_BASE = 'https://api.alwaysdata.com'
API_DOMAIN = API_BASE + '/v1/domain/'
API_RECORD = API_BASE + '/v1/record/'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Alwaysdata

    This Authenticator uses the Alwaysdata API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Alwaysdata as DNS '
                   'provider).')
    ttl = 10

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=10):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Alwaysdata credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ('This plugin configures a DNS TXT record to respond to a dns-01 challenge using '
                'the Alwaysdata API.')

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Alwaysdata credentials INI file',
            {
                'api-key': 'API key for Alwaysdata account, obtained from {}'.format(API_KEY_URL),
                'account': 'Name of the Alwaysdata account owning the domain and making the '
                           'requests, obtained from {}'.format(ACCOUNT_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_alwaysdata_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_alwaysdata_client().del_txt_record(domain, validation_name, validation, self.ttl)

    def _get_alwaysdata_client(self):
        return _AlwaysdataClient(self.credentials.conf('api-key'), self.credentials.conf('account'))


class _AlwaysdataClient(object):
    """
    Encapsulates all communication with Alwaysdata API.
    """

    def __init__(self, api_key, account):
        self.client = requests.session()
        self.client.headers = {'user-agent': 'certbot-dns-alwaysdata (v. {})'.format(__version__),
                               'alwaysdata-synchronous': 'yes'}
        # https://help.alwaysdata.com/api/usage/request#identification
        self.client.auth = ('{} account={}'.format(api_key, account), '')

    @classmethod
    def canonical_record_name(cls, record_name, domain_name):
        """
        Strip the domain name from the record name, as Alwaysdata expects name ``foo.bar`` when
        adding the ``foo.bar.domain.com`` record.

        :param str record_name: the full record name
        :param str domain_name: the domain name managing the DNS record
        """
        return record_name[:record_name.rindex("." + domain_name)]

    @classmethod
    def record_dict(cls, domain_name, domain_id, record_name, record_content, record_ttl):
        # pylint: disable=missing-docstring
        return {
            'domain': domain_id,
            'type': 'TXT',
            'name': cls.canonical_record_name(record_name, domain_name),
            'value': record_content,
            'ttl': record_ttl,
        }

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the API
        """
        domain_name, domain_id = self._find_alwaysdata_domain(domain)
        record_data = self.record_dict(domain_name, domain_id, record_name, record_content,
                                       record_ttl)
        try:
            r = self.client.post(API_RECORD, json=record_data)
            r.raise_for_status()
        except requests.RequestException as e:
            raise errors.PluginError('Error adding the TXT record: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        """
        domain_name, domain_id = self._find_alwaysdata_domain(domain)
        record_data = self.record_dict(domain_name, domain_id, record_name, record_content,
                                       record_ttl)
        try:
            r = self.client.get(API_RECORD, params=record_data)
            r.raise_for_status()
            records = r.json()
            if not records:
                logger.warning('No matching TXT record to delete, skipping cleanup')
                return
            if len(records) > 1:
                # prefer to not delete anything instead of deleting randomly
                logger.warning('Too many matching TXT records to delete, skipping cleanup')
                return
            record = records[0]
        except requests.RequestException as e:
            logger.warning(
                'Encountered error searching TXT record to delete, skipping cleanup: %s', e)
            return
        try:
            r = self.client.delete(API_BASE + record['href'])
            r.raise_for_status()
            logger.debug('Deleted Alwaysdata TXT record: %s', record['href'])
        except requests.RequestException as e:
            logger.warning('Encountered error deleting TXT record, skipping cleanup: %s', e)

    def _find_alwaysdata_domain(self, domain_name):
        """
        Find the Alwaysdata domain for a given domain name.

        :param str domain_name: The domain name for which to find the Alwaysdata domain.
        :returns: The domain name and domain ID, if found.
        :rtype: tuple(str, str)
        :raises certbot.errors.PluginError: if the domain cannot be found.
        """
        zone_names = dns_common.base_domain_name_guesses(domain_name)

        for zone_name in zone_names:
            try:
                response = self.client.get(API_DOMAIN, params={'name': zone_name})
                if response.ok:
                    for domain in response.json():
                        # check for exact match
                        if domain['name'] == zone_name:
                            return zone_name, domain['id']
            except requests.RequestException as e:
                raise errors.PluginError('Encountered error finding zone domain: {0}'.format(e))

        raise errors.PluginError(
            'Unable to determine domain for {0} using zone names: {1}.'.format(domain_name,
                                                                               zone_names))
