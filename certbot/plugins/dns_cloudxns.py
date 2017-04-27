"""DNS Authenticator for CloudXNS DNS."""
import logging
from requests.exceptions import HTTPError, RequestException

import zope.interface

from certbot import errors
from certbot import interfaces

from certbot.plugins import dns_common

from lexicon.providers import cloudxns

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://www.cloudxns.net/en/AccountManage/apimanage.html'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS  Authenticator for CloudXNS DNS

    This Authenticator uses the CloudXNS DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using CloudXNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=20)
        add('api-key', help='API key for CloudXNS account. (See {0}.)'.format(ACCOUNT_URL))
        add('secret-key', help='Secret key for CloudXNS account. (See {0}.)'.format(ACCOUNT_URL))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the CloudXNS API.'

    def _setup_credentials(self):
        self._configure('api-key', 'CloudXNS API key')
        self._configure('secret-key', 'CloudXNS secret key')

    def _perform(self, domain, validation_name, validation):
        self._get_cloudxns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_cloudxns_client().del_txt_record(domain, validation_name, validation)

    def _get_cloudxns_client(self):
        return _CloudXNSLexiconClient(self.conf('api-key'), self.conf('secret-key'), self.ttl)


class _CloudXNSLexiconClient(object):
    """
    Encapsulates all communication with the CloudXNS via Lexicon.
    """

    def __init__(self, api_key, secret_key, ttl):
        self.provider = cloudxns.Provider({
            'auth_username': api_key,
            'auth_token': secret_key,
            'ttl': ttl,
        })

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param string domain: The domain to use to look up the managed zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the CloudXNS API
        """
        self._find_domain_id(domain)

        try:
            self.provider.create_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param string domain: The domain to use to look up the managed zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the CloudXNS API
        """
        try:
            self._find_domain_id(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e,
                         exc_info=True)
            return

        try:
            self.provider.delete_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error deleting TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error deleting TXT record: {0}'.format(e))

    def _find_domain_id(self, domain):
        """
        Find the domain_id for a given domain.

        :param string domain: The domain for which to find the domain_id.
        :raises: errors.PluginError if the domain_id cannot be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                self.provider.options['domain'] = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                hint = None

                if str(e).startswith('400 Client Error:'):
                    hint = 'Are your API key and Secret key values correct?'

                raise errors.PluginError('Error determining domain_id: {0}.{1}'
                                         .format(e, ' ({0})'.format(hint) if hint else ''))
            except Exception as e:  # pylint: disable=broad-except
                if str(e).startswith('No domain found'):
                    pass
                else:
                    raise errors.PluginError('Unexpected error determining zone_id: {0}'.format(e))

        raise errors.PluginError('Unable to determine zone_id for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))
