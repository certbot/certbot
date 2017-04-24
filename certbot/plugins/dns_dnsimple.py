"""DNS Authenticator for DNSimple DNS."""
import logging
from requests.exceptions import HTTPError, RequestException

import zope.interface

from certbot import errors
from certbot import interfaces

from certbot.plugins import dns_common

from lexicon.providers import dnsimple

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dnsimple.com/user'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSimple

    This Authenticator uses the DNSimple v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using DNSimple for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('token', help='User access token for DNSimple v2 API. (See {0}.)'.format(ACCOUNT_URL))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNSimple API.'

    def _setup_credentials(self):
        self._configure('token', 'User access token (for v2 API)')

    def _perform(self, domain, validation_name, validation):
        self._get_dnsimple_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dnsimple_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsimple_client(self):
        return _DNSimpleLexiconClient(self.conf('token'), self.ttl)


class _DNSimpleLexiconClient(object):
    """
    Encapsulates all communication with the DNSimple via Lexicon.
    """

    def __init__(self, token, ttl):
        self.provider = dnsimple.Provider({
            'auth_token': token,
            'ttl': ttl,
        })

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param string domain: The domain to use to look up the managed zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the DNSimple API
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
        :raises: errors.PluginError if an error occurs communicating with the DNSimple API
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

                if str(e).startswith('401 Client Error: Unauthorized for url:'):
                    hint = 'Is your API token value correct?'

                raise errors.PluginError('Error determining domain_id: {0}.{1}'
                                         .format(e, ' ({0})'.format(hint) if hint else ''))
            except Exception as e:  # pylint: disable=broad-except
                if str(e).startswith('No domain found'):
                    pass
                else:
                    raise errors.PluginError('Unexpected error determining zone_id: {0}'.format(e))

        raise errors.PluginError('Unable to determine zone_id for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))
