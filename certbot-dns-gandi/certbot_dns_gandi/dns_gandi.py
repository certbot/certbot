"""DNS Authenticator for Gandi DNS."""
import logging

import zope.interface
from lexicon.providers import gandi
from requests.exceptions import HTTPError

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

XMLRPC_TOKEN_URL = 'https://www.gandi.net/admin/apixml'
LIVEDNS_TOKEN_URL = 'https://account.gandi.net'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Gandi

    This Authenticator uses the Gandi XML-RPC or LiveDNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Gandi for DNS).'
    ttl = 300  # minimum TTL allowed by Gandi LiveDNS API

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Gandi credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Gandi API (either XML-RPC or LiveDNS, depending on your domain configuration).'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Gandi credentials INI file',
            {
                'api-protocol': 'Gandi API protocol (rpc or rest)',
                'token': 'User access token for Gandi API. (See {0} for '
                         'XML-RPC API or {1} for LiveDNS REST API.)'
                    .format(XMLRPC_TOKEN_URL, LIVEDNS_TOKEN_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_gandi_client(domain).add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_gandi_client(domain).del_txt_record(domain, validation_name, validation)

    def _get_gandi_client(self, domain):
        return _GandiLexiconClient(
            self.credentials.conf('api-protocol'),
            self.credentials.conf('token'),
            domain,
            self.ttl
        )


class _GandiLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Gandi API via Lexicon.
    """

    def __init__(self, protocol, token, domain, ttl):
        super(_GandiLexiconClient, self).__init__()

        self._protocol = protocol
        self._token = token
        self._ttl = ttl

        self.provider = self._get_provider(domain)

    def _find_domain_id(self, domain):
        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                # we need to instantiate a new provider here since simply setting options['domain']
                # (as is done in base class) is not propagated to internal GandiRPCSubProvider
                self.provider = self._get_provider(domain_name)

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                result = self._handle_http_error(e, domain_name)

                if result:
                    raise result  # pylint: disable=raising-bad-type
            except Exception as e:  # pylint: disable=broad-except
                result = self._handle_general_error(e, domain_name)

                if result:
                    raise result  # pylint: disable=raising-bad-type

        raise errors.PluginError('Unable to determine zone identifier for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))

    def _get_provider(self, domain_name):
        return gandi.Provider({
            'api_protocol': self._protocol,
            'auth_token': self._token,
            'domain': domain_name,
            'ttl': self._ttl,
        })

    def _handle_http_error(self, e, domain_name):
        hint = None

        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your API token value correct?'

        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return  # Expected errors when zone name guess is wrong

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        hint = None

        if 'OBJECT_ACCOUNT' in str(e) and 'CAUSE_NORIGHT' in str(e):
            hint = 'Is your API token value correct?'

        if 'OBJECT_DOMAIN' in str(e) and 'CAUSE_NOTFOUND' in str(e) and domain_name in str(e):
            return  # Expected errors when zone name guess is wrong

        if not str(e).startswith('No domain found'):
            hint_str = ' ({0})'.format(hint) if hint else ''
            return errors.PluginError('Unexpected error determining zone identifier'
                                      ' for {0}: {1}.{2}'.format(domain_name, e, hint_str))
