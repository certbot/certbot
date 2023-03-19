"""DNS Authenticator for Value Domain DNS."""
import logging
from typing import Optional
from requests import HTTPError

from lexicon.providers import valuedomain

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

APIKEY_URL = "https://www.value-domain.com/vdapi/"


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Value Domain DNS

    This Authenticator uses the Value Domain API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Value Domain for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=90)
        add('credentials', help='Value Domain credentials file.')

    def more_info(self) -> str: # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Value Domain API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Value Domain API token',
            {
                'api-token': 'API token for Value Domain API obtained from {0}'.format(APIKEY_URL),
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_valuedomain_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_valuedomain_client().del_txt_record(domain, validation_name, validation)

    def _get_valuedomain_client(self) -> "_ValueDomainLexiconClient":
        return _ValueDomainLexiconClient(
            self.credentials.conf('api-token'),
            self.ttl
        )


class _ValueDomainLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Value Domain via Lexicon.
    """

    def __init__(self, api_token: str, ttl: int):
        super(_ValueDomainLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config(
            'valuedomain',
            {
                'ttl': ttl,
            },
            {
                'auth_token': api_token,
            })
        self.provider = valuedomain.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong
        return super(_ValueDomainLexiconClient, self)._handle_http_error(e, domain_name)

