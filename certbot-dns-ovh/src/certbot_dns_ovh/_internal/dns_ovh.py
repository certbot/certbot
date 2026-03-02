"""DNS Authenticator for OVH DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://eu.api.ovh.com/createToken/ or https://ca.api.ovh.com/createToken/'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for OVH

    This Authenticator uses the OVH API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using OVH for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('endpoint',
                                  'OVH API endpoint (ovh-eu or ovh-ca)',
                                  'auth_entrypoint')
        self._add_provider_option('application-key',
                                  f'Application key for OVH API, obtained from {TOKEN_URL}',
                                  'auth_application_key')
        self._add_provider_option('application-secret',
                                  f'Application secret for OVH API, obtained from {TOKEN_URL}',
                                  'auth_application_secret')
        self._add_provider_option('consumer-key',
                                  f'Consumer key for OVH API, obtained from {TOKEN_URL}',
                                  'auth_consumer_key')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 120) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='OVH credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the OVH API.'

    @property
    def _provider_name(self) -> str:
        return 'ovh'

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> errors.PluginError:
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Is your Application Secret value correct?'
        if str(e).startswith('403 Client Error:'):
            hint = 'Are your Application Key and Consumer Key values correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier for {domain_name}: '
                                  f'{e}.{hint_disp}')

    def _handle_general_error(self, e: Exception, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and str(e).endswith('not found'):
            return None

        return super()._handle_general_error(e, domain_name)
