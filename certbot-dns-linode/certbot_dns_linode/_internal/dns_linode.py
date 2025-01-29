"""DNS Authenticator for Linode."""
import logging
import re
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional
from typing import Union

from certbot import errors
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://manager.linode.com/profile/api'
API_KEY_URL_V4 = 'https://cloud.linode.com/profile/tokens'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for Linode

    This Authenticator uses the Linode API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Linode for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('key',
                                  'API key for Linode account, '
                                  f'obtained from {API_KEY_URL} or {API_KEY_URL_V4}',
                                  'auth_token')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 120) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    @property
    def _provider_name(self) -> str:
        if not hasattr(self, '_credentials'):  # pragma: no cover
            self._setup_credentials()

        api_key = cast(str, self._credentials.conf('key'))
        api_version: Optional[Union[str, int]] = self._credentials.conf('version')

        if not api_version:
            api_version = 3

            # Match for v4 api key
            regex_v4 = re.compile('^[0-9a-f]{64}$')
            regex_match = regex_v4.match(api_key)
            if regex_match:
                api_version = 4
        else:
            api_version = int(api_version)

        if api_version == 3:
            return 'linode'
        elif api_version == 4:
            return 'linode4'

        raise errors.PluginError(f'Invalid api version specified: {api_version}. (Supported: 3, 4)')

    def _setup_credentials(self) -> None:
        self._credentials = self._configure_credentials(
            key='credentials',
            label='Credentials INI file for linode DNS authenticator',
            required_variables={item[0]: item[1] for item in self._provider_options},
        )

    def _handle_general_error(self, e: Exception, domain_name: str) -> Optional[errors.PluginError]:
        if not str(e).startswith('Domain not found'):
            return errors.PluginError('Unexpected error determining zone identifier '
                                      f'for {domain_name}: {e}')
        return None
