"""Lexicon Linode DNS Plugin"""

import re

from lexicon.providers import linode as provider_linode
from lexicon.providers import linode4 as provider_linode4

from certbot import errors
from certbot.plugins import dns_common_lexicon
from certbot._internal.plugins.lexicon import common

API_KEY_URL = 'https://manager.linode.com/profile/api'
API_KEY_URL_V4 = 'https://cloud.linode.com/profile/tokens'


def linode_setup_credentials(self):
    """
    Customized _setup_credentials for Linode provider.
    """
    self.credentials = self._configure_credentials(     # pylint: disable=protected-access
        'credentials',
        'Linode credentials INI file.', {
            'key': 'API key for Linode account, obtained from {0} or {1}'
                .format(API_KEY_URL, API_KEY_URL_V4)
        })


def linode_http_error_handler(self, e, domain_name):   # pylint: disable=unused-argument
    """
    Customized HTTP error handler for Linode provider.
    """
    if not str(e).startswith('Domain not found'):
        return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                  .format(domain_name, e))
    return None


def linode_get_lexicon_client(self):
    """
    Create and return a lexicon client.
    """
    api_key = self.credentials.conf('key')
    api_version = self.credentials.conf('version')
    if api_version == '':
        api_version = None

    if not api_version:
        api_version = 3

        # Match for v4 api key
        regex_v4 = re.compile('^[0-9a-f]{64}$')
        regex_match = regex_v4.match(api_key)
        if regex_match:
            api_version = 4
    else:
        api_version = int(api_version)

    provider = None
    if api_version == 3:
        config = dns_common_lexicon.build_lexicon_config('linode', {}, {
            'auth_token': api_key,
        })

        provider = provider_linode.Provider(config)
    elif api_version == 4:
        config = dns_common_lexicon.build_lexicon_config('linode4', {}, {
            'auth_token': api_key,
        })

        provider = provider_linode4.Provider(config)
    else:
        raise errors.PluginError('Invalid api version specified: {0}. (Supported: 3, 4)'
                                 .format(api_version))

    return common.build_lexicon_client(None, linode_http_error_handler)(provider)


PLUGIN = common.LexiconPluginInfo(
    name='dns-linode',
    option='--dns-linode',
    default=False,
    help="Obtain certificates using a DNS TXT record (if you are using Linode for DNS).",
    info="Obtain certs using a DNS TXT record (if you are using Linode for DNS).",
    default_propagation_seconds=1200,
    parser_arguments={'credentials': 'Linode credentials INI file.'},
    fn_setup_credentials=linode_setup_credentials,
    fn_get_lexicon_client=linode_get_lexicon_client)
