"""Lexicon Godaddy DNS plugin"""

from lexicon.providers import godaddy as provider_godaddy

from certbot._internal.plugins.lexicon import common

def godaddy_setup_credentials(self):
    """
    Customized _setup_credentials for Godaddy provider.
    """
    self.credentials = self._configure_credentials(     # pylint: disable=protected-access
        'credentials',
        'Godaddy credentials INI file.', {
            'key': 'API key for Godaddy account',
            'secret': 'API secret for Godaddy account'
        })

def godaddy_http_error_handler(self, e, domain_name):   # pylint: disable=unused-argument
    """
    Customized HTTP error handler for Godaddy provider.
    """
    response = e.response
    response_body = response.json()
    if response.status_code == 404 and response_body['code'] == 'NOT_FOUND':
        # Lexicon client is just looking for the TLD.
        return None
    else:
        raise e

PLUGIN = common.LexiconPluginInfo(
    name='dns-godaddy',
    option='--dns-godaddy',
    default=False,
    help="Obtain certificates using a DNS TXT record (if you are using Godaddy for DNS).",
    info="Obtain certs using a DNS TXT record (if you are using Godaddy for DNS).",
    default_propagation_seconds=60,
    parser_arguments={'credentials': 'Godaddy credentials INI file.'},
    fn_setup_credentials=godaddy_setup_credentials,
    fn_get_lexicon_client=common.default_get_lexicon_client('godaddy', provider_godaddy.Provider, {
            'key': 'auth_key',
            'secret': 'auth_secret'
        }, None, godaddy_http_error_handler))
