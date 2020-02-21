"""Lexicon plugin provider common methods"""

import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

class LexiconPluginInfo(object):
    """
    Contains all information required to present a lexicon provider as a
    dns plugin to certbot.
    """

    # pylint: disable-msg=R0913,W0622
    def __init__(self, name, option, default, help, info,
            default_propagation_seconds, parser_arguments,
            fn_setup_credentials, fn_get_lexicon_client):
        """
        :param str name: Name of the plugin to present to certbot.
        :param str option: Command line option.
        :param bool default: Default value for the option.
        :param str help: Help text for the plugin.
        :param str info: Info text for the plugin. Shown mainly during plugin selection.
        :param int default_propagation_seconds: Default DNS propagation time.
        :param dict parser_arguments: Command line arguments for parser.
        :param fn_setup_credentials: Function that sets up credentials.
        :param fn_get_lexicon_client: Function that creats and returns a lexicon client.
        """
        self.name = name
        self.option = option
        self.default = default
        self.help = help
        self.info = info
        self.default_propagation_seconds = default_propagation_seconds
        self.parser_arguments = parser_arguments
        self.fn_setup_credentials = fn_setup_credentials
        self.fn_get_lexicon_client = fn_get_lexicon_client
        self.cls = build_lexicon_authenticator(self)

def build_lexicon_authenticator(plugin_info):
    """
    Create authenticator class for a single provider.

    :param plugin_info: Plugin information object for provider.
    """

    @zope.interface.implementer(interfaces.IAuthenticator)
    @zope.interface.provider(interfaces.IPluginFactory)
    class LexiconAuthenticator(dns_common.DNSAuthenticator):
        """Lexicon DNS Authenticator

        This Authenticator uses Lexicon to fulfill a dns-01 challenge.
        """

        plugin_info = None  # type: LexiconPluginInfo
        description = None

        def __init__(self, *args, **kwargs):
            super(LexiconAuthenticator, self).__init__(*args, **kwargs)
            self.credentials = None

        @classmethod
        def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
            super(LexiconAuthenticator, cls).add_parser_arguments(add,
                default_propagation_seconds=cls.plugin_info.default_propagation_seconds)

            for key, value in cls.plugin_info.parser_arguments.items():
                add(key, help=value)

        def more_info(self):  # pylint: disable=missing-docstring,no-self-use
            return LexiconAuthenticator.plugin_info.info

        def _perform(self, domain, validation_name, validation):
            self._get_lexicon_client().add_txt_record(domain, validation_name, validation)

        def _cleanup(self, domain, validation_name, validation):
            self._get_lexicon_client().del_txt_record(domain, validation_name, validation)

        def _setup_credentials(self):
            return LexiconAuthenticator.plugin_info.fn_setup_credentials(self)

        def _get_lexicon_client(self):
            return LexiconAuthenticator.plugin_info.fn_get_lexicon_client(self)

    LexiconAuthenticator.plugin_info = plugin_info
    LexiconAuthenticator.description = plugin_info.help
    return LexiconAuthenticator

def build_lexicon_client(general_error_handler, http_error_handler):
    """
    Create lexicon client with specified error handlers.

    :param general_error_handler: General error handler function or None to use default.
    :param http_error_handler: HTTP error handler function or None to use default.
    """

    class LexiconClient(dns_common_lexicon.LexiconClient):
        """
        Generic lexicon client.
        """

        fn_handle_general_error = None
        fn_handle_http_error = None

        def __init__(self, provider):
            super(LexiconClient, self).__init__()
            self.provider = provider

        def _handle_general_error(self, e, domain_name):
            if LexiconClient.fn_handle_general_error:
                # pylint: disable-msg=E1102
                LexiconClient.fn_handle_general_error(self, e, domain_name)
            else:
                super(LexiconClient, self)._handle_general_error(e, domain_name)

        def _handle_http_error(self, e, domain_name):
            if LexiconClient.fn_handle_http_error:
                # pylint: disable-msg=E1102
                LexiconClient.fn_handle_http_error(self, e, domain_name)
            else:
                super(LexiconClient, self)._handle_http_error(e, domain_name)

    if general_error_handler:
        LexiconClient.fn_handle_general_error = general_error_handler

    if http_error_handler:
        LexiconClient.fn_handle_http_error = http_error_handler

    return LexiconClient

def default_get_lexicon_client(lexicon_name, lexicon_cls, config_map,
    general_error_handler=None, http_error_handler=None):
    """
    Create a function that creates lexicon provider and lexicon client.

    :param str lexicon_name: Name of provider in lexicon library.
    :param lexicon_cls: The provider class in lexicon library.
    :param dict config_map: Mapping of configuration from certbot to lexicon.
    :param general_error_handler: General error handler function or None to use default.
    :param http_error_handler: HTTP error handler function or None to use default.
    """

    def get_lexicon_client(self):
        """
        Create and return a lexicon client.
        """
        # Map certbot config to lexicon config
        lexicon_config = {}
        for key, value in config_map.items():
            lexicon_config[value] = self.credentials.conf(key)

        config = dns_common_lexicon.build_lexicon_config(lexicon_name, {}, lexicon_config)
        provider = lexicon_cls(config)
        return build_lexicon_client(general_error_handler, http_error_handler)(provider)

    return get_lexicon_client
