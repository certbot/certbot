"""Lexicon DNS Authenticator Plugin."""

import logging

from certbot._internal import constants
from certbot._internal.plugins.lexicon import godaddy

logger = logging.getLogger(__name__)

class LexiconProvider(object):
    """Lexicon Provider
    """

    plugins = [godaddy.PLUGIN]

    # Update constants.CLI_DEFAULTS
    constants.CLI_DEFAULTS['dns_godaddy'] = False

    @classmethod
    def cli_plugins(cls, helpful):
        """
        Called from cli.py to add supported providers as DNS plugins.
        """
        for plugin in cls.plugins:
            helpful.add(["plugins", "certonly"], plugin.option,
                action="store_true",
                default=plugin.default,
                help=plugin.help)

    @classmethod
    def cli_plugin_requests(cls, config, req_auth, set_configurator):
        """
        Called from selection.py to handle supported providers.
        """
        if config.dns_godaddy:
            req_auth = set_configurator(req_auth, "dns-godaddy")
        return req_auth
