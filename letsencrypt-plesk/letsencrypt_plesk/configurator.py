"""Plesk Configuration"""
import logging

import zope.interface

from acme import challenges

from letsencrypt import interfaces

from letsencrypt.plugins import common

from letsencrypt_plesk import api_client
from letsencrypt_plesk import challenge
from letsencrypt_plesk import deployer

logger = logging.getLogger(__name__)


class PleskConfigurator(common.Plugin):
    """Plesk Configurator"""
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Plesk"

    @classmethod
    def add_parser_arguments(cls, add):
        add("secret-key", default=None,
            help="Plesk API-RPC authentication secret key.")

    def __init__(self, *args, **kwargs):
        """Initialize Plesk Configurator."""
        super(PleskConfigurator, self).__init__(*args, **kwargs)

        self.plesk_challenges = {}
        self.plesk_deployers = {}
        # This will be set in the prepare function
        self.plesk_api_client = None

    def prepare(self):
        """Prepare the authenticator/installer."""
        if self.plesk_api_client is None:
            self.plesk_api_client = api_client.PleskApiClient(
                secret_key=self.conf('secret-key'))

    @staticmethod
    def more_info():
        """Human-readable string to help understand the module"""
        return "Configures Plesk to authenticate and install SSL certificate."

    # Authenticator methods below

    @staticmethod
    def get_chall_pref(unused_domain):
        """Return list of challenge preferences."""
        return [challenges.SimpleHTTP]

    def perform(self, achalls):
        """Perform the configuration related challenge."""
        responses = []
        for x in achalls:
            plesk_challenge = challenge.PleskChallenge(self.plesk_api_client)
            responses.append(plesk_challenge.perform(x))
            self.plesk_challenges[x.domain] = plesk_challenge
        return responses

    def cleanup(self, achalls):
        """Revert all challenges."""
        for x in achalls:
            if x.domain in self.plesk_challenges:
                self.plesk_challenges[x.domain].cleanup(x)
        # TODO too early to cleanup api
        # self.plesk_api_client.cleanup()

    # Installer methods below

    def get_all_names(self):
        """Returns all names that may be authenticated."""
        request = {'packet': [
            {'webspace': {'get': [
                {'filter': {}},
                {'dataset': {'gen_info': {}}},
            ]}},
            {'site': {'get': [
                {'filter': {}},
                {'dataset': {'gen_info': {}}},
            ]}},
        ]}
        response = self.plesk_api_client.request(request)
        return self._compact_names([
            self._get_names(response['packet']['webspace']['get']['result']),
            self._get_names(response['packet']['site']['get']['result']),
        ])

    def _get_names(self, api_result):
        if isinstance(api_result, list):
            return [self._get_names(x) for x in api_result]
        if 'ok' != api_result['status'] or 'data' not in api_result:
            return None
        return api_result['data']['gen_info']['name'].encode('utf8')

    def _compact_names(self, names):
        compact = []
        for name in names:
            if isinstance(name, list):
                compact += self._compact_names(name)
            elif name is None:
                continue
            else:
                compact.append(name)
        return compact

    def deploy_cert(self, domain, cert_path, key_path, chain_path=None):
        """Deploy certificate.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file

        :raises .PluginError: when cert cannot be deployed

        """
        plesk_deployer = deployer.PleskDeployer(self.plesk_api_client, domain)
        plesk_deployer.install_cert(cert_path, key_path, chain_path)
        plesk_deployer.assign_cert()
        self.plesk_deployers[domain] = plesk_deployer

    def enhance(self, domain, enhancement, options=None):
        """No enhancements are supported now."""
        pass  # pragma: no cover

    @staticmethod
    def supported_enhancements():
        """Returns a list of supported enhancements."""
        return []

    def get_all_certs_keys(self):
        """Retrieve all certs and keys set in configuration.

        :returns: tuples with form `[(cert, key, path)]`, where:

            - `cert` - str path to certificate file
            - `key` - str path to associated key file
            - `path` - file path to configuration file

        :rtype: list

        """
        # TODO implement
        return set()

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises .PluginError: when save is unsuccessful

        """
        # TODO implement

    def rollback_checkpoints(self, rollback=1):
        """Revert `rollback` number of configuration checkpoints.

        :raises .PluginError: when configuration cannot be fully reverted

        """
        # TODO implement

    def recovery_routine(self):
        """Revert configuration to most recent finalized checkpoint.

        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.

        :raises .errors.PluginError: If unable to recover the configuration

        """
        # TODO implement

    def view_config_changes(self):
        """Display all of the LE config changes.

        :raises .PluginError: when config changes cannot be parsed

        """
        # TODO implement

    @staticmethod
    def config_test():
        """Plesk configuration is always valid."""
        pass  # pragma: no cover

    @staticmethod
    def restart():
        """Web server has already restarted."""
        pass  # pragma: no cover
