"""Let's Encrypt compatibility test interfaces"""
import zope.interface

import letsencrypt.interfaces


class IPluginTester(zope.interface.Interface):
    """Wraps a Let's Encrypt plugin"""
    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the parser"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests.

        This is guarenteed to be called before the program exits.

        """

    def has_more_configs(self):
        """Returns True if there are more configs to test"""

    def load_config(self):
        """Loads the next configuration for the plugin to test"""


class IConfiguratorBaseTester(IPluginTester):
    """Common functionality for authenticator/installer tests"""
    http_port = zope.interface.Attribute(
        'The port to connect to on localhost for HTTP traffic')

    https_port = zope.interface.Attribute(
        'The port to connect to on localhost for HTTPS traffic')

    def get_test_domain_names(self):
        """Returns a list of domain names to test against the plugin"""


class IAuthenticatorTester(
        IConfiguratorBaseTester, letsencrypt.interfaces.IAuthenticator):
    """Wraps a Let's Encrypt authenticator"""


class IInstallerTester(
        IConfiguratorBaseTester, letsencrypt.interfaces.IInstaller):
    """Wraps a Let's Encrypt installer"""


class IConfiguratorTester(IAuthenticatorTester, IInstallerTester):
    """Wraps a Let's Encrypt configurator"""
