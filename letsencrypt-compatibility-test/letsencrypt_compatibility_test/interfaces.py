"""Let's Encrypt compatibility test interfaces"""
import zope.interface

import letsencrypt.interfaces

# pylint: disable=no-self-argument,no-method-argument


class IPluginProxy(zope.interface.Interface):
    """Wraps a Let's Encrypt plugin"""
    http_port = zope.interface.Attribute(
        "The port to connect to on localhost for HTTP traffic")

    https_port = zope.interface.Attribute(
        "The port to connect to on localhost for HTTPS traffic")

    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the parser"""

    def __init__(args):
        """Initializes the plugin with the given command line args"""

    def cleanup_from_tests():
        """Performs any necessary cleanup from running plugin tests.

        This is guaranteed to be called before the program exits.

        """

    def has_more_configs():
        """Returns True if there are more configs to test"""

    def load_config():
        """Loads the next config and returns its name"""

    def get_testable_domain_names():
        """Returns the domain names that can be used in testing"""


class IAuthenticatorProxy(IPluginProxy, letsencrypt.interfaces.IAuthenticator):
    """Wraps a Let's Encrypt authenticator"""


class IInstallerProxy(IPluginProxy, letsencrypt.interfaces.IInstaller):
    """Wraps a Let's Encrypt installer"""

    def get_all_names_answer():
        """Returns all names that should be found by the installer"""


class IConfiguratorProxy(IAuthenticatorProxy, IInstallerProxy):
    """Wraps a Let's Encrypt configurator"""
