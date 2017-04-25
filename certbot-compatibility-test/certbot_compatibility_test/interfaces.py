"""Certbot compatibility test interfaces"""
import zope.interface

import certbot.interfaces

# pylint: disable=no-self-argument,no-method-argument


class IPluginProxy(zope.interface.Interface):
    """Wraps a Certbot plugin"""
    http_port = zope.interface.Attribute(
        "The port to connect to on localhost for HTTP traffic")

    https_port = zope.interface.Attribute(
        "The port to connect to on localhost for HTTPS traffic")

    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the parser"""

    def __init__(args):
        """Initializes the plugin with the given command line args"""

    def cleanup_from_tests():  # type: ignore
        """Performs any necessary cleanup from running plugin tests.

        This is guaranteed to be called before the program exits.

        """

    def has_more_configs():  # type: ignore
        """Returns True if there are more configs to test"""

    def load_config():  # type: ignore
        """Loads the next config and returns its name"""

    def get_testable_domain_names():  # type: ignore
        """Returns the domain names that can be used in testing"""


class IAuthenticatorProxy(IPluginProxy, certbot.interfaces.IAuthenticator):
    """Wraps a Certbot authenticator"""


class IInstallerProxy(IPluginProxy, certbot.interfaces.IInstaller):
    """Wraps a Certbot installer"""

    def get_all_names_answer():  # type: ignore
        """Returns all names that should be found by the installer"""


class IConfiguratorProxy(IAuthenticatorProxy, IInstallerProxy):
    """Wraps a Certbot configurator"""
