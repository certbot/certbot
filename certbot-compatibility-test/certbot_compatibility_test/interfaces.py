"""Certbot compatibility test interfaces"""
from abc import ABCMeta
from abc import abstractmethod

import certbot.interfaces


class PluginProxy(metaclass=ABCMeta):
    """Wraps a Certbot plugin"""

    http_port = NotImplemented
    "The port to connect to on localhost for HTTP traffic"

    https_port = NotImplemented
    "The port to connect to on localhost for HTTPS traffic"

    @abstractmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the parser"""

    @abstractmethod
    def __init__(args):
        """Initializes the plugin with the given command line args"""
        super().__init__()

    @abstractmethod
    def cleanup_from_tests():  # type: ignore
        """Performs any necessary cleanup from running plugin tests.

        This is guaranteed to be called before the program exits.

        """

    @abstractmethod
    def has_more_configs():  # type: ignore
        """Returns True if there are more configs to test"""

    @abstractmethod
    def load_config():  # type: ignore
        """Loads the next config and returns its name"""

    @abstractmethod
    def get_testable_domain_names():  # type: ignore
        """Returns the domain names that can be used in testing"""


class AuthenticatorProxy(PluginProxy, certbot.interfaces.Authenticator):
    """Wraps a Certbot authenticator"""


class InstallerProxy(PluginProxy, certbot.interfaces.Installer):
    """Wraps a Certbot installer"""

    @abstractmethod
    def get_all_names_answer():  # type: ignore
        """Returns all names that should be found by the installer"""


class ConfiguratorProxy(AuthenticatorProxy, InstallerProxy):
    """Wraps a Certbot configurator"""
