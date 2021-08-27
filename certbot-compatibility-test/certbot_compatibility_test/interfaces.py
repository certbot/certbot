"""Certbot compatibility test interfaces"""
from abc import ABCMeta
from abc import abstractmethod

from certbot import interfaces


class PluginProxy(interfaces.Plugin, metaclass=ABCMeta):
    """Wraps a Certbot plugin"""

    http_port: int = NotImplemented
    """The port to connect to on localhost for HTTP traffic"""

    https_port: int = NotImplemented
    """The port to connect to on localhost for HTTPS traffic"""

    @classmethod
    @abstractmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the parser"""

    @abstractmethod
    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super().__init__(args, 'proxy')

    @abstractmethod
    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests.

        This is guaranteed to be called before the program exits.

        """

    @abstractmethod
    def has_more_configs(self):
        """Returns True if there are more configs to test"""

    @abstractmethod
    def load_config(self):
        """Loads the next config and returns its name"""

    @abstractmethod
    def get_testable_domain_names(self):
        """Returns the domain names that can be used in testing"""


class AuthenticatorProxy(PluginProxy, interfaces.Authenticator, metaclass=ABCMeta):
    """Wraps a Certbot authenticator"""


class InstallerProxy(PluginProxy, interfaces.Installer, metaclass=ABCMeta):
    """Wraps a Certbot installer"""

    @abstractmethod
    def get_all_names_answer(self):
        """Returns all names that should be found by the installer"""


class ConfiguratorProxy(AuthenticatorProxy, InstallerProxy, metaclass=ABCMeta):
    """Wraps a Certbot configurator"""


class Configurator(interfaces.Installer, interfaces.Authenticator, metaclass=ABCMeta):
    """Represents a plugin that has both Installer and Authenticator capabilities"""
