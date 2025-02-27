"""Certbot compatibility test interfaces"""
from abc import ABCMeta
from abc import abstractmethod
import argparse
from typing import cast


from certbot import interfaces
from certbot.configuration import NamespaceConfig


class PluginProxy(interfaces.Plugin, metaclass=ABCMeta):
    """Wraps a Certbot plugin"""

    http_port: int = NotImplemented
    """The port to connect to on localhost for HTTP traffic"""

    https_port: int = NotImplemented
    """The port to connect to on localhost for HTTPS traffic"""

    @classmethod
    @abstractmethod
    def add_parser_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Adds command line arguments needed by the parser"""

    @abstractmethod
    def __init__(self, args: argparse.Namespace) -> None:
        """Initializes the plugin with the given command line args"""
        super().__init__(cast(NamespaceConfig, args), 'proxy')

    @abstractmethod
    def cleanup_from_tests(self) -> None:
        """Performs any necessary cleanup from running plugin tests.

        This is guaranteed to be called before the program exits.

        """

    @abstractmethod
    def has_more_configs(self) -> bool:
        """Returns True if there are more configs to test"""

    @abstractmethod
    def load_config(self) -> str:
        """Loads the next config and returns its name"""

    @abstractmethod
    def get_testable_domain_names(self) -> set[str]:
        """Returns the domain names that can be used in testing"""


class AuthenticatorProxy(PluginProxy, interfaces.Authenticator, metaclass=ABCMeta):
    """Wraps a Certbot authenticator"""


class InstallerProxy(PluginProxy, interfaces.Installer, metaclass=ABCMeta):
    """Wraps a Certbot installer"""

    @abstractmethod
    def get_all_names_answer(self) -> set[str]:
        """Returns all names that should be found by the installer"""


class ConfiguratorProxy(AuthenticatorProxy, InstallerProxy, metaclass=ABCMeta):
    """Wraps a Certbot configurator"""
