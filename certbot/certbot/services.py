"""This module contains global singletons used throughout Certbot."""
from typing import Optional, Any

from certbot._internal.configuration import NamespaceConfig
from certbot.interfaces import IConfig
from certbot.interfaces import IDisplay
from certbot.interfaces import IReporter


class _Services:
    def __init__(self):
        self.display: Optional[IDisplay] = None
        self.reporter: Optional[IReporter] = None
        self.config: Optional[IConfig] = None


_services = _Services()


# The following functions use "Any" for their parameter/output types. Normally interfaces from
# certbot.interfaces would be used, but MyPy will not understand their semantic. These interfaces
# will be removed soon and replaced by ABC classes that will be used also here for type checking.
# TODO: replace Any by actual ABC classes once available


def get_config() -> Any:
    """Get the Certbot configuration.

    :return: the Certbot configuration
    :rtype: IConfig

    """
    return _services.config


def get_display() -> Any:
    """Get the display utility.

    :return: the display utility
    :rtype: IDisplay

    """
    return _services.display


def get_reporter() -> Any:
    """Get the reporter utility

    :return: the reporter utility
    :rtype: IReporter

    """
    return _services.reporter


def set_config(config: Any) -> None:
    """Set the Certbot configuration.

    :param IConfig config: the Certbot configuration

    """
    _services.config = config


def set_display(display: Any) -> None:
    """Set the display utility.

    :param IDisplay display: the display utility

    """
    _services.display = display


def set_reporter(reporter: Any) -> None:
    """Set the reporter utility.

    :param IReporter reporter: the reporter utility

    """
    _services.reporter = reporter
