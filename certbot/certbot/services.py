"""This module contains global singletons used throughout Certbot."""
from typing import Optional

from certbot.interfaces import Config
from certbot.interfaces import Display
from certbot.interfaces import Reporter


class _Services:
    def __init__(self):
        self.display: Optional[Display] = None
        self.reporter: Optional[Reporter] = None
        self.config: Optional[Config] = None


_services = _Services()


def get_config() -> Config:
    """Get the Certbot configuration.

    :return: the Certbot configuration
    :rtype: Config
    :raise: ValueError if the Certbot configuration is not set

    """
    if not _services.config:
        raise ValueError("Config is not set.")
    return _services.config


def get_display() -> Display:
    """Get the display utility.

    :return: the display utility
    :rtype: Display
    :raise: ValueError if the display utility is not set

    """
    if not _services.display:
        raise ValueError("Display is not set.")
    return _services.display


def get_reporter() -> Reporter:
    """Get the reporter utility

    :return: the reporter utility
    :rtype: Reporter
    :raise: ValueError if the reporter utility is not set

    """
    if not _services.reporter:
        raise ValueError("Reporter is not set.")
    return _services.reporter


def set_config(config: Config) -> None:
    """Set the Certbot configuration.

    :param Config config: the Certbot configuration

    """
    _services.config = config


def set_display(display: Display) -> None:
    """Set the display utility.

    :param Display display: the display utility

    """
    _services.display = display


def set_reporter(reporter: Reporter) -> None:
    """Set the reporter utility.

    :param Reporter reporter: the reporter utility

    """
    _services.reporter = reporter
