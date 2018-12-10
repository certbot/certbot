"""
General conftest for pytest execution of all integration tests lying
in the certbot_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.
"""
import os
import json
from _pytest import config as pytest_config


def pytest_configure(config):
    # type: (pytest_config.Config) -> None
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param pytest_config.Config config: the current pytest configuration
    """
    if not os.environ.get('CERTBOT_ACME_TYPE'):
        raise ValueError('Error, CERTBOT_ACME_TYPE environment variable is not set !')
    config.acme_xdist = _get_acme_xdist()


def _get_acme_xdist():
    # type: () -> dict
    """
    Get the acme server config distribution from the environment variable "CERTBOT_ACME_XDIST"
    :return: a dict of the acme server config distribution
    """
    acme_xdist = os.environ.get('CERTBOT_ACME_XDIST')
    if not acme_xdist:
        raise ValueError('Error, CERTBOT_ACME_XDIST environment variable is not set !')

    return json.loads(acme_xdist)
