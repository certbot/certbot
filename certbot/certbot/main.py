"""Certbot main public entry point."""
import logging.handlers
import sys

from certbot._internal import main as internal_main


logger = logging.getLogger(__name__)


def main(cli_args=None):
    """Shim around internal main script execution.

    :returns: result of requested command

    :raises errors.Error: OS errors triggered by wrong permissions
    :raises errors.Error: error if plugin command is not supported

    """
    return internal_main.main(cli_args)
