"""Certbot main public entry point."""
from certbot._internal import main as internal_main


def main(cli_args=None):
    """Command line argument parsing and main script execution.

    :returns: result of requested command

    :raises errors.Error: OS errors triggered by wrong permissions
    :raises errors.Error: error if plugin command is not supported

    """
    return internal_main.main(cli_args)
