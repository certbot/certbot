"""Certbot main public entry point."""
from certbot._internal import main as internal_main


def main(cli_args=None):
    """Run Certbot.

    :param cli_args: command line to Certbot, defaults to ``sys.argv[1:]``
    :type cli_args: `list` of `str`

    :returns: value for `sys.exit` about the exit status of Certbot
    :rtype: `str` or `int` or `None`

    """
    return internal_main.main(cli_args)
