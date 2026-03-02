"""Certbot main public entry point."""
from typing import Optional
from typing import Union

from certbot._internal import main as internal_main


def main(cli_args: Optional[list[str]] = None) -> Optional[Union[str, int]]:
    """Run Certbot.

    :param cli_args: command line to Certbot, defaults to ``sys.argv[1:]``
    :type cli_args: `list` of `str`

    :returns: value for `sys.exit` about the exit status of Certbot
    :rtype: `str` or `int` or `None`

    """
    return internal_main.main(cli_args)
