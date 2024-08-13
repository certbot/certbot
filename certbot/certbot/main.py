"""Certbot main public entry point."""
from typing import List
from typing import Optional
from typing import Union
import debugpy
from certbot._internal import main as internal_main


def main(cli_args: Optional[List[str]] = None) -> Optional[Union[str, int]]:
    """Run Certbot.

    :param cli_args: command line to Certbot, defaults to ``sys.argv[1:]``
    :type cli_args: `list` of `str`

    :returns: value for `sys.exit` about the exit status of Certbot
    :rtype: `str` or `int` or `None`

    """
    # print("running in debug mode")
    # debugpy.listen(('127.0.0.1', 5009))
    # print("waiting for client")
    # debugpy.wait_for_client()
    return internal_main.main(cli_args)
