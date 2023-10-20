"""iis plugin constants."""
import platform
from typing import Any
from typing import Dict

WINDOWS_SERVER_ROOT = "C:\inetpub"

server_root_tmp = WINDOWS_SERVER_ROOT

CLI_DEFAULTS: Dict[str, Any] = {
    "server_root": server_root_tmp,
    "ctl": "iis",
    "sleep_seconds": 1
}
"""CLI defaults."""

def os_constant(key: str) -> Any:
    # XXX TODO: In the future, this could return different constants
    #           based on what OS we are running under.  To see an
    #           approach to how to handle different OSes, see the
    #           apache version of this file.  Currently, we do not
    #           actually have any OS-specific constants on IIs.
    """
    Get a constant value for operating system

    :param str key: name of cli constant
    :return: value of constant for active os
    """
    return CLI_DEFAULTS[key]


HSTS_ARGS = ['\"max-age=31536000\"', ' ', 'always']

HEADER_ARGS = {'Strict-Transport-Security': HSTS_ARGS}
