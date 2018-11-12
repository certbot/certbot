"""
This compat modules handle various platform specific calls that do not fall into one
particular category.
"""
from __future__ import absolute_import

import select
import sys

try:
    from win32com.shell import shell as shellwin32  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    shellwin32 = None  # type: ignore

from certbot import errors


def raise_for_non_administrative_windows_rights():
    """
    On Windows, raise if current shell does not have the administrative rights.
    Do nothing on Linux.

    :raises .errors.Error: If the current shell does not have administrative rights on Windows.

    """
    if shellwin32 and shellwin32.IsUserAnAdmin() == 0:
        raise errors.Error('Error, certbot must be run on a shell with administrative rights.')


def readline_with_timeout(timeout, prompt):
    """
    Read user input to return the first line entered, or raise after specified timeout.

    :param float timeout: The timeout in seconds given to the user.
    :param str prompt: The prompt message to display to the user.

    :returns: The first line entered by the user.
    :rtype: str

    """
    try:
        # Linux specific
        #
        # Call to select can only be done like this on UNIX
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if not rlist:
            raise errors.Error(
                "Timed out waiting for answer to prompt '{0}'".format(prompt))
        return rlist[0].readline()
    except OSError:
        # Windows specific
        #
        # No way with select to make a timeout to the user input on Windows,
        # as select only supports socket in this case.
        # So no timeout on Windows for now.
        return sys.stdin.readline()
