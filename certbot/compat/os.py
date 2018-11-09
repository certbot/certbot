"""
This compat modules extends native capabilities of core os module to handle correctly platform
specific operations (eg. chown, chmod, geuid)
"""
from __future__ import absolute_import

import errno
import os

def geteuid():
    """
    Get current user uid

    :returns: The current user uid.
    :rtype: int

    """
    try:
        # Linux specific
        return os.geteuid()
    except AttributeError:
        # Windows specific
        return 0

def rename(src, dst):
    """
    Rename a file to a destination path and handles situations where the destination exists.

    :param str src: The current file path.
    :param str dst: The new file path.
    """
    try:
        os.rename(src, dst)
    except OSError as err:
        # Windows specific, renaming a file on an existing path is not possible.
        # On Python 3, the best fallback with atomic capabilities we have is os.replace.
        if err.errno != errno.EEXIST:
            # Every other error is a legitimate exception.
            raise
        if not hasattr(os, 'replace'):  # pragma: no cover
            # We should never go on this line. Either we are on Linux and os.rename has succeeded,
            # either we are on Windows, and only Python >= 3.4 is supported where os.replace is
            # available.
            raise RuntimeError('Error: tried to run os.replace on Python < 3.3. '
                               'Certbot supports only Python 3.4 >= on Windows.')
        getattr(os, 'replace')(src, dst)
