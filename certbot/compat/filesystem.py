"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import os  # pylint: disable=os-module-forbidden


def replace(src, dst):
    # type: (str, str) -> None
    """
    Rename a file to a destination path and handles situations where the destination exists.
    :param str src: The current file path.
    :param str dst: The new file path.
    """
    if hasattr(os, 'replace'):
        # Use replace if possible. On Windows, only Python >= 3.4 is supported
        # so we can assume that os.replace() is always available for this platform.
        getattr(os, 'replace')(src, dst)
    else:
        # Otherwise, use os.rename() that behaves like os.replace() on Linux.
        os.rename(src, dst)
