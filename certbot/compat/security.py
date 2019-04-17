"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import os  # pylint: disable=os-module-forbidden


def open(file_path, flags, mode=0o777):  # pylint: disable=redefined-builtin
    # type: (str, int, int) -> int
    """
    Wrapper of original os.open function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int flags: Flags to apply on file while opened
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :returns: the file descriptor to the opened file
    :rtype: int
    """
    file_descriptor = os.open(file_path, flags, mode)
    # TODO: Change to security.chmod once all logic of windows files permissions has been merged
    os.chmod(file_path, mode)

    return file_descriptor
