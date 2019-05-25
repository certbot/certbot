"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import
import tempfile
import os  # pylint: disable=os-module-forbidden

from certbot.compat import misc


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
    if os.name != 'nt':
        return os.open(file_path, flags, mode)

    # Windows specific
    # In order to avoid race conditions on file access when applying chown() after opening a file,
    # we use the capabilities of tempfile.mkstemp() to call chown() before opening the file.
    # Indeed, mkstemp() is called if the file does not exist and appropriate flag is set, then
    # chown() is invoked, then finally the temporary file is moved on its final location.
    # Using this approach, the file is never exposed to the system with loose permissions:
    # either it is a secured temporary file with exclusive access to the current user, or proper
    # call to chown() has already been applied before the file descriptor is returned.
    if not os.path.exists(file_path) and (flags & os.O_CREAT):
        file_h, path = tempfile.mkstemp()
        os.close(file_h)
        # TODO: Change to filesystem.rename once all logic of windows files permissions
        #  has been merged
        misc.os_rename(path, file_path)

    if os.path.exists(file_path):
        # TODO: Change to filesystem.chmod once all logic of windows files permissions
        #  has been merged
        os.chmod(file_path, mode)

    return os.open(file_path, flags)

