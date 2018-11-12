"""
This compat modules extends native capabilities of core os module to handle correctly platform
specific operations (eg. chown, chmod, geuid).
This module is intended to replace standard os module throughout certbot projects (except acme)
"""
from __future__ import absolute_import

# Expose everything from standard os package to make current package a complete replacement of os.
# pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin
from os import *  # type: ignore
# pylint: enable=wildcard-import,unused-wildcard-import,redefined-builtin

import errno
import os as std_os
import sys

from acme.magic_typing import Callable, Union  # pylint: disable=unused-import, no-name-in-module
from certbot.compat import security

# Monkey patch ourselves to get os attributes that are not in __all__ (so not from os import *)
ourselves = sys.modules[__name__]
for attribute in dir(std_os):
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os, attribute))
del ourselves


def geteuid():  # pylint: disable=function-redefined
    # type: () -> int
    """
    Get current user uid

    :returns: The current user uid.
    :rtype: int

    """
    try:
        # Linux specific
        return std_os.geteuid()
    except AttributeError:
        # Windows specific
        return 0


def rename(src, dst):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], Union[str, unicode]) -> None
    """
    Rename a file to a destination path and handles situations where the destination exists.

    :param str src: The current file path.
    :param str dst: The new file path.
    """
    try:
        std_os.rename(src, dst)
    except OSError as err:
        # Windows specific, renaming a file on an existing path is not possible.
        # On Python 3, the best fallback with atomic capabilities we have is os.replace.
        if err.errno != errno.EEXIST:
            # Every other error is a legitimate exception.
            raise
        if not hasattr(std_os, 'replace'):  # pragma: no cover
            # We should never go on this line. Either we are on Linux and os.rename has succeeded,
            # either we are on Windows, and only Python >= 3.4 is supported where os.replace is
            # available.
            raise RuntimeError('Error: tried to run os.replace on Python < 3.3. '
                               'Certbot supports only Python 3.4 >= on Windows.')
        getattr(std_os, 'replace')(src, dst)


def open(file, flags, mode=0o777):  # pylint: disable=function-redefined,redefined-builtin
    # type: (Union[str, unicode], int, int) -> int
    """
    Wrapper of original os.open function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file: The file path to open
    :param int flags: Flags to apply on file while opened
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``

    :returns: the file descriptor to the opened file
    :rtype: int
    """
    file_descriptor = std_os.open(file, flags, mode)
    security.apply_mode(file, mode)

    return file_descriptor


def mkdir(file_path, mode=0o777, mkdir_fn=None):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int, Callable[[Union[str, unicode], int], None]) -> None
    """
    Wrapper of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :param callable mkdir_fn: The underlying mkdir function to use
    """
    mkdir_fn = mkdir_fn or std_os.mkdir

    mkdir_fn(file_path, mode)
    security.apply_mode(file_path, mode)


def makedirs(file_path, mode=0o777):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int) -> None
    """
    Wrapper of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    """
    # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
    # os module for the time of makedirs execution.
    orig_mkdir_fn = std_os.mkdir
    try:
        def wrapper(one_path, one_mode=0o777):  # pylint: disable=missing-docstring
            # Note, we need to provide the origin os.mkdir to our mkdir function,
            # or we will have a nice infinite loop ...
            mkdir(one_path, mode=one_mode, mkdir_fn=orig_mkdir_fn)

        std_os.mkdir = wrapper

        std_os.makedirs(file_path, mode)
    finally:
        std_os.mkdir = orig_mkdir_fn


def chmod(file_path, mode):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int) -> None
    """
    Wrapper of original os.chmod function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to modify
    :param int mode: POSIX mode to apply on file
    """
    security.apply_mode(file_path, mode)
