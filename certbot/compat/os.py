"""
This compat modules extends native capabilities of core os module to handle correctly platform
specific operations (eg. chown, chmod, geuid).
This module is intended to replace standard os module throughout certbot projects (except acme)
"""
from __future__ import absolute_import

# Expose everything from standard os package to make current package a complete replacement of os.
from os import *  # pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin

import errno
import os as std_os

from certbot.compat import security


def geteuid():  # pylint: disable=function-redefined
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


def open(file, flags, mode=None):  # pylint: disable=function-redefined,redefined-builtin
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
    open_args = ()
    if mode:
        open_args = (mode,)

    file_descriptor = std_os.open(file, flags, *open_args)  # pylint: disable=star-args

    if mode:
        security.apply_mode(file, mode)

    return file_descriptor


def mkdir(file_path, mode=None, mkdir_fn=None):  # pylint: disable=function-redefined
    """
    Wrapper of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :param callable mkdir_fn: The undelying mkdir function to use
    """
    mkdir_fn = mkdir_fn or std_os.mkdir
    mkdir_args = ()
    if mode:
        mkdir_args = (mode,)

    mkdir_fn(file_path, *mkdir_args)  # pylint: disable=star-args

    if mode:
        security.apply_mode(file_path, mode)


def makedirs(file_path, mode=None):  # pylint: disable=function-redefined
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
        def wrapper(one_path, mode=None):  # pylint: disable=missing-docstring
            # Note, we need to provide the origin os.mkdir to our mkdir function,
            # or we will have a nice infinite loop ...
            mkdir(one_path, mode=mode, mkdir_fn=orig_mkdir_fn)

        std_os.mkdir = wrapper

        makedirs_args = ()
        if mode:
            makedirs_args = (mode,)

        std_os.makedirs(file_path, *makedirs_args)  # pylint: disable=star-args
    finally:
        std_os.mkdir = orig_mkdir_fn


def chmod(file_path, mode):  # pylint: disable=function-redefined
    """
    Wrapper of original os.chmod function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to modify
    :param int mode: POSIX mode to apply on file
    """
    security.apply_mode(file_path, mode)
