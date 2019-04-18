"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import os  # pylint: disable=os-module-forbidden

from acme.magic_typing import Callable  # pylint: disable=unused-import,no-name-in-module


def makedirs(file_path, mode=0o777):  # pylint: disable=function-redefined
    # type: (str, int) -> None
    """
    Wrapper of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    """
    # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
    # os module for the time of makedirs execution.
    orig_mkdir_fn = os.mkdir
    try:
        def wrapper(one_path, one_mode=0o777):  # pylint: disable=missing-docstring
            # Note, we need to provide the origin os.mkdir to our mkdir function,
            # or we will have a nice infinite loop ...
            mkdir(one_path, mode=one_mode, mkdir_fn=orig_mkdir_fn)

        os.mkdir = wrapper

        os.makedirs(file_path, mode)
    finally:
        os.mkdir = orig_mkdir_fn


def mkdir(file_path, mode=0o777, mkdir_fn=None):
    # type: (str, int, Callable[[str, int], None]) -> None
    """
    Wrapper of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :param callable mkdir_fn: The underlying mkdir function to use
    """
    mkdir_fn = mkdir_fn or os.mkdir

    mkdir_fn(file_path, mode)
    # TODO: Replace by security.chmod when all logic from windows files permissions is merged.
    os.chmod(file_path, mode)
