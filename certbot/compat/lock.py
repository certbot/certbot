"""
This compat modules handle platform specific calls to lock files.
It is deprecated and will be removed once new lock file mechanism is integrated.
"""
from __future__ import absolute_import

import errno
import sys

from certbot.compat import os

try:
    # Linux specific
    import fcntl  # pylint: disable=import-error
except ImportError:
    # Windows specific
    import msvcrt  # pylint: disable=import-error


def lock_file(file_descriptor):
    """
    Lock the file linked to the specified file descriptor.

    :param int file_descriptor: The file descriptor of the file to lock.

    """
    if 'fcntl' in sys.modules:
        # Linux specific
        fcntl.lockf(file_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        # Windows specific
        msvcrt.locking(file_descriptor, msvcrt.LK_NBLCK, 1)


def release_locked_file(file_descriptor, path):
    """
    Remove, close, and release a lock file specified by its file descriptor and its path.

    :param int file_descriptor: The file descriptor of the lock file.
    :param str path: The path of the lock file.

    """
    # Linux specific
    #
    # It is important the lock file is removed before it's released,
    # otherwise:
    #
    # process A: open lock file
    # process B: release lock file
    # process A: lock file
    # process A: check device and inode
    # process B: delete file
    # process C: open and lock a different file at the same path
    try:
        os.remove(path)
    except OSError as err:
        if err.errno == errno.EACCES:
            # Windows specific
            # We will not be able to remove a file before closing it.
            # To avoid race conditions described for Linux, we will not delete the lockfile,
            # just close it to be reused on the next Certbot call.
            pass
        else:
            raise
    finally:
        os.close(file_descriptor)
