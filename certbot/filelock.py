"""Implements file locks for locking files and directories in UNIX and Windows."""
import errno
import logging
import os
try:
    import fcntl  # pylint: disable=import-error
    POSIX_MODE = True
except ImportError:
    import msvcrt  # pylint: disable=import-error
    POSIX_MODE = False

from certbot import errors
from acme.magic_typing import List, Optional  # pylint: disable=unused-import, no-name-in-module

logger = logging.getLogger(__name__)


# Unix locking mechanism
# ~~~~~~~~~~~~~~~~~~~~~~
class _UnixLockMechanism(object):
    """
    A UNIX lock file mechanism.

    This lock file is released when the locked file is closed or the
    process exits. It cannot be used to provide synchronization between
    threads. It is based on the lock_file package by Martin Horcicka.
    """

    def __init__(self, path):
        # type: (str) -> None
        """
        Create a lock file mechanism for Unix.
        :param str path: the path to the lock file
        """
        self._path = path
        self._fd = None  # type: Optional[int]

    def acquire(self):
        # type: () -> None
        """Acquire the lock."""
        while self._fd is None:
            # Open the file
            fd = os.open(self._path, os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                self._try_lock(fd)
                if self._lock_success(fd):
                    self._fd = fd
            finally:
                # Close the file if it is not the required one
                if self._fd is None:
                    os.close(fd)

    def _try_lock(self, fd):
        # type: (int) -> None
        """
        Try to acquire the lock file without blocking.
        :param int fd: file descriptor of the opened file to lock
        """
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as err:
            if err.errno in (errno.EACCES, errno.EAGAIN):
                logger.debug(
                    "A lock on %s is held by another process.", self._path)
                _raise_for_certbot_lock(self._path)
            raise

    def _lock_success(self, fd):
        # type: (int) -> bool
        """
        Did we successfully grab the lock?

        Because this class deletes the locked file when the lock is
        released, it is possible another process removed and recreated
        the file between us opening the file and acquiring the lock.

        :param int fd: file descriptor of the opened file to lock
        :returns: True if the lock was successfully acquired
        :rtype: bool
        """
        try:
            stat1 = os.stat(self._path)
        except OSError as err:
            if err.errno == errno.ENOENT:
                return False
            raise

        stat2 = os.fstat(fd)
        # If our locked file descriptor and the file on disk refer to
        # the same device and inode, they're the same file.
        return stat1.st_dev == stat2.st_dev and stat1.st_ino == stat2.st_ino

    def release(self):
        # type: () -> None
        """Remove, close, and release the lock file."""
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
            os.remove(self._path)
        finally:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def is_locked(self):
        # type: () -> bool
        """Check if lock file is currently locked.

        :return: True if the lock file is locked
        :rtype: bool
        """
        return self._fd is not None


# Windows locking mechanism
# ~~~~~~~~~~~~~~~~~~~~~~~~~
class _WindowsLockMechanism(object):
    """
    A Windows lock file mechanism.

    On Windows in general, access to a file is exclusive, so opening a file
    is an effective lock. This default behavior may be modified by an administrator,
    so we ensure correct behavior with msvcrt. Moreover on Windows a file can be removed
    only after it has been released: so the concurrency access that may occur on POSIX
    system is irrelevant here, leading to a quite simple code.
    """

    def __init__(self, path):
        # type: (str) -> None
        self._path = path
        self._fd = None

    def acquire(self):
        """Acquire the lock"""
        open_mode = os.O_RDWR | os.O_CREAT | os.O_TRUNC

        fd = os.open(self._path, open_mode, 0o600)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except (IOError, OSError):
            os.close(fd)
            _raise_for_certbot_lock(self._path)

        self._fd = fd

    def release(self):
        """Release the lock."""
        if self._fd:
            try:
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                os.close(self._fd)

                try:
                    os.remove(self._path)
                except OSError as e:
                    # If the lock file cannot be removed, it is not a big deal.
                    # Likely another instance is acquiring the lock we just released.
                    logger.debug(str(e))
            finally:
                self._fd = None

    def is_locked(self):
        # type: () -> bool
        """Check if lock file is currently lock.

        :return: True if the lock file is locked
        :rtype: bool
        """
        return self._fd is not None


# Filelock platform independent utility
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class FileLock(object):
    """
    Platform independent file lock system.

    FileLock accepts a parameter, the path to a file, and offers two main methods,
    acquire and release. Once acquire has been executed, the associated file is 'locked'
    from the point of view of the OS, meaning that if another instance of Certbot try at
    the same time to acquire the same lock, it will raise an Exception. Calling release
    method will release the lock, and make it available to every other instance.

    This allows to protect a file or a directory to be concurrently accessed and modified
    by two Certbot instances in parallel.

    FileLock is platform independent: it will proceed to the appropriate OS lock mechanism
    depending on Linux or Windows.

    Furthermore FileLock is a context manager. It can be used with the python `with` statement.
    In this case, lock will be automatically acquired when entering the context, and automatically
    released when exiting the context.
    """

    def __init__(self, path):
        # type: (str) -> None
        """
        Create a FileLock instance on the given file path.
        :param str path: the path to the file that will hold a lock
        """
        self._path = path
        mechanism = _UnixLockMechanism if POSIX_MODE else _WindowsLockMechanism
        self._lock_mechanism = mechanism(path)

    def __enter__(self):
        self._lock_mechanism.acquire()
        return True

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock_mechanism.release()

    def __repr__(self):
        # type: () -> str
        repr_str = '{0}({1}) <'.format(self.__class__.__name__, self._path)
        if self.is_locked():
            repr_str += 'released>'
        else:
            repr_str += 'acquired>'
        return repr_str

    def acquire(self):
        # type: () -> None
        """
        Acquire the lock on the file, forbidding any other Certbot instance to acquire it.
        :raises errors.LockError: if unable to acquire the lock
        """
        self._lock_mechanism.acquire()  # type: ignore

    def release(self):
        # type: () -> None
        """
        Release the lock on the file, allowing any other Certbot instance to acquire it.
        """
        if self.is_locked():
            self._lock_mechanism.release()  # type: ignore

    def is_locked(self):
        # type: () -> bool
        """
        Check if the file is currently locked.
        :return: True if the file is locked, False otherwise
        """
        return self._lock_mechanism.is_locked()  # type: ignore


# Utility functions
# ~~~~~~~~~~~~~~~~~


def lock_for_file(path):
    # type: (str) -> FileLock
    """
    Create a lock for a file.
    :param str path: the file path to lock
    :return: a FileLock instance
    """
    return FileLock('{0}.certbot.lock'.format(path))


def lock_for_dir(path):
    # type: (str) -> FileLock
    """
    Create a lock for a directory.
    :param str path: the directory path to lock
    :return: a FileLock instance
    """
    return FileLock(os.path.join(path, '.certbot.lock'))


def _raise_for_certbot_lock(lock_file_path):
    # type: (str) -> None
    """
    Raise a certbot error when lock file cannot be acquired.
    :param str lock_file_path: the path to the lock file
    """
    raise errors.LockError(
        'Error, the lock file "{0}" could not be acquired. '
        'It is likely that another Certbot instance is still running.'
        .format(lock_file_path))
