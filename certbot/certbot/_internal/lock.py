"""Implements file locks compatible with Linux and Windows for locking files and directories."""
import errno
import logging

from acme.magic_typing import Optional
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os

try:
    import fcntl
except ImportError:
    import msvcrt
    POSIX_MODE = False
else:
    POSIX_MODE = True



logger = logging.getLogger(__name__)


def lock_dir(dir_path):
    # type: (str) -> LockFile
    """Place a lock file on the directory at dir_path.

    The lock file is placed in the root of dir_path with the name
    .certbot.lock.

    :param str dir_path: path to directory

    :returns: the locked LockFile object
    :rtype: LockFile

    :raises errors.LockError: if unable to acquire the lock

    """
    return LockFile(os.path.join(dir_path, '.certbot.lock'))


class LockFile(object):
    """
    Platform independent file lock system.
    LockFile accepts a parameter, the path to a file acting as a lock. Once the LockFile,
    instance is created, the associated file is 'locked from the point of view of the OS,
    meaning that if another instance of Certbot try at the same time to acquire the same lock,
    it will raise an Exception. Calling release method will release the lock, and make it
    available to every other instance.
    Upon exit, Certbot will also release all the locks.
    This allows us to protect a file or directory from being concurrently accessed
    or modified by two Certbot instances.
    LockFile is platform independent: it will proceed to the appropriate OS lock mechanism
    depending on Linux or Windows.
    """
    def __init__(self, path):
        # type: (str) -> None
        """
        Create a LockFile instance on the given file path, and acquire lock.
        :param str path: the path to the file that will hold a lock
        """
        self._path = path
        mechanism = _UnixLockMechanism if POSIX_MODE else _WindowsLockMechanism
        self._lock_mechanism = mechanism(path)

        self.acquire()

    def __repr__(self):
        # type: () -> str
        repr_str = '{0}({1}) <'.format(self.__class__.__name__, self._path)
        if self.is_locked():
            repr_str += 'acquired>'
        else:
            repr_str += 'released>'
        return repr_str

    def acquire(self):
        # type: () -> None
        """
        Acquire the lock on the file, forbidding any other Certbot instance to acquire it.
        :raises errors.LockError: if unable to acquire the lock
        """
        self._lock_mechanism.acquire()

    def release(self):
        # type: () -> None
        """
        Release the lock on the file, allowing any other Certbot instance to acquire it.
        """
        self._lock_mechanism.release()

    def is_locked(self):
        # type: () -> bool
        """
        Check if the file is currently locked.
        :return: True if the file is locked, False otherwise
        """
        return self._lock_mechanism.is_locked()


class _BaseLockMechanism(object):
    def __init__(self, path):
        # type: (str) -> None
        """
        Create a lock file mechanism for Unix.
        :param str path: the path to the lock file
        """
        self._path = path
        self._fd = None  # type: Optional[int]

    def is_locked(self):
        # type: () -> bool
        """Check if lock file is currently locked.
        :return: True if the lock file is locked
        :rtype: bool
        """
        return self._fd is not None

    def acquire(self):  # pylint: disable=missing-function-docstring
        pass  # pragma: no cover

    def release(self):  # pylint: disable=missing-function-docstring
        pass  # pragma: no cover


class _UnixLockMechanism(_BaseLockMechanism):
    """
    A UNIX lock file mechanism.
    This lock file is released when the locked file is closed or the
    process exits. It cannot be used to provide synchronization between
    threads. It is based on the lock_file package by Martin Horcicka.
    """
    def acquire(self):
        # type: () -> None
        """Acquire the lock."""
        while self._fd is None:
            # Open the file
            fd = filesystem.open(self._path, os.O_CREAT | os.O_WRONLY, 0o600)
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
                logger.debug('A lock on %s is held by another process.', self._path)
                raise errors.LockError('Another instance of Certbot is already running.')
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
        # Normally os module should not be imported in certbot codebase except in certbot.compat
        # for the sake of compatibility over Windows and Linux.
        # We make an exception here, since _lock_success is private and called only on Linux.
        from os import stat, fstat  # pylint: disable=os-module-forbidden
        try:
            stat1 = stat(self._path)
        except OSError as err:
            if err.errno == errno.ENOENT:
                return False
            raise

        stat2 = fstat(fd)
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
            # Following check is done to make mypy happy: it ensure that self._fd, marked
            # as Optional[int] is effectively int to make it compatible with os.close signature.
            if self._fd is None:  # pragma: no cover
                raise TypeError('Error, self._fd is None.')
            try:
                os.close(self._fd)
            finally:
                self._fd = None


class _WindowsLockMechanism(_BaseLockMechanism):
    """
    A Windows lock file mechanism.
    By default on Windows, acquiring a file handler gives exclusive access to the process
    and results in an effective lock. However, it is possible to explicitly acquire the
    file handler in shared access in terms of read and write, and this is done by os.open
    and io.open in Python. So an explicit lock needs to be done through the call of
    msvcrt.locking, that will lock the first byte of the file. In theory, it is also
    possible to access a file in shared delete access, allowing other processes to delete an
    opened file. But this needs also to be done explicitly by all processes using the Windows
    low level APIs, and Python does not do it. As of Python 3.7 and below, Python developers
    state that deleting a file opened by a process from another process is not possible with
    os.open and io.open.
    Consequently, mscvrt.locking is sufficient to obtain an effective lock, and the race
    condition encountered on Linux is not possible on Windows, leading to a simpler workflow.
    """
    def acquire(self):
        """Acquire the lock"""
        open_mode = os.O_RDWR | os.O_CREAT | os.O_TRUNC

        fd = None
        try:
            # Under Windows, filesystem.open will raise directly an EACCES error
            # if the lock file is already locked.
            fd = filesystem.open(self._path, open_mode, 0o600)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except (IOError, OSError) as err:
            if fd:
                os.close(fd)
            # Anything except EACCES is unexpected. Raise directly the error in that case.
            if err.errno != errno.EACCES:
                raise
            logger.debug('A lock on %s is held by another process.', self._path)
            raise errors.LockError('Another instance of Certbot is already running.')

        self._fd = fd

    def release(self):
        """Release the lock."""
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
