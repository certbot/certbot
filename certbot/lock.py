"""Implements file locks for locking files and directories in UNIX."""
import errno
import fcntl
import logging
import os

from certbot import errors

logger = logging.getLogger(__name__)


def lock_dir(dir_path):
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
    """A UNIX lock file.

    This lock file is released when the locked file is closed or the
    process exits. It cannot be used to provide synchronization between
    threads. It is based on the lock_file package by Martin Horcicka.

    """
    def __init__(self, path):
        """Initialize and acquire the lock file.

        :param str path: path to the file to lock

        :raises errors.LockError: if unable to acquire the lock

        """
        super(LockFile, self).__init__()
        self._path = path
        self._fd = None

        self.acquire()

    def acquire(self):
        """Acquire the lock file.

        :raises errors.LockError: if lock is already held
        :raises OSError: if unable to open or stat the lock file

        """
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
        """Try to acquire the lock file without blocking.

        :param int fd: file descriptor of the opened file to lock

        """
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as err:
            if err.errno in (errno.EACCES, errno.EAGAIN):
                logger.debug(
                    "A lock on %s is held by another process.", self._path)
                raise errors.LockError(
                    "Another instance of Certbot is already running.")
            raise

    def _lock_success(self, fd):
        """Did we successfully grab the lock?

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

    def __repr__(self):
        repr_str = '{0}({1}) <'.format(self.__class__.__name__, self._path)
        if self._fd is None:
            repr_str += 'released>'
        else:
            repr_str += 'acquired>'
        return repr_str

    def release(self):
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
        #
        # Calling os.remove on a file that's in use doesn't work on
        # Windows, but neither does locking with fcntl.
        try:
            os.remove(self._path)
        finally:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
