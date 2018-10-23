"""
Library to lock a directory or a file using a lockfile.
This implementation heavily relies on the work of benediktschmitt 
(https://github.com/benediktschmitt/py-filelock)
and should be considered as a fork of its project.
"""
import atexit
import logging
import os
import threading
try:
    import warnings
except ImportError:
    warnings = None  # type: ignore

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore

try:
    import fcntl
except ImportError:
    fcntl = None # type: ignore

from certbot import errors
from acme.magic_typing import List

logger = logging.getLogger(__name__)

# Handling exit
# ~~~~~~~~~~~~~
_INITIAL_PID = os.getpid()
_LOCKS = []  # type: List[FileLock]


def _release_all_locks():
    if _INITIAL_PID == os.getpid():
        for lock in _LOCKS:
            if lock.is_locked:
                try:
                    lock.release()
                    logger.debug('Lock released: %s', lock.lock_file)
                except (OSError, IOError):
                    logger.error('Exception occurred releasing lock: %s',
                                 lock.lock_file, exc_info=True)


atexit.register(_release_all_locks)

# Classes
# ------------------------------------------------


class BaseFileLock(object):
    """
    Implements the base class of a file lock.
    """

    def __init__(self, lock_file):
        """
        Create a new Lock. Note that this lock is set to be release when program exit.
        """
        # The path to the lock file.
        self._lock_file = lock_file

        # The file descriptor for the *_lock_file* as it is returned by the
        # os.open() function.
        # This file lock is only NOT None, if the object currently holds the
        # lock.
        self._lock_file_fd = None

        # We use this lock primarily for the lock counter.
        self._thread_lock = threading.Lock()

        # The lock counter is used for implementing the nested locking
        # mechanism. Whenever the lock is acquired, the counter is increased and
        # the lock is only released, when this value is 0 again.
        self._lock_counter = 0

        # Pass itelf to the _LOCK global variable to ensure that all locks are
        # released at least when the program exit.
        _LOCKS.append(self)

    @property
    def lock_file(self):
        """
        The path to the lock file.
        """
        return self._lock_file

    # Platform dependent locking
    # --------------------------------------------

    def _acquire(self):
        """
        Platform dependent. If the file lock could be
        acquired, self._lock_file_fd holds the file descriptor
        of the lock file.
        """
        raise NotImplementedError()

    def _release(self):
        """
        Releases the lock and sets self._lock_file_fd to None.
        """
        raise NotImplementedError()

    # Platform independent methods
    # --------------------------------------------

    @property
    def is_locked(self):
        """
        True, if the object holds the file lock.
        .. versionchanged:: 2.0.0
            This was previously a method and is now a property.
        """
        return self._lock_file_fd is not None

    def acquire(self):
        """
        Acquires the file lock or fails with a :exc:`Timeout` error.
        .. code-block:: python
            # You can use this method in the context manager (recommended)
            with lock.acquire():
                pass
            # Or use an equivalent try-finally construct:
            lock.acquire()
            try:
                pass
            finally:
                lock.release()
        """
        # Increment the number right at the beginning.
        # We can still undo it, if something fails.
        with self._thread_lock:
            self._lock_counter += 1

        lock_id = id(self)
        lock_filename = self._lock_file

        try:
            with self._thread_lock:
                if not self.is_locked:
                    logger.debug('Attempting to acquire lock %s on %s', lock_id, lock_filename)
                    self._acquire()

            if self.is_locked:
                logger.info('Lock %s acquired on %s', lock_id, lock_filename)
            else:
                raise errors.LockError((
                    'Error, the filelock "{0}" could not be acquired. '
                    'It is likely that another Certbot instance is still running.'
                    .format(self.lock_file)))
        except (OSError, IOError):
            # Something did go wrong, so decrement the counter.
            with self._thread_lock:
                self._lock_counter = max(0, self._lock_counter - 1)

            raise

        # This class wraps the lock to make sure __enter__ is not called
        # twice when entering the with statement.
        # If we would simply return *self*, the lock would be acquired again
        # in the *__enter__* method of the BaseFileLock, but not released again
        # automatically.
        class ReturnProxy(object):

            def __init__(self, lock):
                self.lock = lock

            def __enter__(self):
                return self.lock

            def __exit__(self, exc_type, exc_value, traceback):
                self.lock.release()
                return None

        return ReturnProxy(lock=self)

    def release(self, force=False):
        """
        Releases the file lock.
        Please note, that the lock is only completely released, if the lock
        counter is 0.
        Also note, that the lock file itself is not automatically deleted.
        :arg bool force:
            If true, the lock counter is ignored and the lock is released in
            every case.
        """
        with self._thread_lock:

            if self.is_locked:
                self._lock_counter -= 1

                if self._lock_counter == 0 or force:
                    lock_id = id(self)
                    lock_filename = self._lock_file

                    logger.debug('Attempting to release lock %s on %s', lock_id, lock_filename)
                    self._release()
                    self._lock_counter = 0
                    logger.info('Lock %s released on %s', lock_id, lock_filename)

        return None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        return None

    def __del__(self):
        self.release(force=True)
        return None

# Windows locking mechanism
# ~~~~~~~~~~~~~~~~~~~~~~~~~


class WindowsFileLock(BaseFileLock):
    """
    Uses the :func:`msvcrt.locking` function to hard lock the lock file on
    windows systems.
    """

    def _acquire(self):
        open_mode = os.O_RDWR | os.O_CREAT | os.O_TRUNC

        try:
            fd = os.open(self._lock_file, open_mode)
        except OSError:
            pass
        else:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except (IOError, OSError):
                os.close(fd)
            else:
                self._lock_file_fd = fd
        return None

    def _release(self):
        fd = self._lock_file_fd
        self._lock_file_fd = None
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        os.close(fd)

        try:
            os.remove(self._lock_file)
        # Probably another instance of the application
        # that acquired the file lock.
        except OSError:
            pass
        return None

# Unix locking mechanism
# ~~~~~~~~~~~~~~~~~~~~~~


class UnixFileLock(BaseFileLock):
    """
    Uses the :func:`fcntl.flock` to hard lock the lock file on unix systems.
    """

    def _acquire(self):
        open_mode = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        fd = os.open(self._lock_file, open_mode)

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError):
            os.close(fd)
        else:
            self._lock_file_fd = fd
        return None

    def _release(self):
        # It is important the lock file is removed before it's released,
        # otherwise:
        #
        # process A: open lock file
        # process B: release lock file
        # process A: lock file
        # process A: check device and inode
        # process B: delete file
        # process C: open and lock a different file at the same path
        fd = self._lock_file_fd
        self._lock_file_fd = None
        try:
            os.remove(self.lock_file)
            fcntl.flock(fd, fcntl.LOCK_UN)
        # The file is already deleted and that's what we want.
        except OSError:
            pass
        finally:
            os.close(fd)
        return None

# Soft lock
# ~~~~~~~~~


class SoftFileLock(BaseFileLock):
    """
    Simply watches the existence of the lock file.
    """

    def _acquire(self):
        open_mode = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC
        try:
            fd = os.open(self._lock_file, open_mode)
        except (IOError, OSError):
            pass
        else:
            self._lock_file_fd = fd
        return None

    def _release(self):
        os.close(self._lock_file_fd)
        self._lock_file_fd = None

        try:
            os.remove(self._lock_file)
        # The file is already deleted and that's what we want.
        except OSError:
            pass
        return None


# Platform filelock
# ~~~~~~~~~~~~~~~~~

#: Alias for the lock, which should be used for the current platform. On
#: Windows, this is an alias for :class:`WindowsFileLock`, on Unix for
#: :class:`UnixFileLock` and otherwise for :class:`SoftFileLock`.
def FileLock(*args, **kwargs):
    if msvcrt:
        return WindowsFileLock(*args, **kwargs)
    elif fcntl:
        return UnixFileLock(*args, **kwargs)
    else:
        if warnings:
            warnings.warn("Only soft file lock is available")
        return SoftFileLock(*args, **kwargs)


# Utility functions
# ~~~~~~~~~~~~~~~~~


def lock_for_file(path):
    """Create a lockfile for a file"""
    return FileLock('{0}.certbot.lock'.format(path))  # mypy: ignore


def lock_for_dir(path):
    """Create a lockfile for a dir"""
    return FileLock(os.path.join(path, '.certbot.lock'))  # mypy: ignore
