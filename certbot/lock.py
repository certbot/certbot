# $Id: lock_file.py 18 2007-10-24 04:47:12Z horcicka $

'''Lock file manipulation.

Lock file is a traditional means of synchronization among processes. In
this module it is implemented as an empty regular file exclusively
locked using fcntl.lockf. When it is to be released it is removed by
default. However, if all cooperating processes turn off the removal,
they get a guaranteed order of acquisitions and better scalability.

Example: Checking if at most one instance of the script is running

    import sys
    from lock_file import LockFile, LockError

    try:
        lock_f = LockFile('/var/run/app.lock')
    except LockError:
        sys.exit('The script is already running')

    try:
        do_something_useful()
    finally:
        lock_f.release()

Example: Waiting for the lock file acquisition

    from lock_file import LockFile

    lock_f = LockFile('/var/run/app.lock', wait = True)
    try:
        do_something_useful()
    finally:
        lock_f.release()

Example: Waiting for the lock file acquisition (in Python 2.5 and
higher)

    from __future__ import with_statement
    from lock_file import LockFile

    with LockFile('/var/run/app.lock', wait = True):
        do_something_useful()
'''

__all__ = 'LockError', 'LockFile'

import errno
import fcntl
import os


class LockError(Exception):
    '''Lock error.

    Raised when a lock file acquisition is unsuccessful because the lock
    file is held by another process.
    '''

    def __init__(self, message):
        Exception.__init__(self, message)


    def __repr__(self):
        return self.__class__.__name__ + '(' + repr(self.args[0]) + ')'


class LockFile(object):
    '''Lock file.

    This class represents an acquired lock file. After its releasing
    most methods lose their sense and raise a ValueError.
    '''

    def __init__(self, path, wait = False, remove = True):
        '''Initialize and acquire the lock file.

        Creates and locks the specified file. The wait argument can be
        set to True to wait until the lock file can be acquired. The
        remove argument can be set to False to keep the file after
        releasing.

        Raises LockError if the wait argument is False and the lock file
        is held by another process. Raises OSError or IOError if any
        other error occurs. In particular, raises IOError with the errno
        attribute set to errno.EINTR, if waiting for the acquisition is
        interrupted by a signal.
        '''

        object.__init__(self)
        self._path = path
        self._fd = None
        self._remove = remove

        # Acquire the lock file
        while self._fd is None:
            # Open the file
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0666)
            try:
                # Acquire an exclusive lock
                if wait:
                    fcntl.lockf(fd, fcntl.LOCK_EX)
                else:
                    try:
                        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except IOError, e:
                        if e.errno in (errno.EACCES, errno.EAGAIN):
                            raise LockError(
                                'Lock file is held by another process: '
                                + repr(self._path))
                        else:
                            raise

                # Check if the locked file is the required one (it could
                # have been removed and possibly recreated between the
                # opening and the lock acquisition)
                try:
                    stat1 = os.stat(path)
                except OSError, e:
                    if e.errno != errno.ENOENT:
                        raise
                else:
                    stat2 = os.fstat(fd)
                    if stat1.st_dev == stat2.st_dev \
                        and stat1.st_ino == stat2.st_ino:

                        self._fd = fd

            finally:
                # Close the file if it is not the required one
                if self._fd is None:
                    os.close(fd)


    def __enter__(self):
        if self._fd is None:
            raise ValueError('The lock file is released')

        return self


    def __repr__(self):
        repr_str = '<'
        if self._fd is None:
            repr_str += 'released'
        else:
            repr_str += 'acquired'

        repr_str += ' lock file ' + repr(self._path) + '>'
        return repr_str


    def get_path(self):
        if self._fd is None:
            raise ValueError('The lock file is released')

        return self._path


    def fileno(self):
        if self._fd is None:
            raise ValueError('The lock file is released')

        return self._fd


    def release(self):
        '''Release the lock file.

        Removes (optionally) and closes the lock file.

        Raises ValueError if the lock file is already released. Raises
        OSError if any other error occurs.
        '''

        if self._fd is None:
            raise ValueError('The lock file is already released')

        # Remove and close the file
        try:
            if self._remove:
                os.remove(self._path)
        finally:
            try:
                os.close(self._fd)
            finally:
                self._fd = None


    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
