"""
Compatibility layer to run certbot both on Linux and Windows.

The approach used here is similar to Modernizr for Web browsers.
We do not check the plateform type to determine if a particular logic is supported.
Instead, we apply a logic, and then fallback to another logic if first logic
is not supported at runtime.

Then logic chains are abstracted into single functions to be exposed to certbot.
"""
import os
import select
import sys
import errno
import ctypes

from certbot import errors

try:
    # Linux specific
    import fcntl # pylint: disable=import-error
except ImportError:
    # Windows specific
    import msvcrt # pylint: disable=import-error

def raise_for_non_administrative_windows_user():
    on_windows = False
    try:
        os.geteuid()
    except AttributeError:
        on_windows = True
        pass

    # Windows specific
    if on_windows and ctypes.windll.shell32.IsUserAnAdmin() == 0:
        raise ValueError('Error, certbot must be run on a shell with administrative rights.')

def os_geteuid():
    """Get current user uid"""
    try:
        # Linux specific
        return os.geteuid()
    except AttributeError:
        # Windows specific
        return '0'

def readline_with_timeout(timeout, prompt):
    """Read user input to return the first line entered, or raise after specified timeout"""
    try:
        # Linux specific
        #
        # Call to select can only be done like this on UNIX
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if not rlist:
            raise errors.Error(
                "Timed out waiting for answer to prompt '{0}'".format(prompt))
        return rlist[0].readline()
    except OSError:
        # Windows specific
        #
        # No way with select to make a timeout to the user input on Windows,
        # as select only supports socket in this case.
        # So no timeout on Windows for now.
        return sys.stdin.readline()

def lock_file(fd):
    """Lock the file linked to the specified file descriptor"""
    if 'fcntl' in sys.modules:
        # Linux specific
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        # Windows specific
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

def release_locked_file(fd, path):
    """Remove, close, and release a lock file specified by its file descriptor and its path."""
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
        if err.errno in (errno.EACCES, errno.EPERM):
            # Windows specific
            #
            # On Windows we cannot remove a file before closing its file descriptor.
            # So we close first, and be exposed to the concurrency problem
            # described in Linux section.
            os.close(fd)
            os.remove(path)
        else:
            raise
    finally:
        try:
            os.close(fd)
        except OSError:
            # File descriptor already closed
            pass
