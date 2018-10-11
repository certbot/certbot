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

UNPRIVILEGED_SUBCOMMANDS_ALLOWED = [
    'certificates', 'enhance', 'revoke', 'delete',
    'register', 'unregister', 'config_changes', 'plugins']
def raise_for_non_administrative_windows_rights(subcommand):
    """
    On Windows, raise if current shell does not have the administrative rights.
    Do nothing on Linux.

    :param str subcommand: The subcommand (like 'certonly') passed to the certbot client.

    :raises .errors.Error: If the provided subcommand must be run on a shell with
        administrative rights, and current shell does not have these rights.

    """
    # Why not simply try ctypes.windll.shell32.IsUserAnAdmin() and catch AttributeError ?
    # Because windll exists only on a Windows runtime, and static code analysis engines
    # do not like at all non existent objects when run from Linux (even if we handle properly
    # all the cases in the code).
    # So we access windll only by reflection to trick theses engines.
    if hasattr(ctypes, 'windll') and subcommand not in UNPRIVILEGED_SUBCOMMANDS_ALLOWED:
        windll = getattr(ctypes, 'windll')
        if windll.shell32.IsUserAnAdmin() == 0:
            raise errors.Error(
                'Error, "{0}" subcommand must be run on a shell with administrative rights.'
                .format(subcommand))

def os_geteuid():
    """
    Get current user uid

    :returns: The current user uid.
    :rtype: int

    """
    try:
        # Linux specific
        return os.geteuid()
    except AttributeError:
        # Windows specific
        return 0

def readline_with_timeout(timeout, prompt):
    """
    Read user input to return the first line entered, or raise after specified timeout.

    :param float timeout: The timeout in seconds given to the user.
    :param str prompt: The prompt message to display to the user.

    :returns: The first line entered by the user.
    :rtype: str

    """
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
    """
    Lock the file linked to the specified file descriptor.

    :param int fd: The file descriptor of the file to lock.

    """
    if 'fcntl' in sys.modules:
        # Linux specific
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        # Windows specific
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

def release_locked_file(fd, path):
    """
    Remove, close, and release a lock file specified by its file descriptor and its path.

    :param int fd: The file descriptor of the lock file.
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
        os.close(fd)

WINDOWS_DEFAULT_FOLDERS = {
    'config': 'C:\\letsencrypt',
    'workdir': 'C:\\letsencrypt\\lib',
    'logs': 'C:\\letsencrypt\\log',
}
LINUX_DEFAULT_FOLDERS = {
    'config': '/etc/letsencrypt',
    'workdir': '/var/letsencrypt/lib',
    'logs': '/var/letsencrypt/log',
}
def get_default_folder(folder_type):
    """
    Return the relevant default folder for the current OS

    :param str folder_type: The type of folder to retrieve (config, workdir or logs)

    :returns: The relevant default folder.
    :rtype: str

    """
    if 'fcntl' in sys.modules:
        # Linux specific
        return LINUX_DEFAULT_FOLDERS[folder_type]
    # Windows specific
    return WINDOWS_DEFAULT_FOLDERS[folder_type]
