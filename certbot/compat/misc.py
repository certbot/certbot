"""
This compat module handles various platform specific calls that do not fall into one
particular category.
"""
import ctypes
import errno
import select
import stat
import sys

from certbot import errors
from certbot.compat import os

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
    # So we access windll only by reflection to trick these engines.
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


def os_rename(src, dst):
    """
    Rename a file to a destination path and handles situations where the destination exists.

    :param str src: The current file path.
    :param str dst: The new file path.
    """
    try:
        os.rename(src, dst)
    except OSError as err:
        # Windows specific, renaming a file on an existing path is not possible.
        # On Python 3, the best fallback with atomic capabilities we have is os.replace.
        if err.errno != errno.EEXIST:
            # Every other error is a legitimate exception.
            raise
        if not hasattr(os, 'replace'):  # pragma: no cover
            # We should never go on this line. Either we are on Linux and os.rename has succeeded,
            # or we are on Windows, and only Python >= 3.4 is supported where os.replace is
            # available.
            raise RuntimeError('Error: tried to run os_rename on Python < 3.3. '
                               'Certbot supports only Python 3.4 >= on Windows.')
        getattr(os, 'replace')(src, dst)


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


def compare_file_modes(mode1, mode2):
    """Return true if the two modes can be considered as equals for this platform"""
    if os.name != 'nt':
        # Linux specific: standard compare
        return oct(stat.S_IMODE(mode1)) == oct(stat.S_IMODE(mode2))
    # Windows specific: most of mode bits are ignored on Windows. Only check user R/W rights.
    return (stat.S_IMODE(mode1) & stat.S_IREAD == stat.S_IMODE(mode2) & stat.S_IREAD
            and stat.S_IMODE(mode1) & stat.S_IWRITE == stat.S_IMODE(mode2) & stat.S_IWRITE)


WINDOWS_DEFAULT_FOLDERS = {
    'config': 'C:\\Certbot',
    'work': 'C:\\Certbot\\lib',
    'logs': 'C:\\Certbot\\log',
}
LINUX_DEFAULT_FOLDERS = {
    'config': '/etc/letsencrypt',
    'work': '/var/lib/letsencrypt',
    'logs': '/var/log/letsencrypt',
}


def get_default_folder(folder_type):
    """
    Return the relevant default folder for the current OS

    :param str folder_type: The type of folder to retrieve (config, work or logs)

    :returns: The relevant default folder.
    :rtype: str

    """
    if os.name != 'nt':
        # Linux specific
        return LINUX_DEFAULT_FOLDERS[folder_type]
    # Windows specific
    return WINDOWS_DEFAULT_FOLDERS[folder_type]


def underscores_for_unsupported_characters_in_path(path):
    # type: (str) -> str
    """
    Replace unsupported characters in path for current OS by underscores.
    :param str path: the path to normalize
    :return: the normalized path
    :rtype: str
    """
    if os.name != 'nt':
        # Linux specific
        return path

    # Windows specific
    drive, tail = os.path.splitdrive(path)
    return drive + tail.replace(':', '_')
