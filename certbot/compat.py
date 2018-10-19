"""
Compatibility layer to run certbot both on Linux and Windows.

The approach used here is similar to Modernizr for Web browsers.
We do not check the platform type to determine if a particular logic is supported.
Instead, we apply a logic, and then fallback to another logic if first logic
is not supported at runtime.

Then logic chains are abstracted into single functions to be exposed to certbot.
"""
import os
import select
import sys
import ctypes
import stat

from certbot import errors

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

def compare_file_modes(mode1, mode2):
    """Return true if the two modes can be considered as equals for this platform"""
    if 'fcntl' in sys.modules:
        # Linux specific: standard compare
        return oct(stat.S_IMODE(mode1)) == oct(stat.S_IMODE(mode2))
    # Windows specific: most of mode bits are ignored on Windows. Only check user R/W rights.
    return (stat.S_IMODE(mode1) & stat.S_IREAD == stat.S_IMODE(mode2) & stat.S_IREAD
            and stat.S_IMODE(mode1) & stat.S_IWRITE == stat.S_IMODE(mode2) & stat.S_IWRITE)
