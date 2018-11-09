"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import os
import stat

try:
    import ntsecuritycon  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    ntsecuritycon = None  # type: ignore

try:
    import win32security  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    win32security = None  # type: ignore

try:
    import win32api  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    win32api = None  # type: ignore

def apply_mode(filepath, mode):
    """
    Apply a POSIX mode on given filepath:
        * for Linux, the POSIX mode will be directly applied using chmod,
        * for Windows, the POSIX mode will be translated into a Windows DACL that make sense for
          Certbot context, and applied to the file using kernel calls.

    :param str filename: Path of the file
    :param octal mode: POSIX mode to apply
    """
    if not win32security:
        os.chmod(filepath, mode)
    else:
        _apply_win_mode(filepath, mode)

def take_ownership(filepath):
    """
    Take ownership on the given filepath, in compatible way for Linux and Windows.

    :param str filepath: Path of the file
    """
    if not win32security:
        os.chown(os.geteuid(), -1)  # pylint: disable=no-member
    else:
        _take_win_ownership(filepath)

def _apply_win_mode(filepath, mode):
    analysis = _analyze_mode(mode)

    # Get owner sid of the file
    security = win32security.GetFileSecurity(filepath, win32security.OWNER_SECURITY_INFORMATION)
    user = security.GetSecurityDescriptorOwner()

    # Get standard accounts sid
    system = win32security.ConvertStringSidToSid('S-1-5-18')
    admins = win32security.ConvertStringSidToSid('S-1-5-32-544')
    everyone = win32security.ConvertStringSidToSid('S-1-1-0')

    # New dacl, that will overwrite existing one (including inherited permissions)
    dacl = win32security.ACL()

    # Handle user rights
    user_flags = _generate_windows_flags(analysis['user'])
    if user_flags:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, user_flags, user)

    # Handle everybody rights
    everybody_flags = _generate_windows_flags(analysis['all'])
    if everybody_flags:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, everybody_flags, everyone)

    # Handle administrator rights
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, admins)

    # Apply the new DACL
    security.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(filepath, win32security.DACL_SECURITY_INFORMATION, security)

def _take_win_ownership(filepath):
    username = win32api.GetUserName()
    user = win32security.LookupAccountName('', username)[0]

    security = win32security.GetFileSecurity(filepath, win32security.OWNER_SECURITY_INFORMATION)
    security.SetSecurityDescriptorOwner(user, False)

    win32security.SetFileSecurity(filepath, win32security.OWNER_SECURITY_INFORMATION, security)

def _analyze_mode(mode):
    return {
        'user': {
            'read': mode & stat.S_IRUSR,
            'write': mode & stat.S_IWUSR,
            'execute': mode & stat.S_IXUSR,
        },
        'all': {
            'read': mode & stat.S_IROTH,
            'write': mode & stat.S_IWOTH,
            'execute': mode & stat.S_IXOTH,
        },
    }

def _generate_windows_flags(rights_desc):
    # Some notes about how each POSIX right is interpreted.
    #
    # For the rights read and execute, we have a pretty bijective relation between
    # POSIX flags and their generic counterparts on Windows, so we use them directly
    # (respectively ntsecuritycon.GENERIC_READ) and (respectively ntsecuritycon.GENERIC_EXECUTE).
    #
    # But ntsecuritycon.GENERIC_WRITE does not correspond to what one could expect from a write
    # access on Linux: for Windows, GENERIC_WRITE does not include delete, move or
    # rename. This is something that requires ntsecuritycon.GENERIC_ALL.
    # So to reproduce the write right as POSIX, we will apply ntsecuritycon.GENERIC_ALL
    # substracted of the rights corresponding to POSIX read and POSIX execute.
    #
    # Finally, having read + write + execute gives a ntsecuritycon.GENERIC_ALL,
    # so a full control of the file.
    flag = 0
    if rights_desc['read']:
        flag = flag | ntsecuritycon.FILE_GENERIC_READ
    if rights_desc['write']:
        flag = flag | (ntsecuritycon.FILE_ALL_ACCESS
                       ^ ntsecuritycon.FILE_GENERIC_READ
                       ^ ntsecuritycon.FILE_GENERIC_EXECUTE)
    if rights_desc['execute']:
        flag = flag | ntsecuritycon.FILE_GENERIC_EXECUTE
    return flag
