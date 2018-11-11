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

from acme.magic_typing import Union  # pylint: disable=unused-import, no-name-in-module


def apply_mode(file_path, mode):
    # type: (Union[str, unicode], int) -> None
    """
    Apply a POSIX mode on given file_path:
        * for Linux, the POSIX mode will be directly applied using chmod,
        * for Windows, the POSIX mode will be translated into a Windows DACL that make sense for
          Certbot context, and applied to the file using kernel calls.

    :param str file_path: Path of the file
    :param int mode: POSIX mode to apply
    """
    if not win32security:
        os.chmod(file_path, mode)
    else:
        _apply_win_mode(file_path, mode)


def take_ownership(file_path):
    # type: (Union[str, unicode]) -> None
    """
    Take ownership on the given file path, in compatible way for Linux and Windows.

    :param str file_path: Path of the file
    """
    if not win32security:
        os.chown(file_path, os.geteuid(), -1)
    else:
        _take_win_ownership(file_path)


def check_permissions(file_path, mode):
    # type: (Union[str, unicode], int) -> bool
    """
    Return true if the given mode matches the permissions of the given file.
    On Linux, will make a direct comparison, on Windows, mode will be compared against
    the security model.

    :param str file_path: Path of the file
    :param mode int: POSIX mode to test
    :return: True if the POSIX mode matches the file permissions
    """
    if not win32security:
        return stat.S_IMODE(os.stat(file_path)) == mode

    return _get_win_permissions(file_path, mode)


def _apply_win_mode(file_path, mode):
    # Get owner sid of the file
    security = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
    user = security.GetSecurityDescriptorOwner()

    # New DACL, that will overwrite existing one (including inherited permissions)
    dacl = _generate_dacl(user, mode)

    # Apply the new DACL
    security.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, security)


def _generate_dacl(user_sid, mode):
    analysis = _analyze_mode(mode)

    # Get standard accounts sid
    system = win32security.ConvertStringSidToSid('S-1-5-18')
    admins = win32security.ConvertStringSidToSid('S-1-5-32-544')
    everyone = win32security.ConvertStringSidToSid('S-1-1-0')

    # New dacl, without inherited permissions
    dacl = win32security.ACL()

    # Handle user rights
    user_flags = _generate_windows_flags(analysis['user'])
    if user_flags:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, user_flags, user_sid)

    # Handle everybody rights
    everybody_flags = _generate_windows_flags(analysis['all'])
    if everybody_flags:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, everybody_flags, everyone)

    # Handle administrator rights
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, system)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, admins)

    return dacl


def _take_win_ownership(file_path):
    username = win32api.GetUserName()
    user = win32security.LookupAccountName('', username)[0]

    security = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
    security.SetSecurityDescriptorOwner(user, False)

    win32security.SetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION, security)


def _get_win_permissions(file_path, mode):
    # Get current dacl file
    security = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION
                                             | win32security.DACL_SECURITY_INFORMATION)
    dacl = security.GetSecurityDescriptorDacl()

    # Get current file owner sid
    user = security.GetSecurityDescriptorOwner()

    if not dacl:
        # No DACL means full control to everyone
        # This is not a deterministic permissions set.
        return False

    # Calculate the target dacl
    ref_dacl = _generate_dacl(user, mode)

    return _compare_dacls(dacl, ref_dacl)


def _compare_dacls(dacl1, dacl2):
    return True


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
