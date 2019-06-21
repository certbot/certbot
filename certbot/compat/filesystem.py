"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import errno
import os  # pylint: disable=os-module-forbidden
import stat

try:
    # pylint: disable=import-error
    import ntsecuritycon
    import win32security
    import win32file
    import win32api
    import pywintypes
    import winerror
    # pylint: enable=import-error
except ImportError:
    POSIX_MODE = True
else:
    POSIX_MODE = False

from acme.magic_typing import List, Callable  # pylint: disable=unused-import, no-name-in-module


def chmod(file_path, mode):
    # type: (str, int) -> None
    """
    Apply a POSIX mode on given file_path:
        * for Linux, the POSIX mode will be directly applied using chmod,
        * for Windows, the POSIX mode will be translated into a Windows DACL that make sense for
          Certbot context, and applied to the file using kernel calls.

    The definition of the Windows DACL that correspond to a POSIX mode, in the context of Certbot,
    is explained at https://github.com/certbot/certbot/issues/6356 and is implemented by the
    method _generate_windows_flags().

    :param str file_path: Path of the file
    :param int mode: POSIX mode to apply
    """
    if POSIX_MODE:
        os.chmod(file_path, mode)
    else:
        _apply_win_mode(file_path, mode)


# Funtion os.makedirs will temporarily monkeypatch os.mkdir to replace it by filesystem.mkdir.
# However, filesystem.mkdir also invokes os.mkdir. To avoid a looped reference, we take now a
# reference of the original os.mkdir, to use it in filesystem.mkdir.
_os_mkdir = os.mkdir


def makedirs(file_path, mode=0o777, exists_ok=False):
    # type: (str, int, bool) -> None
    """
    Rewrite of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on leaf directory when created, Python defaults
                     will be applied if ``None``
    :param bool exists_ok: If set to ``True``, do not raise exception if leaf directory
                           already exists.
    """
    # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
    # os module for the time of makedirs execution.
    orig_mkdir_fn = os.mkdir
    try:
        os.mkdir = mkdir  # type: ignore
        try:
            os.makedirs(file_path, mode)
        except (IOError, OSError) as err:
            # In case of exists_ok is True, and exception was about the path to already exist,
            # we ignore the exception.
            if not exists_ok or err.errno != errno.EEXIST:
                raise
    finally:
        os.mkdir = orig_mkdir_fn


def mkdir(file_path, mode=0o777):
    # type: (str, int) -> None
    """
    Rewrite of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on directory when created, Python defaults
                     will be applied if ``None``
    """
    if POSIX_MODE:
        _os_mkdir(file_path, mode)
    else:
        attributes = win32security.SECURITY_ATTRIBUTES()
        security = attributes.SECURITY_DESCRIPTOR
        user = _get_current_user()
        dacl = _generate_dacl(user, mode)
        security.SetSecurityDescriptorDacl(1, dacl, 0)

        try:
            win32file.CreateDirectory(file_path, attributes)
        except pywintypes.error as err:
            # Handle native windows error into python error to be consistent with the API
            # of os.mkdir in the situation of a directory already existing.
            if err.winerror == winerror.ERROR_ALREADY_EXISTS:
                raise OSError(errno.EEXIST, err.strerror)
            raise err


def replace(src, dst):
    # type: (str, str) -> None
    """
    Rename a file to a destination path and handles situations where the destination exists.
    :param str src: The current file path.
    :param str dst: The new file path.
    """
    if hasattr(os, 'replace'):
        # Use replace if possible. On Windows, only Python >= 3.4 is supported
        # so we can assume that os.replace() is always available for this platform.
        getattr(os, 'replace')(src, dst)
    else:
        # Otherwise, use os.rename() that behaves like os.replace() on Linux.
        os.rename(src, dst)


def _apply_win_mode(file_path, mode):
    """
    This function converts the given POSIX mode into a Windows ACL list, and applies it to the
    file given its path. If the given path is a symbolic link, it will resolved to apply the
    mode on the targeted file.
    """
    original_path = file_path
    inspected_paths = []  # type: List[str]
    while os.path.islink(file_path):
        link_path = file_path
        file_path = os.readlink(file_path)
        if not os.path.isabs(file_path):
            file_path = os.path.join(os.path.dirname(link_path), file_path)
        if file_path in inspected_paths:
            raise RuntimeError('Error, link {0} is a loop!'.format(original_path))
        inspected_paths.append(file_path)
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

    # Get standard accounts from "well-known" sid
    # See the list here:
    # https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
    system = win32security.ConvertStringSidToSid('S-1-5-18')
    admins = win32security.ConvertStringSidToSid('S-1-5-32-544')
    everyone = win32security.ConvertStringSidToSid('S-1-1-0')

    # New dacl, without inherited permissions
    dacl = win32security.ACL()

    # If user is already system or admins, any ACE defined here would be superseded by
    # the full control ACE that will be added after.
    if user_sid not in [system, admins]:
        # Handle user rights
        user_flags = _generate_windows_flags(analysis['user'])
        if user_flags:
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, user_flags, user_sid)

    # Handle everybody rights
    everybody_flags = _generate_windows_flags(analysis['all'])
    if everybody_flags:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, everybody_flags, everyone)

    # Handle administrator rights
    full_permissions = _generate_windows_flags({'read': True, 'write': True, 'execute': True})
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, full_permissions, system)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, full_permissions, admins)

    return dacl


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
    # (respectively ntsecuritycon.FILE_GENERIC_READ and ntsecuritycon.FILE_GENERIC_EXECUTE).
    #
    # But ntsecuritycon.FILE_GENERIC_WRITE does not correspond to what one could expect from a
    # write access on Linux: for Windows, FILE_GENERIC_WRITE does not include delete, move or
    # rename. This is something that requires ntsecuritycon.FILE_ALL_ACCESS.
    # So to reproduce the write right as POSIX, we will apply ntsecuritycon.FILE_ALL_ACCESS
    # substracted of the rights corresponding to POSIX read and POSIX execute.
    #
    # Finally, having read + write + execute gives a ntsecuritycon.FILE_ALL_ACCESS,
    # so a "Full Control" on the file.
    #
    # A complete list of the rights defined on NTFS can be found here:
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)#permissions-for-files-and-folders
    flag = 0
    if rights_desc['read']:
        flag = flag | ntsecuritycon.FILE_GENERIC_READ
    if rights_desc['write']:
        flag = flag | (ntsecuritycon.FILE_ALL_ACCESS
                       ^ ntsecuritycon.FILE_GENERIC_READ
                       ^ ntsecuritycon.FILE_GENERIC_EXECUTE
                       # Despite bit `512` being present in ntsecuritycon.FILE_ALL_ACCESS, it is
                       # not effectively applied to the file or the directory.
                       # As _generate_windows_flags is also used to compare two dacls, we remove
                       # it right now to have flags that contain only the bits effectively applied
                       # by Windows.
                       ^ 512)
    if rights_desc['execute']:
        flag = flag | ntsecuritycon.FILE_GENERIC_EXECUTE

    return flag


def _compare_dacls(dacl1, dacl2):
    """
    This method compare the two given DACLs to check if they are identical.
    Identical means here that they contains the same set of ACEs in the same order.
    """
    return ([dacl1.GetAce(index) for index in range(0, dacl1.GetAceCount())] ==
            [dacl2.GetAce(index) for index in range(0, dacl2.GetAceCount())])


def _get_current_user():
    """
    Return the pySID corresponding to the current user.
    """
    account_name = win32api.GetUserNameEx(win32api.NameSamCompatible)
    # Passing None to systemName instruct the lookup to start from the local system,
    # then continue the lookup to associated domain.
    # See https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-lookupaccountnamea
    return win32security.LookupAccountName(None, account_name)[0]
