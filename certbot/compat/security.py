"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import os  # pylint: disable=os-module-forbidden
import stat
import tempfile

try:
    import pwd  # pylint: disable=import-error
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore
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

from acme.magic_typing import Callable  # pylint: disable=unused-import,no-name-in-module


def get_current_user():
    # type: () -> str
    """
    Get current username, in a platform independent way.
    :rtype: str
    :return: Current username.
    """
    if not win32api:
        # Module pwd is available on all Unix version,
        # so it will be here if we are not on Windows.
        return pwd.getpwuid(os.getuid()).pw_name

    # On Windows, for Certbot, what matters is not the user of current thread, but the owner of
    # files that are created in this thread.
    # Theses two values can be different, in particular in privileged shells, where typically will
    # be the user for win32api.GetUsername() (thread owner), and Administrators group (file owner).
    with tempfile.TemporaryFile() as probe:
        security = win32security.GetFileSecurity(
            probe.name, win32security.OWNER_SECURITY_INFORMATION)
        current_user = security.GetSecurityDescriptorOwner()

        return win32security.LookupAccountSid(None, current_user)[0]


def chmod(file_path, mode):
    # type: (str, int) -> None
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


def copy_ownership_and_apply_mode(src, dst, mode, user=True, group=False):
    # type: (str, str, int, bool, bool) -> None
    """
    Copy ownership (user and optionally group) from the source to the destination,
    then apply given mode in compatible way for Linux and Windows.

    NB: The copy_ownership() function does not exist, because on Windows, DACLs need to be
    recalculated after a change of ownership.

    :param str src: Path of the source file
    :param str dst: Path of the destination file
    :param int mode: Permission mode to apply on the destination file
    :param bool user: Copy user (True by default)
    :param bool group: Copy group (False by default)
    """
    if not win32security:
        stats = os.stat(src)
        user_id = stats.st_uid if user else -1
        group_id = stats.st_gid if group else -1
        os.chown(dst, user_id, group_id)
        os.chmod(dst, mode)
    elif user:
        # There is no group handling in Windows
        _copy_win_ownership(src, dst)
        _apply_win_mode(dst, mode)


def check_mode(file_path, mode):
    # type: (str, int) -> bool
    """
    Check if the given mode matches the permissions of the given file.
    On Linux, will make a direct comparison, on Windows, mode will be compared against
    the security model.

    :param str file_path: Path of the file
    :param int mode: POSIX mode to test
    :rtype: bool
    :return: True if the POSIX mode matches the file permissions
    """
    if not win32security:
        return stat.S_IMODE(os.stat(file_path).st_mode) == mode

    return _check_win_mode(file_path, mode)


def check_owner(file_path):
    # type: (str) -> bool
    """
    Check if given file is owner by current user.
    :param str file_path: File path to check
    :rtype: bool
    :return: True if given file is owned by current user, False otherwise.
    """
    if not win32security:
        return os.stat(file_path).st_uid == os.getuid()

    # Get owner sid of the file
    security = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
    user = security.GetSecurityDescriptorOwner()

    # Get current owner sid for files
    with tempfile.TemporaryFile() as probe:
        security = win32security.GetFileSecurity(probe.name,
                                                 win32security.OWNER_SECURITY_INFORMATION)
        current_user = security.GetSecurityDescriptorOwner()

        # Compare sids
        return str(current_user) == str(user)


def check_permissions(file_path, mode):
    # type: (str, int) -> bool
    """
    Check if given file has the given mode and is owned by current user.
    :param str file_path: File path to check
    :param int mode: POSIX mode to check
    :rtype: bool
    :return: True if file has correct mode and owner, False otherwise.
    """
    return check_owner(file_path) and check_mode(file_path, mode)


def _apply_win_mode(file_path, mode):
    # Resolve symbolic links
    if os.path.islink(file_path):
        link_path = file_path
        file_path = os.readlink(file_path)
        if not os.path.isabs(file_path):
            file_path = os.path.join(os.path.dirname(link_path), file_path)
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

    # If user is already system or admins, any ACE defined here would be superseeded by
    # the full control ACE that will be added after.
    if str(user_sid) not in [str(system), str(admins)]:
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


def _copy_win_ownership(src, dst):
    security_src = win32security.GetFileSecurity(src, win32security.OWNER_SECURITY_INFORMATION)
    user_src = security_src.GetSecurityDescriptorOwner()

    security_dst = win32security.GetFileSecurity(dst, win32security.OWNER_SECURITY_INFORMATION)
    security_dst.SetSecurityDescriptorOwner(user_src, False)

    win32security.SetFileSecurity(dst, win32security.OWNER_SECURITY_INFORMATION, security_dst)


def _check_win_mode(file_path, mode):
    # Resolve symbolic links
    if os.path.islink(file_path):
        link_path = file_path
        file_path = os.readlink(file_path)
        if not os.path.isabs(file_path):
            file_path = os.path.join(os.path.dirname(link_path), file_path)
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
    aces1 = [dacl1.GetAce(index) for index in range(0, dacl1.GetAceCount())]
    aces2 = [dacl2.GetAce(index) for index in range(0, dacl2.GetAceCount())]

    # Convert PySIDs into hashable objects
    aces1_refined = []
    aces2_refined = []
    for ace in aces1:
        if len(ace) == 3:
            aces1_refined.append((ace[0], ace[1], str(ace[2])))
        else:
            aces1_refined.append((ace[0], ace[1], ace[2], ace[3], str(ace[4])))  # type: ignore
    for index, ace in enumerate(aces2):
        if len(ace) == 3:
            aces2_refined.append((ace[0], ace[1], str(ace[2])))
        else:
            aces2_refined.append((ace[0], ace[1], ace[2], ace[3], str(ace[4])))  # type: ignore

    return set(aces1_refined) == set(aces2_refined)


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
                       ^ ntsecuritycon.FILE_GENERIC_EXECUTE
                       ^ 512)  # This bit is never set with file/directory objects
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


def open(file_path, flags, mode=0o777):  # pylint: disable=function-redefined,redefined-builtin
    # type: (str, int, int) -> int
    """
    Wrapper of original os.open function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int flags: Flags to apply on file while opened
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``

    :returns: the file descriptor to the opened file
    :rtype: int
    """
    file_descriptor = os.open(file_path, flags, mode)
    chmod(file_path, mode)

    return file_descriptor


def makedirs(file_path, mode=0o777):  # pylint: disable=function-redefined
    # type: (str, int) -> None
    """
    Wrapper of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    """
    # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
    # os module for the time of makedirs execution.
    orig_mkdir_fn = os.mkdir
    try:
        def wrapper(one_path, one_mode=0o777):  # pylint: disable=missing-docstring
            # Note, we need to provide the origin os.mkdir to our mkdir function,
            # or we will have a nice infinite loop ...
            mkdir(one_path, mode=one_mode, mkdir_fn=orig_mkdir_fn)

        os.mkdir = wrapper

        os.makedirs(file_path, mode)
    finally:
        os.mkdir = orig_mkdir_fn


def mkdir(file_path, mode=0o777, mkdir_fn=None):  # pylint: disable=function-redefined
    # type: (str, int, Callable[[str, int], None]) -> None
    """
    Wrapper of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :param callable mkdir_fn: The underlying mkdir function to use
    """
    mkdir_fn = mkdir_fn or os.mkdir

    mkdir_fn(file_path, mode)
    chmod(file_path, mode)
