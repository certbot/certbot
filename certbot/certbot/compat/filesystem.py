"""Compat module to handle files security on Windows and Linux"""
from __future__ import absolute_import

import errno
import os  # pylint: disable=os-module-forbidden
import stat

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module
from acme.magic_typing import Tuple  # pylint: disable=unused-import, no-name-in-module
from acme.magic_typing import Union  # pylint: disable=unused-import, no-name-in-module

try:
    # pylint: disable=import-error
    import ntsecuritycon
    import win32security
    import win32con
    import win32api
    import win32file
    import pywintypes
    import winerror
    # pylint: enable=import-error
except ImportError:
    POSIX_MODE = True
else:
    POSIX_MODE = False


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


# One could ask why there is no copy_ownership() function, or even a reimplementation
# of os.chown() that would modify the ownership of file without touching the mode itself.
# This is because on Windows, it would require recalculating the existing DACL against
# the new owner, since the DACL is composed of ACEs that targets a specific user, not dynamically
# the current owner of a file. This action would be necessary to keep consistency between
# the POSIX mode applied to the file and the current owner of this file.
# Since copying and editing arbitrary DACL is very difficult, and since we actually know
# the mode to apply at the time the owner of a file should change, it is easier to just
# change the owner, then reapply the known mode, as copy_ownership_and_apply_mode() does.
def copy_ownership_and_apply_mode(src, dst, mode, copy_user, copy_group):
    # type: (str, str, int, bool, bool) -> None
    """
    Copy ownership (user and optionally group on Linux) from the source to the
    destination, then apply given mode in compatible way for Linux and Windows.
    This replaces the os.chown command.
    :param str src: Path of the source file
    :param str dst: Path of the destination file
    :param int mode: Permission mode to apply on the destination file
    :param bool copy_user: Copy user if `True`
    :param bool copy_group: Copy group if `True` on Linux (has no effect on Windows)
    """
    if POSIX_MODE:
        stats = os.stat(src)
        user_id = stats.st_uid if copy_user else -1
        group_id = stats.st_gid if copy_group else -1
        # On Windows, os.chown does not exist. This is checked through POSIX_MODE value,
        # but MyPy/PyLint does not know it and raises an error here on Windows.
        # We disable specifically the check to fix the issue.
        os.chown(dst, user_id, group_id)
    elif copy_user:
        # There is no group handling in Windows
        _copy_win_ownership(src, dst)

    chmod(dst, mode)


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
    if POSIX_MODE:
        return stat.S_IMODE(os.stat(file_path).st_mode) == mode

    return _check_win_mode(file_path, mode)


def check_owner(file_path):
    # type: (str) -> bool
    """
    Check if given file is owned by current user.
    :param str file_path: File path to check
    :rtype: bool
    :return: True if given file is owned by current user, False otherwise.
    """
    if POSIX_MODE:
        # On Windows, os.getuid does not exist. This is checked through POSIX_MODE value,
        # but MyPy/PyLint does not know it and raises an error here on Windows.
        # We disable specifically the check to fix the issue.
        return os.stat(file_path).st_uid == os.getuid()  # type: ignore

    # Get owner sid of the file
    security = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
    user = security.GetSecurityDescriptorOwner()

    # Compare sids
    return _get_current_user() == user


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


def open(file_path, flags, mode=0o777):  # pylint: disable=redefined-builtin
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
    :raise: OSError(errno.EEXIST) if the file already exists and os.O_CREAT & os.O_EXCL are set,
            OSError(errno.EACCES) on Windows if the file already exists and is a directory, and
                os.O_CREAT is set.
    """
    if POSIX_MODE:
        # On Linux, invoke os.open directly.
        return os.open(file_path, flags, mode)

    # Windows: handle creation of the file atomically with proper permissions.
    if flags & os.O_CREAT:
        # If os.O_EXCL is set, we will use the "CREATE_NEW", that will raise an exception if
        # file exists, matching the API contract of this bit flag. Otherwise, we use
        # "CREATE_ALWAYS" that will always create the file whether it exists or not.
        disposition = win32con.CREATE_NEW if flags & os.O_EXCL else win32con.CREATE_ALWAYS

        attributes = win32security.SECURITY_ATTRIBUTES()
        security = attributes.SECURITY_DESCRIPTOR
        user = _get_current_user()
        dacl = _generate_dacl(user, mode)
        # We set second parameter to 0 (`False`) to say that this security descriptor is
        # NOT constructed from a default mechanism, but is explicitly set by the user.
        # See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptorowner  # pylint: disable=line-too-long
        security.SetSecurityDescriptorOwner(user, 0)
        # We set first parameter to 1 (`True`) to say that this security descriptor contains
        # a DACL. Otherwise second and third parameters are ignored.
        # We set third parameter to 0 (`False`) to say that this security descriptor is
        # NOT constructed from a default mechanism, but is explicitly set by the user.
        # See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptordacl  # pylint: disable=line-too-long
        security.SetSecurityDescriptorDacl(1, dacl, 0)

        handle = None
        try:
            handle = win32file.CreateFile(file_path, win32file.GENERIC_READ,
                                          win32file.FILE_SHARE_READ & win32file.FILE_SHARE_WRITE,
                                          attributes, disposition, 0, None)
        except pywintypes.error as err:
            # Handle native windows errors into python errors to be consistent with the API
            # of os.open in the situation of a file already existing or locked.
            if err.winerror == winerror.ERROR_FILE_EXISTS:
                raise OSError(errno.EEXIST, err.strerror)
            if err.winerror == winerror.ERROR_SHARING_VIOLATION:
                raise OSError(errno.EACCES, err.strerror)
            raise err
        finally:
            if handle:
                handle.Close()

        # At this point, the file that did not exist has been created with proper permissions,
        # so os.O_CREAT and os.O_EXCL are not needed anymore. We remove them from the flags to
        # avoid a FileExists exception before calling os.open.
        return os.open(file_path, flags ^ os.O_CREAT ^ os.O_EXCL)

    # Windows: general case, we call os.open, let exceptions be thrown, then chmod if all is fine.
    handle = os.open(file_path, flags)
    chmod(file_path, mode)
    return handle


def makedirs(file_path, mode=0o777):
    # type: (str, int) -> None
    """
    Rewrite of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.
    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on leaf directory when created, Python defaults
                     will be applied if ``None``
    """
    if POSIX_MODE:
        return os.makedirs(file_path, mode)

    orig_mkdir_fn = os.mkdir
    try:
        # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
        # os module for the time of makedirs execution on Windows.
        os.mkdir = mkdir  # type: ignore
        return os.makedirs(file_path, mode)
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
        return os.mkdir(file_path, mode)

    attributes = win32security.SECURITY_ATTRIBUTES()
    security = attributes.SECURITY_DESCRIPTOR
    user = _get_current_user()
    dacl = _generate_dacl(user, mode)
    security.SetSecurityDescriptorOwner(user, False)
    security.SetSecurityDescriptorDacl(1, dacl, 0)

    try:
        win32file.CreateDirectory(file_path, attributes)
    except pywintypes.error as err:
        # Handle native windows error into python error to be consistent with the API
        # of os.mkdir in the situation of a directory already existing.
        if err.winerror == winerror.ERROR_ALREADY_EXISTS:
            raise OSError(errno.EEXIST, err.strerror, file_path, err.winerror)
        raise err

    return None


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


def realpath(file_path):
    # type: (str) -> str
    """
    Find the real path for the given path. This method resolves symlinks, including
    recursive symlinks, and is protected against symlinks that creates an infinite loop.
    """
    original_path = file_path

    if POSIX_MODE:
        path = os.path.realpath(file_path)
        if os.path.islink(path):
            # If path returned by realpath is still a link, it means that it failed to
            # resolve the symlink because of a loop.
            # See realpath code: https://github.com/python/cpython/blob/master/Lib/posixpath.py
            raise RuntimeError('Error, link {0} is a loop!'.format(original_path))
        return path

    inspected_paths = []  # type: List[str]
    while os.path.islink(file_path):
        link_path = file_path
        file_path = os.readlink(file_path)
        if not os.path.isabs(file_path):
            file_path = os.path.join(os.path.dirname(link_path), file_path)
        if file_path in inspected_paths:
            raise RuntimeError('Error, link {0} is a loop!'.format(original_path))
        inspected_paths.append(file_path)

    return os.path.abspath(file_path)


# On Windows is_executable run from an unprivileged shell may claim that a path is
# executable when it is excutable only if run from a privileged shell. This result
# is due to the fact that GetEffectiveRightsFromAcl calculate effective rights
# without taking into consideration if the target user has currently required the
# elevated privileges or not. However this is not a problem since certbot always
# requires to be run under a privileged shell, so the user will always benefit
# from the highest (privileged one) set of permissions on a given file.
def is_executable(path):
    # type: (str) -> bool
    """
    Is path an executable file?
    :param str path: path to test
    :return: True if path is an executable file
    :rtype: bool
    """
    if POSIX_MODE:
        return os.path.isfile(path) and os.access(path, os.X_OK)

    return _win_is_executable(path)


def has_world_permissions(path):
    # type: (str) -> bool
    """
    Check if everybody/world has any right (read/write/execute) on a file given its path
    :param str path: path to test
    :return: True if everybody/world has any right to the file
    :rtype: bool
    """
    if POSIX_MODE:
        return bool(stat.S_IMODE(os.stat(path).st_mode) & stat.S_IRWXO)

    security = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    dacl = security.GetSecurityDescriptorDacl()

    return bool(dacl.GetEffectiveRightsFromAcl({
        'TrusteeForm': win32security.TRUSTEE_IS_SID,
        'TrusteeType': win32security.TRUSTEE_IS_USER,
        'Identifier': win32security.ConvertStringSidToSid('S-1-1-0'),
    }))


def compute_private_key_mode(old_key, base_mode):
    # type: (str, int) -> int
    """
    Calculate the POSIX mode to apply to a private key given the previous private key
    :param str old_key: path to the previous private key
    :param int base_mode: the minimum modes to apply to a private key
    :return: the POSIX mode to apply
    :rtype: int
    """
    if POSIX_MODE:
        # On Linux, we keep read/write/execute permissions
        # for group and read permissions for everybody.
        old_mode = (stat.S_IMODE(os.stat(old_key).st_mode) &
                    (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH))
        return base_mode | old_mode

    # On Windows, the mode returned by os.stat is not reliable,
    # so we do not keep any permission from the previous private key.
    return base_mode


def has_same_ownership(path1, path2):
    # type: (str, str) -> bool
    """
    Return True if the ownership of two files given their respective path is the same.
    On Windows, ownership is checked against owner only, since files do not have a group owner.
    :param str path1: path to the first file
    :param str path2: path to the second file
    :return: True if both files have the same ownership, False otherwise
    :rtype: bool

    """
    if POSIX_MODE:
        stats1 = os.stat(path1)
        stats2 = os.stat(path2)
        return (stats1.st_uid, stats1.st_gid) == (stats2.st_uid, stats2.st_gid)

    security1 = win32security.GetFileSecurity(path1, win32security.OWNER_SECURITY_INFORMATION)
    user1 = security1.GetSecurityDescriptorOwner()

    security2 = win32security.GetFileSecurity(path2, win32security.OWNER_SECURITY_INFORMATION)
    user2 = security2.GetSecurityDescriptorOwner()

    return user1 == user2


def has_min_permissions(path, min_mode):
    # type: (str, int) -> bool
    """
    Check if a file given its path has at least the permissions defined by the given minimal mode.
    On Windows, group permissions are ignored since files do not have a group owner.
    :param str path: path to the file to check
    :param int min_mode: the minimal permissions expected
    :return: True if the file matches the minimal permissions expectations, False otherwise
    :rtype: bool
    """
    if POSIX_MODE:
        st_mode = os.stat(path).st_mode
        return st_mode == st_mode | min_mode

    # Resolve symlinks, to get a consistent result with os.stat on Linux,
    # that follows symlinks by default.
    path = realpath(path)

    # Get owner sid of the file
    security = win32security.GetFileSecurity(
        path, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    user = security.GetSecurityDescriptorOwner()
    dacl = security.GetSecurityDescriptorDacl()
    min_dacl = _generate_dacl(user, min_mode)

    for index in range(min_dacl.GetAceCount()):
        min_ace = min_dacl.GetAce(index)

        # On a given ACE, index 0 is the ACE type, 1 is the permission mask, and 2 is the SID.
        # See: http://timgolden.me.uk/pywin32-docs/PyACL__GetAce_meth.html
        mask = min_ace[1]
        user = min_ace[2]

        effective_mask = dacl.GetEffectiveRightsFromAcl({
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': user,
        })

        if effective_mask != effective_mask | mask:
            return False

    return True


def _win_is_executable(path):
    if not os.path.isfile(path):
        return False

    security = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    dacl = security.GetSecurityDescriptorDacl()

    mode = dacl.GetEffectiveRightsFromAcl({
        'TrusteeForm': win32security.TRUSTEE_IS_SID,
        'TrusteeType': win32security.TRUSTEE_IS_USER,
        'Identifier': _get_current_user(),
    })

    return mode & ntsecuritycon.FILE_GENERIC_EXECUTE == ntsecuritycon.FILE_GENERIC_EXECUTE


def _apply_win_mode(file_path, mode):
    """
    This function converts the given POSIX mode into a Windows ACL list, and applies it to the
    file given its path. If the given path is a symbolic link, it will resolved to apply the
    mode on the targeted file.
    """
    file_path = realpath(file_path)
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


def _copy_win_ownership(src, dst):
    security_src = win32security.GetFileSecurity(src, win32security.OWNER_SECURITY_INFORMATION)
    user_src = security_src.GetSecurityDescriptorOwner()

    security_dst = win32security.GetFileSecurity(dst, win32security.OWNER_SECURITY_INFORMATION)
    # Second parameter indicates, if `False`, that the owner of the file is not provided by some
    # default mechanism, but is explicitly set instead. This is obviously what we are doing here.
    security_dst.SetSecurityDescriptorOwner(user_src, False)

    win32security.SetFileSecurity(dst, win32security.OWNER_SECURITY_INFORMATION, security_dst)


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
                       ^ ntsecuritycon.FILE_GENERIC_EXECUTE)
    if rights_desc['execute']:
        flag = flag | ntsecuritycon.FILE_GENERIC_EXECUTE

    return flag


def _check_win_mode(file_path, mode):
    # Resolve symbolic links
    file_path = realpath(file_path)
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
    """
    This method compare the two given DACLs to check if they are identical.
    Identical means here that they contains the same set of ACEs in the same order.
    """
    return ([dacl1.GetAce(index) for index in range(dacl1.GetAceCount())] ==
            [dacl2.GetAce(index) for index in range(dacl2.GetAceCount())])


def _get_current_user():
    """
    Return the pySID corresponding to the current user.
    """
    # We craft the account_name ourselves instead of calling for instance win32api.GetUserNameEx,
    # because this function returns nonsense values when Certbot is run under NT AUTHORITY\SYSTEM.
    # To run Certbot under NT AUTHORITY\SYSTEM, you can open a shell using the instructions here:
    # https://blogs.technet.microsoft.com/ben_parker/2010/10/27/how-do-i-run-powershell-execommand-prompt-as-the-localsystem-account-on-windows-7/
    account_name = r"{0}\{1}".format(win32api.GetDomainName(), win32api.GetUserName())
    # LookupAccountName() expects the system name as first parameter. By passing None to it,
    # we instruct Windows to first search the matching account in the machine local accounts,
    # then into the primary domain accounts, if the machine has joined a domain, then finally
    # into the trusted domains accounts. This is the preferred lookup mechanism to use in Windows
    # if there is no reason to use a specific lookup mechanism.
    # See https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-lookupaccountnamea
    return win32security.LookupAccountName(None, account_name)[0]
