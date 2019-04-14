"""
This compat modules is a wrapper of the core os module that forbids usage of specific operations
(eg. chown, chmod, getuid) that would be harmful to the Windows file security model of Certbot.
This module is intended to replace standard os module throughout certbot projects (except acme).
"""
from __future__ import absolute_import

# First round of wrapping: we import statically all public attributes exposed by the os module
# This allows in particular to have pylint, mypy, IDEs be aware that most of os members are
# available in certbot.compat.os.
from os import *  # type: ignore  # pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin,os-module-forbidden

# Second round of wrapping: we import dynamically all attributes from the os module that have not
# yet been imported by the first round (static import). This covers in particular the case of
# specific python 3.x versions where not all public attributes are in the special __all__ of os,
# and so not in `from os import *`.
import os as std_os  # pylint: disable=os-module-forbidden
import sys
ourselves = sys.modules[__name__]
for attribute in dir(std_os):
    # Check if the attribute does not already exist in our module. It could be internal attributes
    # of the module (__name__, __doc__), or attributes from standard os already imported with
    # `from os import *`.
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os, attribute))

# Similar to os.path, allow certbot.compat.os.path to behave as a module
sys.modules[__name__ + '.path'] = path

# Clean all remaining importables that are not from the core os module.
del ourselves

from acme.magic_typing import Callable, Union  # pylint: disable=unused-import, no-name-in-module

from certbot.compat import security


# The concept of uid is specific to POSIX system. On Windows, there is nothing like this.
# So we cannot use python methods that relies on uid, on geteuid() is useless.
def geteuid():  # pylint: disable=function-redefined
    # type: () -> int
    """
    Get current user uid

    :returns: The current user uid.
    :rtype: int

    """
    raise RuntimeError('Usage of os.geteuid() is forbidden. '
                       'Use certbot.compat.security.get_current_user() instead.')


# Because uid is not a concept on Windows, chown is useless. In fact, it is not even available
# on Python for Windows. So to be consistent with both platforms for Certbot, this method is
# always forbidden.
def chown(file_path, uid, gid):  # pylint: disable=function-redefined, unused-argument
    """
    Change the owner and group id of path to the numeric uid and gid.
    To leave one of the ids unchanged, set it to -1.

    :param str file_name: The current file path.
    :param int uid: Owner user id.
    :param int gid: Group user id.
    """
    raise RuntimeError('Usage of os.chown() is forbidden.'
                       'Use certbot.compat.security.take_ownership() or '
                       'certbot.compat.security.copy_ownership_and_apply_mode() instead.')


# Because of the blocking strategy on file handlers on Windows, rename to not behave as expected
# with POSIX systems: an exception will be raised if dst already exists. Hopefully there is
# os.replace on Windows for Python 3, that will do the same than on POSIX. Hopefully also, only
# Python 3 is supported for Certbot. So we can rely on os.rename on Linux, and os.replace
# on Windows.
def rename(src, dst):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], Union[str, unicode]) -> None
    """
    Rename a file to a destination path and handles situations where the destination exists.

    :param str src: The current file path.
    :param str dst: The new file path.
    """
    try:
        std_os.rename(src, dst)
    except OSError as err:
        # Windows specific, renaming a file on an existing path is not possible.
        # On Python 3, the best fallback with atomic capabilities we have is os.replace.
        if err.errno != errno.EEXIST:
            # Every other error is a legitimate exception.
            raise
        if not hasattr(std_os, 'replace'):  # pragma: no cover
            # We should never go on this line. Either we are on Linux and os.rename has succeeded,
            # either we are on Windows, and only Python >= 3.4 is supported where os.replace is
            # available.
            raise RuntimeError('Error: tried to run os.replace on Python < 3.3. '
                               'Certbot supports only Python 3.4 >= on Windows.')
        getattr(std_os, 'replace')(src, dst)


# Chmod is the root of all evil for our security model on Windows. With the default implementation
# of os.chmod on Windows, almost all bits on mode will be ignored, and only a general RO or RW will
# be applied. The DACL, the inner mechanism to control file access on Windows, will stay on its
# default definition, giving effectively at least read permissions to any one, as the default
# permissions on root path will be inherit by the file (as NTFS state), and root path can be read
# by anyone. So the given mode will be translated into a secured and not inherited DACL that will
# be applied to this file using security.apply_mode, that will call internally the win32security
# module to construct and apply the DACL. Complete security model to translate a POSIX mode for
# something usable on Windows for Certbot can be found here:
# https://github.com/certbot/certbot/issues/6356
# Basically, it states that appropriate permissions will be set for the owner, nothing for the
# group, appropriate permissions for the "Everyone" group, and all permissions to the
# "Administrators" group, as they can do everything anyway.
def chmod(file_path, mode):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int) -> None
    """
    Wrapper of original os.chmod function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to modify
    :param int mode: POSIX mode to apply on file
    """
    security.apply_mode(file_path, mode)


# The os.open function on Windows will have the same effect than a bare os.chown towards the given
# mode, and will create a file with the same flaws that what have been described for os.chown.
# So upon file creation, security.take_ownership will be called to ensure current user is the owner
# of the file, and security.apply_mode will do the same thing than for the modified os.chown.
# Internally, take_ownership will update the existing metdata of the file, to set the current
# username (resolved thanks to win32api module) as the owner of the file.
def open(file_path, flags, mode=0o777):  # pylint: disable=function-redefined,redefined-builtin
    # type: (Union[str, unicode], int, int) -> int
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
    file_descriptor = std_os.open(file_path, flags, mode)
    security.apply_mode(file_path, mode)

    return file_descriptor


# Very similarly to os.open, os.mkdir has the same effect on Windows, to create an unsecured
# folder. Same mitigation is provided using security.take_ownership and security.apply_mode.
# On top of that, we need to handle the fact that os.mkdir is called recursively by os.makedirs.
# This is done by protecting the original os.mkdir to have the real logic, call it during the
# recurrence and apply immediately the security model on every processed folder.
def mkdir(file_path, mode=0o777, mkdir_fn=None):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int, Callable[[Union[str, unicode], int], None]) -> None
    """
    Wrapper of original os.mkdir function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    :param callable mkdir_fn: The underlying mkdir function to use
    """
    mkdir_fn = mkdir_fn or std_os.mkdir

    mkdir_fn(file_path, mode)
    security.apply_mode(file_path, mode)


# As said above, os.makedirs would call the original os.mkdir function recursively, creating the
# same flaws for every actual folder created. This method is modified to ensure that our
# modified os.mkdir is called, by monkey patching temporarily the mkdir method on the
# original os module, executing the modified logic to protect corecrtly newly created folders,
# then restoring original mkdir method in the os module.
def makedirs(file_path, mode=0o777):  # pylint: disable=function-redefined
    # type: (Union[str, unicode], int) -> None
    """
    Wrapper of original os.makedirs function, that will ensure on Windows that given mode
    is correctly applied.

    :param str file_path: The file path to open
    :param int mode: POSIX mode to apply on file when opened,
        Python defaults will be applied if ``None``
    """
    # As we know that os.mkdir is called internally by os.makedirs, we will swap the function in
    # os module for the time of makedirs execution.
    orig_mkdir_fn = std_os.mkdir
    try:
        def wrapper(one_path, one_mode=0o777):  # pylint: disable=missing-docstring
            # Note, we need to provide the origin os.mkdir to our mkdir function,
            # or we will have a nice infinite loop ...
            mkdir(one_path, mode=one_mode, mkdir_fn=orig_mkdir_fn)

        std_os.mkdir = wrapper

        std_os.makedirs(file_path, mode)
    finally:
        std_os.mkdir = orig_mkdir_fn
