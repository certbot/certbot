"""
This compat modules is a wrapper of the core os module that forbids usage of specific operations
(eg. chown, chmod, geteuid) that would be harmful to the Windows file security model of Certbot.
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
import sys as std_sys
ourselves = std_sys.modules[__name__]
for attribute in dir(std_os):
    # Check if the attribute does not already exist in our module. It could be internal attributes
    # of the module (__name__, __doc__), or attributes from standard os already imported with
    # `from os import *`.
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os, attribute))

# Similar to os.path, allow certbot.compat.os.path to behave as a module
std_sys.modules[__name__ + '.path'] = path

# Clean all remaining importables that are not from the core os module.
del ourselves, std_os, std_sys


# The concept of uid is specific to POSIX system. On Windows, there is nothing like this.
# So we cannot use python methods that relies on uid, on geteuid() is useless.
def geteuid(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.geteuid() is forbidden"""
    raise RuntimeError('Usage of os.geteuid() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.get_current_user() instead.')


# Because uid is not a concept on Windows, chown is useless. In fact, it is not even available
# on Python for Windows. So to be consistent with both platforms for Certbot, this method is
# always forbidden.
def chown(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.chown() is forbidden"""
    raise RuntimeError('Usage of os.chown() is forbidden.'  # pragma: no cover
                       'Use certbot.compat.filesystem.take_ownership() or '
                       'certbot.compat.filesystem.copy_ownership_and_apply_mode() instead.')


# Because of the blocking strategy on file handlers on Windows, rename to not behave as expected
# with POSIX systems: an exception will be raised if dst already exists. Hopefully there is
# os.replace on Windows for Python 3, that will do the same than on POSIX. Hopefully also, only
# Python 3 is supported for Certbot. So we can rely on os.rename on Linux, and os.replace
# on Windows.
def rename(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.rename() is forbidden"""
    raise RuntimeError('Usage of os.rename() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.rename() instead.')


# Chmod is the root of all evil for our security model on Windows. With the default implementation
# of os.chmod on Windows, almost all bits on mode will be ignored, and only a general RO or RW will
# be applied. The DACL, the inner mechanism to control file access on Windows, will stay on its
# default definition, giving effectively at least read permissions to any one, as the default
# permissions on root path will be inherit by the file (as NTFS state), and root path can be read
# by anyone. So the given mode will be translated into a secured and not inherited DACL that will
# be applied to this file using filesystem.chmod, that will call internally the win32security
# module to construct and apply the DACL. Complete security model to translate a POSIX mode for
# something usable on Windows for Certbot can be found here:
# https://github.com/certbot/certbot/issues/6356
# Basically, it states that appropriate permissions will be set for the owner, nothing for the
# group, appropriate permissions for the "Everyone" group, and all permissions to the
# "Administrators" group, as they can do everything anyway.
def chmod(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.chmod() is forbidden"""
    raise RuntimeError('Usage of os.chmod() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.chmod() instead.')


# The os.open function on Windows will have the same effect than a bare os.chown towards the given
# mode, and will create a file with the same flaws that what have been described for os.chown.
# So upon file creation, filesystem.take_ownership will be called to ensure current user is the owner
# of the file, and filesystem.chmod will do the same thing than for the modified os.chown.
# Internally, take_ownership will update the existing metdata of the file, to set the current
# username (resolved thanks to win32api module) as the owner of the file.
def open(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.open() is forbidden"""
    raise RuntimeError('Usage of os.open() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.open() instead.')


# Very similarly to os.open, os.mkdir has the same effect on Windows, to create an unsecured
# folder. Same mitigation is provided using filesystem.take_ownership and filesystem.chmod.
# On top of that, we need to handle the fact that os.mkdir is called recursively by os.makedirs.
# This is done by protecting the original os.mkdir to have the real logic, call it during the
# recurrence and apply immediately the security model on every processed folder.
def mkdir(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.mkdir() is forbidden"""
    raise RuntimeError('Usage of os.mkdir() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.mkdir() instead.')


# As said above, os.makedirs would call the original os.mkdir function recursively, creating the
# same flaws for every actual folder created. This method is modified to ensure that our
# modified os.mkdir is called, by monkey patching temporarily the mkdir method on the
# original os module, executing the modified logic to protect corecrtly newly created folders,
# then restoring original mkdir method in the os module.
def makedirs(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.makedirs() is forbidden"""
    raise RuntimeError('Usage of os.makedirs() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.makedirs() instead.')
