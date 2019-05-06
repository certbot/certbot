"""
This compat modules is a wrapper of the core os module that forbids usage of specific operations
(e.g. chown, chmod, getuid) that would be harmful to the Windows file security model of Certbot.
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


# Chmod is the root of all evil for our security model on Windows. With the default implementation
# of os.chmod on Windows, almost all bits on mode will be ignored, and only a general RO or RW will
# be applied. The DACL, the inner mechanism to control file access on Windows, will stay on its
# default definition, giving effectively at least read permissions to any one, as the default
# permissions on root path will be inherit by the file (as NTFS state), and root path can be read
# by anyone. So the given mode will be translated into a secured and not inherited DACL that will
# be applied to this file using security.chmod, that will call internally the win32security
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
