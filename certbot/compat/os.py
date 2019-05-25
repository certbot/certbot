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


# Very similarly to os.open, os.mkdir has the same effect on Windows, to create an unsecured
# folder. Same mitigation is provided using security.take_ownership and security.chmod.
# On top of that, we need to handle the fact that os.mkdir is called recursively by os.makedirs.
# This is done by protecting the original os.mkdir to have the real logic, call it during the
# recurrence and apply immediately the security model on every processed folder.
def mkdir(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.mkdir() is forbidden"""
    raise RuntimeError('Usage of os.mkdir() is forbidden. '
                       'Use certbot.compat.filesystem.mkdir() instead.')


# As said above, os.makedirs would call the original os.mkdir function recursively, creating the
# same flaws for every actual folder created. This method is modified to ensure that our
# modified os.mkdir is called, by monkey patching temporarily the mkdir method on the
# original os module, executing the modified logic to protect corecrtly newly created folders,
# then restoring original mkdir method in the os module.
def makedirs(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.makedirs() is forbidden"""
    raise RuntimeError('Usage of os.makedirs() is forbidden. '
                       'Use certbot.compat.filesystem.makedirs() instead.')
