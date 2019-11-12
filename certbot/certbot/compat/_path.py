"""This compat module wraps os.path to forbid some functions."""
# pylint: disable=function-redefined
from __future__ import absolute_import

# First round of wrapping: we import statically all public attributes exposed by the os.path
# module. This allows in particular to have pylint, mypy, IDEs be aware that most of os.path
# members are available in certbot.compat.path.
from os.path import *  # type: ignore  # pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin,os-module-forbidden

# Second round of wrapping: we import dynamically all attributes from the os.path module that have
# not yet been imported by the first round (static star import).
import os.path as std_os_path  # pylint: disable=os-module-forbidden
import sys as std_sys

ourselves = std_sys.modules[__name__]
for attribute in dir(std_os_path):
    # Check if the attribute does not already exist in our module. It could be internal attributes
    # of the module (__name__, __doc__), or attributes from standard os.path already imported with
    # `from os.path import *`.
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os_path, attribute))

# Clean all remaining importables that are not from the core os.path module.
del ourselves, std_os_path, std_sys


# Function os.path.realpath is broken on some versions of Python for Windows.
def realpath(*unused_args, **unused_kwargs):
    """Method os.path.realpath() is forbidden"""
    raise RuntimeError('Usage of os.path.realpath() is forbidden. '
                       'Use certbot.compat.filesystem.realpath() instead.')
