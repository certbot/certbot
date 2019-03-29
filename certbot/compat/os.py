"""
This compat modules extends native capabilities of core os module to handle correctly platform
specific operations (eg. chown, chmod, geuid).
This module is intended to replace standard os module throughout certbot projects (except acme).
"""
from __future__ import absolute_import

# Expose everything from standard os package to make current package a complete replacement of os.
from os import *  # type: ignore  # pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin

# Monkey patch ourselves to get os attributes that are not in __all__ (so not from os import *).
import os as std_os
import sys as std_sys
ourselves = std_sys.modules[__name__]
for attribute in dir(std_os):
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os, attribute))

# Clean all remaining importables that are not from the core os module.
del ourselves, std_os, std_sys
