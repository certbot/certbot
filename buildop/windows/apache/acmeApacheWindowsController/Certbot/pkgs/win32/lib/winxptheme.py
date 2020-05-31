"""A useful wrapper around the "_winxptheme" module.
Unlike _winxptheme, this module will load on any version of Windows.

If _winxptheme is not available, then this module will have only 2 functions -
IsAppThemed() and IsThemeActive, which will both always return False.

If _winxptheme is available, this module will have all methods in that module,
including real implementations of IsAppThemed() and IsThemeActive().
"""

import win32api
try:
    win32api.FreeLibrary(win32api.LoadLibrary("Uxtheme.dll"))
    # Life is good, everything is available.
    from _winxptheme import *
except win32api.error:
    # Probably not running XP.
    def IsAppThemed():
        return False
    def IsThemeActive():
        return False

del win32api
