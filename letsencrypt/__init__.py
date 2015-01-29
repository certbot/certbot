"""Let's Encrypt."""

# do not import stuff here. this file is used by setup.py, thus importing
# stuff here might break setup.py as dependencies are not installed yet.

VERSION_TUPLE = 0, 1, 0, "a0"
"""version tuple: major, minor, micro, {a|b|rc}N - see PEP440"""

VERSION = "%d.%d.%d%s" % VERSION_TUPLE
"""version as str"""
