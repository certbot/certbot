#!/usr/bin/env python
"""Canonicalizes a path and follows any symlinks.

This is the equivalent of `readlink -f` on many Linux systems. This is
useful as there are often differences in readlink on different
platforms.

"""
from __future__ import print_function
import os
import sys

print(os.path.realpath(sys.argv[1]))
