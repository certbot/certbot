#!/usr/bin/env python
"""Canonicalizes a path and follows any symlinks.

This is the equivalent of `readlink -f` on many Linux systems. This is
useful as there are often differences in readlink on different
platforms.

"""
import os
import sys


def main(link):
    return os.path.realpath(link)

if __name__ == '__main__':
    print(main(sys.argv[1]))
