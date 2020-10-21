#!/usr/bin/env python
"""Uses pip to install or upgrade Python packaging tools.

pip_install.py is used to accomplish this so packages like pip can be
pinned the same way as our other packages.

"""
from __future__ import absolute_import

import pip_install


def main():
    pkgs = 'pip setuptools wheel'.split()
    pip_install.main(pkgs)


if __name__ == '__main__':
    main()
