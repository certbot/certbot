#!/usr/bin/env python
"""Uses pip to install or upgrade Python packaging tools.

pip_install.py is used to accomplish this so packages like pip can be
pinned the same way as our other packages.

"""
from __future__ import absolute_import

import pip_install


def main():
    pkgs = 'pip setuptools wheel'.split()
    # We don't disable build isolation because we may have an older version of
    # pip that doesn't support the flag disabling it. We expect these packages
    # to already have usable wheels available anyway so no building should be
    # required.
    pip_install.main(pkgs, disable_build_isolation=False)


if __name__ == '__main__':
    main()
