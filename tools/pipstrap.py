#!/usr/bin/env python
"""Uses pip to upgrade Python packaging tools to pinned versions."""
from __future__ import absolute_import
import os

import pip_install


_REQUIREMENTS_PATH = os.path.join(os.path.dirname(__file__), "pipstrap_constraints.txt")


def main():
    pip_install_args = '--requirement "{0}"'.format(_REQUIREMENTS_PATH)
    pip_install.pip_install_with_print(pip_install_args)


if __name__ == '__main__':
    main()
