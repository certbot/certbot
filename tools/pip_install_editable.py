#!/usr/bin/env python
# pip installs packages in editable mode using certbot-auto's requirements file
# as constraints

from __future__ import absolute_import

import sys

import pip_install

def main(tools_path, args):
    new_args = []
    for arg in args:
        new_args.append('-e')
        new_args.append(arg)
    pip_install.main(tools_path, new_args)

if __name__ == '__main__':
    tools_dir = pip_install.find_tools_path(sys.argv[0])
    main(tools_dir, sys.argv[1:])
