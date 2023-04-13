#!/usr/bin/env python
# pip installs packages in editable mode using pip_install.py
import sys

import pip_install


def main(args):
    new_args = []
    for arg in args:
        new_args.append('-e')
        new_args.append(arg)

    pip_install.main(new_args)

if __name__ == '__main__':
    main(sys.argv[1:])
