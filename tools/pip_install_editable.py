#!/usr/bin/env python
# pip installs packages in editable mode using certbot-auto's requirements file
# as constraints
#
# cryptography is currently using this script in their CI at
# https://github.com/pyca/cryptography/blob/a02fdd60d98273ca34427235c4ca96687a12b239/.travis/downstream.d/certbot.sh#L8-L9.
# We should try to remember to keep their repo updated if we make any changes
# to this script which may break things for them.

from __future__ import absolute_import

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
