#!/usr/bin/env python
"""Get the current Certbot version number.

Provides simple utilities for determining the Certbot version number and
building letsencrypt-auto.

"""
from __future__ import print_function
from os.path import abspath, dirname, join
import re


def certbot_version(build_script_dir):
    """Return the version number stamped in certbot/__init__.py."""
    return re.search('''^__version__ = ['"](.+)['"].*''',
                     file_contents(join(dirname(build_script_dir),
                                        'certbot',
                                        'certbot',
                                        '__init__.py')),
                     re.M).group(1)


def file_contents(path):
    with open(path) as file:
        return file.read()


if __name__ == '__main__':
    print(certbot_version(dirname(abspath(__file__))))
