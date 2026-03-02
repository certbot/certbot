#!/usr/bin/env python
"""Get the current Certbot version number.

Provides a simple utility for determining the Certbot version number

"""
from __future__ import print_function

from os.path import abspath
from os.path import dirname
from os.path import join
import re


def certbot_version(letstest_scripts_dir):
    """Return the version number stamped in certbot/__init__.py."""
    return re.search('''^__version__ = ['"](.+)['"].*''',
                     file_contents(join(dirname(dirname(letstest_scripts_dir)),
                                        'certbot',
                                        'src',
                                        'certbot',
                                        '__init__.py')),
                     re.M).group(1)


def file_contents(path):
    with open(path) as file:
        return file.read()


if __name__ == '__main__':
    print(certbot_version(dirname(abspath(__file__))))
