#!/usr/bin/env python
"""Merges multiple Python requirements files into one file.

Requirements files specified later take precedence over earlier ones. Only
simple SomeProject==1.2.3 format is currently supported.

"""

from __future__ import print_function

import sys


def read_file(file_path):
    """Reads in a Python requirements file.

    :param str file_path: path to requirements file

    :returns: mapping from a project to its pinned version
    :rtype: dict

    """
    d = {}
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith('#'):
                project, _, version = line.partition('==')
                if not version:
                    raise ValueError("Unexpected syntax '{0}'".format(line))
                d[project] = version
    return d


def print_requirements(requirements):
    """Prints requirements to stdout.

    :param dict requirements: mapping from a project to its pinned version

    """
    print('\n'.join('{0}=={1}'.format(k, v)
          for k, v in sorted(requirements.items())))


def merge_requirements_files(*files):
    """Merges multiple requirements files together and prints the result.

    Requirement files specified later in the list take precedence over earlier
    files.

    :param tuple files: paths to requirements files

    """
    d = {}
    for f in files:
        d.update(read_file(f))
    print_requirements(d)


if __name__ == '__main__':
    merge_requirements_files(*sys.argv[1:])
