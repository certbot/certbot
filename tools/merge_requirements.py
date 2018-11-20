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
            if line and not line.startswith('#'):
                project, version = line.split('==')
                if not version:
                    raise ValueError("Unexpected syntax '{0}'".format(line))
                d[project] = version
    return d


def output_requirements(requirements):
    """Prepare print requirements to stdout.

    :param dict requirements: mapping from a project to its pinned version

    """
    return '\n'.join('{0}=={1}'.format(k, v)
          for k, v in sorted(requirements.items()))


def main(*files):
    """Merges multiple requirements files together and prints the result.

    Requirement files specified later in the list take precedence over earlier
    files.

    :param tuple files: paths to requirements files

    """
    d = {}
    for f in files:
        d.update(read_file(f))
    return output_requirements(d)


if __name__ == '__main__':
    merged_requirements = main(*sys.argv[1:])
    print(merged_requirements)
