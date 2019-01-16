#!/usr/bin/env python
"""Merges multiple Python requirements files into one file.

Requirements files specified later take precedence over earlier ones. Only
simple SomeProject==1.2.3 format is currently supported.

"""
from __future__ import print_function

import sys


def read_file(file_path):
    """Reads in a Python requirements file.
    Ignore empty lines, comments and editable requirements

    :param str file_path: path to requirements file

    :returns: mapping from a project to its pinned version
    :rtype: dict

    """
    data = {}
    with open(file_path) as file_h:
        for line in file_h:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-e'):
                project, version = line.split('==')
                if not version:
                    raise ValueError("Unexpected syntax '{0}'".format(line))
                data[project] = version
    return data


def output_requirements(requirements):
    """Prepare print requirements to stdout.

    :param dict requirements: mapping from a project to its pinned version

    """
    return '\n'.join('{0}=={1}'.format(key, value)
                     for key, value in sorted(requirements.items()))


def main(*paths):
    """Merges multiple requirements files together and prints the result.

    Requirement files specified later in the list take precedence over earlier
    files.

    :param tuple paths: paths to requirements files

    """
    data = {}
    for path in paths:
        data.update(read_file(path))
    return output_requirements(data)


if __name__ == '__main__':
    print(main(*sys.argv[1:]))  # pylint: disable=star-args
