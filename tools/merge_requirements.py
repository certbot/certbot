#!/usr/bin/env python
"""Merges multiple Python requirements files into one file.

Requirements files specified later take precedence over earlier ones.
Only the simple formats SomeProject==1.2.3 or SomeProject<=1.2.3 are
currently supported.

"""
from __future__ import print_function

import sys


def process_entries(entries):
    """
    Ignore empty lines, comments and editable requirements

    :param list entries: List of entries

    :returns: mapping from a project to its version specifier
    :rtype: dict
    """
    data = {}
    for e in entries:
        e = e.strip()
        if e and not e.startswith('#') and not e.startswith('-e'):
            # Support for <= was added as part of
            # https://github.com/certbot/certbot/pull/8460 because we weren't
            # able to pin a package to an exact version. Normally, this
            # functionality shouldn't be needed so we could remove it in the
            # future. If you do so, make sure to update other places in this
            # file related to this behavior such as this file's docstring.
            for comparison in ('==', '<=',):
                parts = e.split(comparison)
                if len(parts) == 2:
                    project_name = parts[0]
                    version = parts[1]
                    data[project_name] = comparison + version
                    break
            else:
                raise ValueError("Unexpected syntax '{0}'".format(e))
    return data

def read_file(file_path):
    """Reads in a Python requirements file.

    :param str file_path: path to requirements file

    :returns: list of entries in the file
    :rtype: list

    """
    with open(file_path) as file_h:
        return file_h.readlines()

def output_requirements(requirements):
    """Prepare print requirements to stdout.

    :param dict requirements: mapping from a project to its version
        specifier

    """
    return '\n'.join('{0}{1}'.format(key, value)
                     for key, value in sorted(requirements.items()))


def main(*paths):
    """Merges multiple requirements files together and prints the result.

    Requirement files specified later in the list take precedence over earlier
    files. Files are read from file paths passed from the command line arguments.

    If no command line arguments are defined, data is read from stdin instead.

    :param tuple paths: paths to requirements files provided on command line

    """
    data = {}
    if paths:
        for path in paths:
            data.update(process_entries(read_file(path)))
    else:
        # Need to check if interactive to avoid blocking if nothing is piped
        if not sys.stdin.isatty():
            stdin_data = []
            for line in sys.stdin:
                stdin_data.append(line)
            data.update(process_entries(stdin_data))

    return output_requirements(data)


if __name__ == '__main__':
    print(main(*sys.argv[1:]))  # pylint: disable=star-args
