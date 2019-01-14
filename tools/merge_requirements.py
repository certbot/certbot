#!/usr/bin/env python
"""
Merge multiple Python requirements files into one file

- Version taken for each requirement will be the lowest one found from all files.
- Comments and local editable packages (eg. -e acme[dev]) are ignored.
- Only equality version comparator is supported (==).
- Environment markers and version ranges are not supported.
"""
import re
import os
import sys
from distutils.version import LooseVersion

REQUIREMENT_REGEX = re.compile(r'^(\S+)==(\S+)$')


def read_requirement_file(path, data):
    """
    Read a requirement file, and feeds its content into the given data dict.
    :param str path: the requirement file path to read
    :param dict data: the data dict to feed with
    """
    with open(path) as fh:
        for line in fh:
            if line.strip() and not line.startswith('#') and not line.startswith('-e'):
                match = REQUIREMENT_REGEX.match(line)

                if not match:
                    raise ValueError("Unexpected syntax '{0}'".format(line))

                package = match.group(1)
                version = LooseVersion(match.group(2))

                if not data.get(package):
                    data[package] = []

                data[package].append(version)


def merge_requirements(data):
    """
    Merge requirements in the dict data, by returning one requirement for each package.
    First version found for each package is retained.
    :param dict data: dict of all requirements
    :return: the merged requirements
    :rtype: list
    """
    merged_data = []
    for package, versions in data.items():
        merged_data.append((package, str(versions[-1])))
    return merged_data


def main(*paths):
    """
    Main function of this module.
    Accept a list of requirements files, return a list of well formatted merged requirements.
    Order of paths follows an increasing priority: version retained for a given package will be
    the last one found along all requirements files.
    :param str paths: list of the requirement files to merge
    :return: a well formatted merged requirements
    :rtype: str
    """
    data = {}
    for path in paths:
        read_requirement_file(path, data)

    requirements = merge_requirements(data)
    requirements.sort(key=lambda requirement: requirement[0].lower())
    return os.linesep.join(['=='.join(requirement) for requirement in requirements])


if __name__ == '__main__':
    merged_requirements = main(*sys.argv[1:])
    print(merged_requirements)
