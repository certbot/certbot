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
from distutils.version import StrictVersion

REQUIREMENT_REGEX = re.compile('^(.*?)==(.*)$')


def read_requirement_file(path, data):
    """
    Read a requirement file, and feeds its content into the given data dict.
    :param str path: the requirement file path to read
    :param dict data: the data dict to feed with
    """
    with open(path) as file:
        for line in file:
            if line and not line.startswith('#') and not line.startswith('-e'):
                match = REQUIREMENT_REGEX.match(line)

                if not match:
                    raise ValueError("Unexpected syntax '{0}'".format(line))

                package = match.group(1)
                version = StrictVersion(match.group(2))

                if not data.get(package):
                    data[package] = []

                data[package].append(version)


def merge_requirements(data):
    """
    Merge requirements in the dict data, by returning one requirement for each package.
    Lowest version for each package is retained.
    :param dict data: dict of all requirements
    :return: the merged requirements
    :rtype: list
    """
    merged_data = []
    for package, versions in data.items():
        versions.sort()
        merged_data.append((package, str(versions[0])))
    return merged_data


def main(*files):
    """
    Main function of this module.
    Accept a list of requirements files, return a list of well formatted merged requirements.
    :param str files: list of the requirement files to merge
    :return: a well formatted merged requirements
    :rtype: str
    """
    data = {}
    for file in files:
        read_requirement_file(file, data)

    requirements = merge_requirements(data)
    requirements.sort(key=lambda requirement: requirement[0].lower())
    return os.linesep.join(['=='.join(requirement) for requirement in requirements])


if __name__ == '__main__':
    merged_requirements = main(*sys.argv[1:])
    print(merged_requirements)
