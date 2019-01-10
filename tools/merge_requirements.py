#!/usr/bin/env python
"""
Merge multiple Python requirements files into one file

- Version taken for each requirement will be the lowest on found from all files.
- Comments and local editable packages (eg. -e acme[dev]) are ignored.
- Standard version comparators are supported (==, <=, ...), but a given package cannot be
  declared multiple times with different version comparator, or an exception will be raised.
- Environment markers and version ranges are not supported.
"""
import re
import os
import sys
from distutils.version import StrictVersion

REQUIREMENT_REGEX = re.compile('^(.*?)(==|!=|<|>|<=|>=)(.*)$')


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
                comparator = match.group(2)
                version = StrictVersion(match.group(3))

                if not data.get(package):
                    data[package] = []

                data[package].append((comparator, version))


def merge_one_requirement(package, claims):
    """
    Merge multiple claims for a package into one, taking the claims of the lowest version.
    :param str package: the package concerned by the claims
    :param tuple claims: the claims for the package
    :return: the claim corresponding to the lowest version
    :rtype: tuple
    """
    comparators = {claim[0] for claim in claims}

    if len(comparators) > 1:
        raise ValueError("Incompatible requirements for package {0} "
                         "because of multiple versions comparators:{1}{2}"
                         .format(package, os.linesep, claims))

    claims.sort(key=lambda claim: claim[1])
    return claims[0]


def merge_requirements(data):
    """
    Merge requirements in the dict data, by returning one requirement for each package.
    Lowest version for each package is retained.
    :param dict data: dict of all requirements
    :return: the merged requirements
    :rtype: list
    """
    merged_data = []
    for key, value in data.items():
        merged_requirement = merge_one_requirement(key, value)
        merged_data.append((key, merged_requirement[0], str(merged_requirement[1])))
    return merged_data


def main(*files):
    """
    Main function of this module.
    Accept a list of requirements files, return a list of well formatted merged requirements.
    :param list files: list of the requirement files to merge
    :return: a well formatted merged requirements
    :rtype: str
    """
    data = {}
    for file in files:
        read_requirement_file(file, data)

    requirements = merge_requirements(data)
    requirements.sort(key=lambda requirement: requirement[0].lower())
    return os.linesep.join([''.join(requirement) for requirement in requirements])


if __name__ == '__main__':
    merged_requirements = main(*sys.argv[1:])
    print(merged_requirements)
