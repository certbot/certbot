#!/usr/bin/env python
from __future__ import print_function

import os
import re
import sys

CERTBOT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

NEW_SECTION_PATTERN = re.compile(r'^##\s*[\d.]+\s*-\s*[\d-]+$')


def main():
    version = sys.argv[1]

    section_pattern = re.compile(r'^##\s*{0}\s*-\s*[\d-]+$'
                                 .format(version.replace('.', '\\.')))

    with open(os.path.join(CERTBOT_ROOT, 'certbot', 'CHANGELOG.md')) as file_h:
        lines = file_h.read().splitlines()

    changelog = []

    i = 0
    while i < len(lines):
        if section_pattern.match(lines[i]):
            i = i + 1
            while i < len(lines):
                if NEW_SECTION_PATTERN.match(lines[i]):
                    break
                changelog.append(lines[i])
                i = i + 1
        i = i + 1

    changelog = [entry for entry in changelog if entry]

    print('\n'.join(changelog))


if __name__ == '__main__':
    main()
