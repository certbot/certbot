#!/usr/bin/env python
import glob
import os
import re
import sys

CERTBOT_ROOT = os.path.dirname(os.path.dirname(__file__))
WHITELIST_PATTERNS = [
    r'^.*/docs/conf\.py$',
    r'^certbot/compat/os\.py$',
    r'^certbot-compatibility-test/.*$']
IMPORT_OS_PATTERN = r'^\s*(import\s+os|from\s+os)(\s*$|\s.*$)'

def main():
    faulty_files = []
    for python_file in glob.glob(os.path.join(CERTBOT_ROOT, 'certbot*/**/*.py')):
        if not [item for item in WHITELIST_PATTERNS
                if re.match(item, python_file.replace(os.path.sep, '/'))]:
            with open(python_file, 'r') as file:
                content = file.read().splitlines()

            for (index, line) in enumerate(content):
                if re.match(IMPORT_OS_PATTERN, line):
                    faulty_files.append((python_file, index, line))

    if faulty_files:
        sys.stderr.write('Some python files are importing the standard \'os\' module.\n')
        sys.stderr.write('This is forbidden, \'certbot.compat.os\' module must be used instead.\n')
        sys.stderr.write('Faulty files:\n')
        for faulty_file in faulty_files:
            sys.stderr.write('\t-> {0} at line {1}: {2}\n'.format(
                faulty_file[0], faulty_file[1], faulty_file[2]
            ))

        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
