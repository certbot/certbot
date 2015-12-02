#!/usr/bin/env python
"""Stitch together the letsencrypt-auto script.

Implement a simple templating language in which {{ some/file }} turns into the
contents of the file at ./pieces/some/file.

"""
from os.path import dirname, join
import re
from sys import argv


def main():
    dir = dirname(argv[0])

    def replacer(match):
        rel_path = match.group(1)
        with open(join(dir, 'pieces', rel_path)) as replacement:
            return replacement.read()

    with open(join(dir, 'letsencrypt-auto.template')) as template:
        result = re.sub(r'{{\s*([A-Za-z0-9_./-]+)\s*}}',
                        replacer,
                        template.read())
    with open(join(dir, 'letsencrypt-auto'), 'w') as out:
        out.write(result)


if __name__ == '__main__':
    main()
