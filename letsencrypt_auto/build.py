#!/usr/bin/env python
"""Stitch together the letsencrypt-auto script.

Implement a simple templating language in which {{ some/file }} turns into the
contents of the file at ./pieces/some/file except for certain tokens which have
other, special definitions.

"""
from os.path import dirname, join
import re
from sys import argv


def le_version(build_script_dir):
    """Return the version number stamped in letsencrypt/__init__.py."""
    return re.search('''^__version__ = ['"](.+)['"].*''',
                     file_contents(join(dirname(build_script_dir),
                                        'letsencrypt',
                                        '__init__.py')),
                     re.M).group(1)


def file_contents(path):
    with open(path) as file:
        return file.read()


def main():
    dir = dirname(argv[0])

    special_replacements = {
        'LE_AUTO_VERSION': le_version(dir)
    }

    def replacer(match):
        token = match.group(1)
        if token in special_replacements:
            return special_replacements[token]
        else:
            return file_contents(join(dir, 'pieces', token))

    result = re.sub(r'{{\s*([A-Za-z0-9_./-]+)\s*}}',
                    replacer,
                    file_contents(join(dir, 'letsencrypt-auto.template')))
    with open(join(dir, 'letsencrypt-auto'), 'w') as out:
        out.write(result)


if __name__ == '__main__':
    main()
